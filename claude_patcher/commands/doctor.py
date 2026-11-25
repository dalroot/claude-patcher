"""
Doctor and Diagnostic Command Implementation.
Performs an evidence-based audit of MDM policies, supported Chromium flags, ASAR/V8 compile-cache
integrity, WebRTC/Sentry/Crashpad runtime artifacts, proxy DNS bypass, and TZ anti-ban sync.
"""
import json
import os
import sqlite3
import subprocess
import time
from rich import box
from rich.panel import Panel
from rich.table import Table

from ..asar import check_asar_patch_status, parse_asar
from ..constants import (
    ANTI_LEAK_SWITCHES,
    CURRENT_OS,
    MANAGED_POLICIES,
    SURGICAL_PATCHES,
    TRACKER_SINKS,
)
from ..engines import ENGINE
from ..network import check_vpn_network, resolve_proxy_url
from ..paths import PATHS
from ..sanitizer import check_ant_did_status
from ..system import (
    calculate_sha256,
    get_current_launcher_tz,
    parse_sinkholed_domains,
    validate_js_syntax,
)
from ..ui import console

V8_COMPILE_CACHE_MAGIC = b"\xd6\x06\xde\xc0"

DEAD_CHROMIUM_SWITCHES = (
    "--disable-webrtc",
    "--force-webrtc-ip-handling-policy",
    "--enforce-webrtc-ip-permission-check",
    "--dns-prefetch-disable",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--no-pings",
    "--disable-client-side-phishing-detection",
    "--disable-breakpad",
)

TRACKED_COOKIE_NAMES = (
    "anthropic-device-id",
    "_dd_s_v2",
    "ajs_anonymous_id",
    "_fbp",
    "__ssid",
)


def audit_asar_internals(asar_path, ion_asar_path=None):
    """Audits real ASAR guarantees: V8 .x64.jsc status, webRequest hook, 1p MDM, WebRTC & JS syntax."""
    res = {
        "compile_cache_status": "NOT_CHECKED",
        "compile_cache_files": 0,
        "artifact_app_may_request_preserved": None,
        "session_created_hook_active": False,
        "webrtc_policy_enforced": False,
        "mdm_1p_unlocked": False,
        "js_syntax_ok": None,
        "js_syntax_errors": [],
        "ion_dist_status": "NOT_FOUND",
    }

    if asar_path and os.path.isfile(asar_path):
        try:
            arc = parse_asar(asar_path)
            jsc_files = [f for f in arc.list_files() if f.startswith("compile-cache/") and f.endswith(".x64.jsc")]
            res["compile_cache_files"] = len(jsc_files)
            if not jsc_files:
                res["compile_cache_status"] = "ABSENT"
            else:
                has_valid_magic = any(
                    arc.read_file(jf).startswith(V8_COMPILE_CACHE_MAGIC)
                    for jf in jsc_files
                )
                res["compile_cache_status"] = "ACTIVE_STOCK_BYTECODE" if has_valid_magic else "INVALIDATED"

            pre_js = arc.read_file(".vite/build/index.pre.js") if arc.has_file(".vite/build/index.pre.js") else b""
            chunk_js = arc.read_file(".vite/build/index.chunk-DqepnCaA.js") if arc.has_file(".vite/build/index.chunk-DqepnCaA.js") else b""

            if chunk_js:
                res["artifact_app_may_request_preserved"] = b"artifactAppMayRequest" in chunk_js
                res["session_created_hook_active"] = (
                    b"session-created" in chunk_js
                    and b"onBeforeRequest" in chunk_js
                    and (b"datadoghq" in chunk_js or b"api/v2/rum" in chunk_js)
                )
                res["webrtc_policy_enforced"] = (
                    b"setWebRTCIPHandlingPolicy" in chunk_js
                    and b"disable_non_proxied_udp" in chunk_js
                )

            if pre_js or chunk_js:
                telemetry_prefixes = (
                    b'flatKey:"disableEssentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]',
                    b'flatKey:"disableNonessentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]',
                    b'flatKey:"disableNonessentialServices",support:{enabled:{scopes:["3p","1p"]',
                )
                has_1p_pre = all(p in pre_js for p in telemetry_prefixes)
                has_1p_chunk = all(p in chunk_js for p in telemetry_prefixes)
                res["mdm_1p_unlocked"] = bool(
                    (not pre_js or has_1p_pre) and (not chunk_js or has_1p_chunk)
                )

            syntax_targets = [
                (".vite/build/index.pre.js", pre_js),
                (".vite/build/index.chunk-DqepnCaA.js", chunk_js),
            ]
            checked_any = False
            errors = []
            for name, payload in syntax_targets:
                if not payload:
                    continue
                ok, err = validate_js_syntax(payload)
                if not ok and "node binary not found" in err:
                    continue
                checked_any = True
                if not ok:
                    errors.append(f"{name}: {err.splitlines()[-1] if err else 'SyntaxError'}")
            if checked_any:
                res["js_syntax_ok"] = len(errors) == 0
                res["js_syntax_errors"] = errors
        except Exception as e:
            res["js_syntax_ok"] = False
            res["js_syntax_errors"] = [str(e)]

    if ion_asar_path and os.path.isfile(ion_asar_path):
        try:
            with open(ion_asar_path, "rb") as f:
                ion_data = f.read()
            if b"/*clp_drop*/" in ion_data:
                res["ion_dist_status"] = "BROKEN_LEGACY_ECT_PATCH"
            else:
                bak_path = ion_asar_path + ".stock.bak"
                if os.path.isfile(bak_path) and calculate_sha256(ion_asar_path) == calculate_sha256(bak_path):
                    res["ion_dist_status"] = "STOCK_VERIFIED"
                else:
                    res["ion_dist_status"] = "CLEAN_OR_STOCK"
        except Exception:
            res["ion_dist_status"] = "UNREADABLE"

    return res


def audit_launcher_flags(launcher_path, official_bin=None):
    """Checks launcher script for dead/unsupported switches and proxy configuration."""
    res = {
        "exists": False,
        "dead_flags_found": [],
        "proxy_flag_configured": False,
        "supported_flags_verified": True,
    }
    if not launcher_path or not os.path.isfile(launcher_path):
        return res

    res["exists"] = True
    try:
        with open(launcher_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        res["dead_flags_found"] = [flag for flag in DEAD_CHROMIUM_SWITCHES if flag in content]
        res["proxy_flag_configured"] = "--proxy-server" in content
        if res["dead_flags_found"]:
            res["supported_flags_verified"] = False

        # On Linux, if official ELF binary is readable, verify active switches against ELF strings
        if CURRENT_OS == "Linux" and official_bin and os.path.isfile(official_bin):
            try:
                with open(official_bin, "rb") as bf:
                    elf_data = bf.read()
                for _, sw, _ in ANTI_LEAK_SWITCHES:
                    if sw in content:
                        base_flag = sw.lstrip("-").split("=", 1)[0].encode("utf-8")
                        if (b"\x00" + base_flag + b"\x00") not in elf_data:
                            res["supported_flags_verified"] = False
                            if sw not in res["dead_flags_found"]:
                                res["dead_flags_found"].append(sw)
            except Exception:
                pass
    except Exception:
        pass
    return res


def audit_preferences_and_artifacts():
    """Audits Chromium Preferences, Sentry session.json activity, and tracking cookie counts (no values)."""
    cookies_path = PATHS.get("cookies_path")
    claude_dir = os.path.dirname(cookies_path) if cookies_path else None
    prefs_path = os.path.join(claude_dir, "Preferences") if claude_dir else None

    prefs_info = {"exists": False, "webrtc_policy": None, "dns_prefetch_disabled": None}
    if prefs_path and os.path.isfile(prefs_path):
        prefs_info["exists"] = True
        try:
            with open(prefs_path, "r", encoding="utf-8") as f:
                pdata = json.load(f)
            prefs_info["webrtc_policy"] = (pdata.get("webrtc") or {}).get("ip_handling_policy")
            dns_pref = (pdata.get("dns_prefetching") or {}).get("enabled")
            prefs_info["dns_prefetch_disabled"] = (dns_pref is False) if dns_pref is not None else None
        except Exception:
            pass

    sentry_dir = PATHS.get("sentry_dir")
    session_file = os.path.join(sentry_dir, "session.json") if sentry_dir else None
    sentry_info = {"session_exists": False, "age_seconds": None, "recently_active": False}
    if session_file and os.path.isfile(session_file):
        sentry_info["session_exists"] = True
        try:
            age = max(0, int(time.time() - os.path.getmtime(session_file)))
            sentry_info["age_seconds"] = age
            sentry_info["recently_active"] = age < 86400
        except Exception:
            pass

    cookie_counts = {name: 0 for name in TRACKED_COOKIE_NAMES}
    if cookies_path and os.path.isfile(cookies_path):
        try:
            conn = sqlite3.connect(f"file:{cookies_path}?mode=ro", uri=True)
            for name in TRACKED_COOKIE_NAMES:
                cookie_counts[name] = conn.execute(
                    "SELECT count(*) FROM cookies WHERE name=?",
                    (name,),
                ).fetchone()[0]
            conn.close()
        except Exception:
            pass

    return prefs_info, sentry_info, cookie_counts


def audit_proxy_and_tz(launcher_tz, launcher_audit, check_network=True):
    """Checks proxy /etc/hosts DNS bypass risk and launcher TZ vs proxy exit IP consistency."""
    env_proxy = resolve_proxy_url()
    proxy_active = bool(env_proxy or launcher_audit.get("proxy_flag_configured"))
    res = {
        "proxy_active": proxy_active,
        "hosts_bypass_warning": proxy_active,
        "exit_timezone": None,
        "exit_country": None,
        "tz_consistent": None,
    }
    if check_network:
        info = check_vpn_network(timeout=2.0)
        if info and info.get("status") == "success":
            exit_tz = info.get("timezone")
            res["exit_timezone"] = exit_tz
            res["exit_country"] = info.get("countryCode")
            if exit_tz and launcher_tz:
                res["tz_consistent"] = (exit_tz == launcher_tz)
    return res


def cmd_doctor(json_output=False, check_network=True):
    """Executes full diagnostic security audit and renders detailed tables or JSON."""
    if not json_output:
        console.print("\n[bold cyan]🔍 [1] Running Evidence-Based System & Security Audit...[/bold cyan]")
        console.print("[dim]" + "─" * 80 + "[/dim]")

    mdm_status = ENGINE.check_mdm_status()
    launcher_status = ENGINE.check_launcher_status()

    # Hosts check (exact non-comment token matching)
    hp = PATHS["hosts_path"]
    hosts_content = ""
    if hp and os.path.exists(hp):
        try:
            with open(hp, "r", encoding="utf-8") as f:
                hosts_content = f.read()
        except Exception:
            pass

    sinkholed_domains = parse_sinkholed_domains(hosts_content)
    sink_status = {dom: (dom.strip().lower() in sinkholed_domains) for dom, _, _, _ in TRACKER_SINKS}

    # Network Service socket audit
    active_sockets = []
    try:
        res = subprocess.run(["ss", "-tupn"], capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.strip().split("\n"):
                if "claude" in line.lower():
                    active_sockets.append(line.strip())
    except Exception:
        pass

    asar_status = check_asar_patch_status()
    did_status = check_ant_did_status()
    asar_internals = audit_asar_internals(PATHS.get("asar_path"), PATHS.get("ion_asar_path"))
    launcher_audit = audit_launcher_flags(PATHS.get("launcher_path"), PATHS.get("official_bin"))
    prefs_info, sentry_info, cookie_counts = audit_preferences_and_artifacts()
    launcher_tz = get_current_launcher_tz()
    proxy_audit = audit_proxy_and_tz(launcher_tz, launcher_audit, check_network=check_network)

    warnings = []
    if asar_internals["compile_cache_status"] == "ACTIVE_STOCK_BYTECODE":
        warnings.append("V8 compile-cache (*.x64.jsc) is active and can bypass zero-byte ASAR patches!")
    if asar_internals["ion_dist_status"] == "BROKEN_LEGACY_ECT_PATCH":
        warnings.append("ion-dist.asar contains legacy broken Ect patch (SyntaxError); rollback ion-dist.asar.")
    if launcher_audit["dead_flags_found"]:
        warnings.append(f"Launcher contains unsupported/dead switches: {', '.join(launcher_audit['dead_flags_found'])}")
    if proxy_audit["hosts_bypass_warning"]:
        warnings.append("Proxy active: /etc/hosts sinkholes are bypassed by proxy DNS; ASAR webRequest firewall is primary.")
    if proxy_audit["tz_consistent"] is False:
        warnings.append(
            f"Anti-ban TZ mismatch: launcher TZ={launcher_tz} vs exit IP TZ={proxy_audit['exit_timezone']} ({proxy_audit['exit_country']})."
        )
    elif proxy_audit["proxy_active"] and launcher_tz == "UTC" and proxy_audit["exit_timezone"] is None:
        warnings.append("Proxy active with TZ=UTC; run 'clp tz auto' so TZ matches proxy exit country.")
    if sentry_info["recently_active"]:
        warnings.append(f"sentry/session.json was updated {sentry_info['age_seconds']}s ago (Sentry may still be active).")

    audit_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "os": CURRENT_OS,
        "binary": PATHS["official_bin"],
        "binary_sha256": calculate_sha256(PATHS["official_bin"]),
        "asar": PATHS["asar_path"],
        "asar_sha256": calculate_sha256(PATHS["asar_path"]),
        "asar_patch_status": asar_status["status"],
        "asar_internals": asar_internals,
        "launcher_audit": launcher_audit,
        "preferences_audit": prefs_info,
        "sentry_activity": sentry_info,
        "cookie_counts": cookie_counts,
        "proxy_audit": proxy_audit,
        "ant_did_mode": did_status["mode"],
        "ant_did_uuid": did_status["uuid"],
        "mdm_policies": mdm_status,
        "anti_leak_switches": launcher_status,
        "tracker_sinkholes": sink_status,
        "active_claude_sockets": active_sockets,
        "launcher_tz": launcher_tz,
        "warnings": warnings,
    }

    if json_output:
        print(json.dumps(audit_data, indent=2))
        return

    # Table 1: MDM Policies
    t1 = Table(title="[bold cyan]1. Enterprise MDM Policy Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t1.add_column("Status", width=18, justify="center")
    t1.add_column("Policy Key", style="bold white", width=28)
    t1.add_column("Code Consumer & Architectural Scope", style="dim")
    t1.add_column("Confidence", width=22, justify="center")

    for p in MANAGED_POLICIES:
        act = mdm_status.get(p["key"], False)
        status_badge = "[bold green]✔ ACTIVE[/bold green]" if act else "[bold red]✘ INACTIVE[/bold red]"
        t1.add_row(status_badge, p["key"], p["code_consumer"], p["confidence"])
    console.print(t1)

    # Table 2: Chromium Anti-Leak Flags
    t2 = Table(title=f"[bold cyan]2. Chromium {len(ANTI_LEAK_SWITCHES)}-Flag Anti-Leak Shield Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t2.add_column("Status", width=18, justify="center")
    t2.add_column("Protection Component", style="bold white", width=28)
    t2.add_column("Switch Flag & Engine Translation", style="bold yellow", width=34)
    t2.add_column("Mitigation Scope", style="dim")

    for name, sw, desc in ANTI_LEAK_SWITCHES:
        act = launcher_status.get(sw, False)
        is_dead = sw in launcher_audit["dead_flags_found"]
        if act and is_dead:
            status_badge = "[bold yellow]⚠ UNSUPPORTED[/bold yellow]"
        elif act:
            status_badge = "[bold green]✔ ENFORCED[/bold green]"
        else:
            status_badge = "[bold red]✘ UNCONFIGURED[/bold red]"
        t2.add_row(status_badge, name, sw, desc)
    console.print(t2)

    # Table 3: Domain Sinkholes
    t3 = Table(title="[bold cyan]3. Egress Domain Sinkhole Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t3.add_column("Status", width=18, justify="center")
    t3.add_column("Target Domain", style="bold white", width=30)
    t3.add_column("Taxonomy Level", width=20, justify="center")
    t3.add_column("Threat Role & Architectural Verification", style="dim")

    for dom, role, tax, note in TRACKER_SINKS:
        act = sink_status.get(dom, False)
        status_badge = "[bold green]✔ SINKHOLED[/bold green]" if act else "[bold red]✘ OPEN[/bold red]"
        t3.add_row(status_badge, dom, f"[cyan]{tax}[/cyan]", f"{role} ({note})")
    console.print(t3)

    # Table 4: Real Runtime & ASAR Effectiveness Audit
    t4 = Table(title="[bold cyan]4. Real Runtime Effectiveness, ASAR & V8 Cache Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t4.add_column("Status", width=18, justify="center")
    t4.add_column("Audit Target", style="bold white", width=30)
    t4.add_column("Observed State", style="bold yellow", width=32)
    t4.add_column("Verification Details", style="dim")

    jsc_st = asar_internals["compile_cache_status"]
    jsc_badge = "[bold green]✔ CLEAN[/bold green]" if jsc_st in ("ABSENT", "INVALIDATED") else "[bold red]✘ BYPASS RISK[/bold red]"
    t4.add_row(jsc_badge, "V8 Compile Cache (.x64.jsc)", jsc_st, f"{asar_internals['compile_cache_files']} .x64.jsc file(s) in app.asar")

    art_ok = asar_internals["artifact_app_may_request_preserved"]
    art_badge = "[bold green]✔ PRESERVED[/bold green]" if art_ok else "[bold red]✘ MISSING[/bold red]"
    t4.add_row(art_badge, "artifactAppMayRequest Gate", str(art_ok), "Ensures sandboxed artifact request gating stays intact")

    hook_ok = asar_internals["session_created_hook_active"]
    hook_badge = "[bold green]✔ ACTIVE[/bold green]" if hook_ok else "[bold red]✘ INACTIVE[/bold red]"
    t4.add_row(hook_badge, "webRequest + session-created", "HOOKED" if hook_ok else "MISSING", "Covers defaultSession + all WebView partitions")

    mdm1p_ok = asar_internals["mdm_1p_unlocked"]
    mdm1p_badge = "[bold green]✔ UNLOCKED[/bold green]" if mdm1p_ok else "[bold red]✘ 3P-ONLY[/bold red]"
    t4.add_row(mdm1p_badge, "MDM 1p Scope Gate", "1p+3p" if mdm1p_ok else "3p-only", "Allows managed-settings.json telemetry opt-out in 1p mode")

    rtc_ok = asar_internals["webrtc_policy_enforced"]
    rtc_badge = "[bold green]✔ ENFORCED[/bold green]" if rtc_ok else "[bold yellow]⚠ PARTIAL[/bold yellow]"
    t4.add_row(rtc_badge, "WebRTC IP Policy", "disable_non_proxied_udp" if rtc_ok else "Unpatched", "Enforced via webContents.setWebRTCIPHandlingPolicy")

    syn_ok = asar_internals["js_syntax_ok"]
    syn_badge = "[bold green]✔ VALID[/bold green]" if syn_ok else ("[bold yellow]⚠ SKIPPED[/bold yellow]" if syn_ok is None else "[bold red]✘ SYNTAX ERR[/bold red]")
    t4.add_row(syn_badge, "app.asar JS Syntax (node)", "OK" if syn_ok else ("node missing" if syn_ok is None else "; ".join(asar_internals["js_syntax_errors"])), "Validates patched main/chunk JS via node --check")

    ion_st = asar_internals["ion_dist_status"]
    ion_badge = "[bold green]✔ VALID[/bold green]" if ion_st in ("STOCK_VERIFIED", "CLEAN_OR_STOCK", "NOT_FOUND") else "[bold red]✘ BROKEN[/bold red]"
    t4.add_row(ion_badge, "ion-dist.asar Integrity", ion_st, "Must remain stock/valid to avoid Ect SyntaxError")

    sentry_badge = "[bold yellow]⚠ ACTIVE[/bold yellow]" if sentry_info["recently_active"] else "[bold green]✔ QUIET[/bold green]"
    t4.add_row(sentry_badge, "Sentry session.json", f"age={sentry_info['age_seconds']}s" if sentry_info["session_exists"] else "Absent", "Detects live Crashpad/Sentry writes")

    cookie_summary = ", ".join(f"{k}:{v}" for k, v in cookie_counts.items())
    t4.add_row("[cyan]ℹ AUDIT[/cyan]", "Tracking Cookie Counts", cookie_summary, "Counts only (values never read or logged)")

    did_act = (did_status["mode"] == "EPHEMERAL_OR_ABSENT")
    did_badge = "[bold green]✔ EPHEMERAL[/bold green]" if did_act else "[bold yellow]⚠ PERSISTENT[/bold yellow]"
    t4.add_row(did_badge, "Device Identity (ant-did)", f"UUID: {did_status.get('uuid') or 'None'}", "Machine-bound base64 install identifier")

    console.print(t4)

    # Summary Panel
    all_mdm = all(mdm_status.values())
    all_sw = all(launcher_status.values()) and not launcher_audit["dead_flags_found"]
    all_asar = (
        asar_status["status"] == "NEUTRALIZED"
        and asar_internals["compile_cache_status"] in ("ABSENT", "INVALIDATED")
        and asar_internals["session_created_hook_active"]
        and asar_internals["ion_dist_status"] != "BROKEN_LEGACY_ECT_PATCH"
    )

    if warnings:
        console.print(Panel(
            "\n".join(f"[bold yellow]⚠[/bold yellow] {w}" for w in warnings),
            title="[bold yellow]Security & Anti-Ban Warnings[/bold yellow]",
            box=box.ROUNDED,
            border_style="yellow",
        ))

    if all_mdm and all_sw and all_asar and not warnings:
        console.print(Panel(
            f"[bold green]✨ VERIFIED HARDENED:[/bold green] MDM (1p unlocked), {len(ANTI_LEAK_SWITCHES)} supported switches, V8 compile-cache cleared, and ASAR webRequest firewall active.\n"
            f"[dim]Network sockets monitored: {len(active_sockets)} active Claude sockets.[/dim]",
            box=box.ROUNDED,
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[bold yellow]⚠ ATTENTION NEEDED:[/bold yellow] Review warnings/failures above and run [bold cyan]clp apply[/bold cyan] after Phase B updates.",
            box=box.ROUNDED,
            border_style="yellow",
        ))
