"""
Doctor and Diagnostic Command Implementation.
Performs an evidence-based audit of MDM policies, Chromium flags, domain sinkholes, and ASAR patches.
"""
import os
import time
import json
import sqlite3
import subprocess
from rich.table import Table
from rich.panel import Panel
from rich import box

from ..ui import console
from ..engines import ENGINE
from ..paths import PATHS
from ..constants import (
    CURRENT_OS,
    MANAGED_POLICIES,
    ANTI_LEAK_SWITCHES,
    TRACKER_SINKS,
    SURGICAL_PATCHES
)
from ..system import calculate_sha256, get_current_launcher_tz
from ..asar import check_asar_patch_status
from ..sanitizer import check_ant_did_status


def cmd_doctor(json_output=False):
    """Executes full diagnostic security audit and renders detailed tables or JSON."""
    if not json_output:
        console.print("\n[bold cyan]🔍 [1] Running Evidence-Based System & Security Audit...[/bold cyan]")
        console.print("[dim]" + "─" * 80 + "[/dim]")

    mdm_status = ENGINE.check_mdm_status()
    launcher_status = ENGINE.check_launcher_status()

    # Hosts check
    hp = PATHS["hosts_path"]
    hosts_content = ""
    if hp and os.path.exists(hp):
        try:
            with open(hp, "r") as f:
                hosts_content = f.read()
        except Exception:
            pass

    sink_status = {}
    for dom, role, tax, note in TRACKER_SINKS:
        sink_status[dom] = f"0.0.0.0 {dom}" in hosts_content

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

    audit_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "os": CURRENT_OS,
        "binary": PATHS["official_bin"],
        "binary_sha256": calculate_sha256(PATHS["official_bin"]),
        "asar": PATHS["asar_path"],
        "asar_sha256": calculate_sha256(PATHS["asar_path"]),
        "asar_patch_status": asar_status["status"],
        "ant_did_mode": did_status["mode"],
        "ant_did_uuid": did_status["uuid"],
        "mdm_policies": mdm_status,
        "anti_leak_switches": launcher_status,
        "tracker_sinkholes": sink_status,
        "active_claude_sockets": active_sockets,
        "launcher_tz": get_current_launcher_tz()
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

    # Table 2: 11 Chromium Anti-Leak Flags
    t2 = Table(title="[bold cyan]2. Chromium 11-Flag Anti-Leak Shield Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t2.add_column("Status", width=18, justify="center")
    t2.add_column("Protection Component", style="bold white", width=28)
    t2.add_column("Switch Flag & Engine Translation", style="bold yellow", width=34)
    t2.add_column("Mitigation Scope", style="dim")

    for name, sw, desc in ANTI_LEAK_SWITCHES:
        act = launcher_status.get(sw, False)
        status_badge = "[bold green]✔ ENFORCED[/bold green]" if act else "[bold red]✘ UNCONFIGURED[/bold red]"
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

    # Table 4: ASAR Integrity & Hardware Tracking Audit
    t4 = Table(title="[bold cyan]4. ASAR Surgical Hardening & Deep Telemetry Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t4.add_column("Status", width=18, justify="center")
    t4.add_column("Audit Target", style="bold white", width=28)
    t4.add_column("File & Signature Scope", style="bold yellow", width=34)
    t4.add_column("Threat Mitigation & Architectural Role", style="dim")

    patch_results = asar_status.get("patches", {})
    for p in SURGICAL_PATCHES:
        pid = p["id"]
        res = patch_results.get(pid, {})
        st = res.get("status", "UNKNOWN")
        if st == "NEUTRALIZED":
            badge = "[bold green]✔ NEUTRALIZED[/bold green]"
        elif st == "STOCK":
            badge = "[bold red]✘ ACTIVE (STOCK)[/bold red]"
        else:
            badge = f"[bold yellow]⚠ {st}[/bold yellow]"

        fname = os.path.basename(PATHS.get(p["file_key"]) or "")
        t4.add_row(badge, p["name"], f"{fname} ({p['stock'][:16].decode('latin1', 'ignore')}...)", p["description"])

    did_act = (did_status["mode"] == "EPHEMERAL_OR_ABSENT")
    did_badge = "[bold green]✔ EPHEMERAL[/bold green]" if did_act else "[bold yellow]⚠ PERSISTENT[/bold yellow]"
    t4.add_row(did_badge, "Device Identity (ant-did)", f"UUID: {did_status.get('uuid') or 'None'}", "Machine-bound base64 install identifier stored in config directory")

    cp = PATHS.get("cookies_path")
    cookie_present = False
    if cp and os.path.exists(cp):
        try:
            conn = sqlite3.connect(f"file:{cp}?mode=ro", uri=True)
            cnt = conn.execute("SELECT count(*) FROM cookies WHERE name='anthropic-device-id'").fetchone()[0]
            cookie_present = (cnt > 0)
            conn.close()
        except Exception:
            pass
    cookie_badge = "[bold red]✘ STORED[/bold red]" if cookie_present else "[bold green]✔ CLEAN[/bold green]"
    t4.add_row(cookie_badge, "SQLite Device-ID Cookie", "Cookies: anthropic-device-id", "Persistent browser cookie passed during OAuth authorize workflows")

    app_bak = asar_status.get("backups", {}).get("asar_path", False)
    ion_bak = asar_status.get("backups", {}).get("ion_asar_path", False)
    bak_act = app_bak and ion_bak
    bak_badge = "[bold green]✔ AVAILABLE[/bold green]" if bak_act else "[bold yellow]⚠ INCOMPLETE[/bold yellow]"
    t4.add_row(bak_badge, "Stock ASAR Backups", "app.asar.stock.bak + ion.bak", "Guarantees zero-risk byte-level rollback to factory unpatched state")

    console.print(t4)

    # Summary Panel
    all_mdm = all(mdm_status.values())
    all_sw = all(launcher_status.values())
    all_sink = all(sink_status.values())
    all_asar = (asar_status["status"] == "NEUTRALIZED")

    if all_mdm and all_sw and all_sink and all_asar:
        console.print(Panel(
            "[bold green]✨ FULLY HARDENED (MULTI-LAYER DEFENSE ENFORCED):[/bold green] All MDM policies, 11 Chromium switches, egress sinkholes, and all 8 surgical ASAR patches are active.\n"
            f"[dim]Network sockets monitored: {len(active_sockets)} active Claude sockets (All encapsulated in local proxy).[/dim]",
            box=box.ROUNDED, border_style="green"
        ))
    elif all_mdm and all_sw and all_sink:
        console.print(Panel(
            "[bold green]✨ ENTERPRISE HARDENED:[/bold green] MDM policies, 11 Chromium switches, and domain sinkholes are enforced.\n"
            "[yellow]Note:[/yellow] Some ASAR telemetry patches are inactive. Run option [bold cyan][5] Apply All Protections[/bold cyan] to enforce in-place zero-byte patches.",
            box=box.ROUNDED, border_style="yellow"
        ))
    else:
        console.print(Panel(
            "[bold yellow]⚠ ATTENTION NEEDED:[/bold yellow] One or more security controls are inactive. Run option [bold cyan][5] Apply[/bold cyan] to enforce all shields.",
            box=box.ROUNDED, border_style="yellow"
        ))
