"""
Apply All Protections Command Implementation.
Deploys MDM policies, 11-flag Chromium shield, domain sinkholes, and zero-byte ASAR patches.
"""
import os
import uuid
import base64
import inspect
from rich.table import Table
from rich.panel import Panel
from rich import box

from ..ui import console
from ..engines import ENGINE
from ..paths import PATHS
from ..constants import CURRENT_OS, TRACKER_SINKS, MANAGED_POLICIES, ANTI_LEAK_SWITCHES, get_lang_for_country
from ..network import resolve_proxy_timezone
from ..sanitizer import harden_chromium_preferences
from ..system import (
    ensure_claude_closed,
    backup_pristine_state,
    run_privileged_write,
    get_current_launcher_tz,
    get_missing_sinkhole_domains,
)
from ..asar import apply_asar_patch


def _call_apply_asar(strict_sift=False):
    """Calls apply_asar_patch, forwarding strict_sift when supported by asar.py."""
    try:
        sig = inspect.signature(apply_asar_patch)
        if "strict_sift" in sig.parameters:
            return apply_asar_patch(strict_sift=strict_sift)
    except Exception:
        pass
    return apply_asar_patch()


def cmd_apply(tz=None, block_trackers=True, reset_did=False, strict_sift=False):
    """Enforces all enterprise privacy controls and anti-leak protections."""
    console.print("\n[bold green]🛠 [5] Applying Enterprise Policies & Multi-Platform Anti-Leak Shield...[/bold green]")
    console.print("[dim]" + "─" * 80 + "[/dim]")

    # 0. Ensure running Claude instances are cleanly terminated before patching
    ensure_claude_closed()

    backup_pristine_state()

    t = Table(title="[bold green]Enforcement Audit Results[/bold green]", box=box.ROUNDED, show_lines=True, expand=True)
    t.add_column("Status", width=18, justify="center")
    t.add_column("Security Component", style="bold white", width=30)
    t.add_column("Operational Details", style="dim")

    # 1. MDM Policies
    ENGINE.apply_mdm()
    t.add_row("[bold green]✔ APPLIED[/bold green]", "Enterprise MDM Policies", f"Configured {len(MANAGED_POLICIES)} policies across {CURRENT_OS} policy store")

    # 2. Hosts Sinkholes
    hp = PATHS["hosts_path"]
    if block_trackers and hp:
        hosts_content = ""
        hosts_readable = True
        if os.path.exists(hp):
            try:
                with open(hp, "r", encoding="utf-8") as f:
                    hosts_content = f.read()
            except Exception as e:
                hosts_readable = False
                t.add_row("[bold red]✘ ERROR[/bold red]", "Tracker Domains", f"Failed to read {hp}: {e}")

        if hosts_readable:
            missing_doms = get_missing_sinkhole_domains(hosts_content, [dom for dom, _, _, _ in TRACKER_SINKS])
            new_entries = [f"0.0.0.0 {dom}" for dom in missing_doms]
            if new_entries:
                prefix = "\n" if hosts_content and not hosts_content.endswith("\n") else ""
                addition = f"{prefix}# Claude Desktop Privacy Sinkhole (Managed by claude-patcher)\n" + "\n".join(new_entries) + "\n"
                run_privileged_write(hp, hosts_content + addition)

            t.add_row("[bold green]✔ SINKHOLED[/bold green]", f"Tracker Domains ({len(TRACKER_SINKS)} total)", f"Added {len(new_entries)} new; {len(TRACKER_SINKS)} routed to 0.0.0.0 in hosts")

    # 3. Launcher Wrapper & Chromium Flags (proxy-synced TZ + lang for anti-ban consistency)
    lp = PATHS.get("launcher_path")
    has_launcher = bool(lp and os.path.exists(lp))
    selected_tz, geo_info = resolve_proxy_timezone(
        explicit_tz=tz,
        current_tz=get_current_launcher_tz(),
        has_launcher=has_launcher,
    )
    selected_lang = get_lang_for_country(geo_info.get("countryCode")) if geo_info else "en-US"
    try:
        if "lang" in inspect.signature(ENGINE.apply_launcher).parameters:
            ENGINE.apply_launcher(selected_tz, lang=selected_lang)
        else:
            ENGINE.apply_launcher(selected_tz)
    except Exception:
        ENGINE.apply_launcher(selected_tz)

    tz_note = f"Cloaked Timezone: {selected_tz} (lang={selected_lang})"
    if geo_info:
        tz_note += f" (auto-synced to {geo_info.get('countryCode', '')} exit IP)"
    t.add_row("[bold green]✔ CONFIGURED[/bold green]", "Privacy Launcher Wrapper", tz_note)
    t.add_row("[bold green]✔ ENFORCED[/bold green]", f"{len(ANTI_LEAK_SWITCHES)}-Flag Chromium Shield", "Supported Chromium anti-leak flags & QUIC/locale hardening")

    pref_logs = harden_chromium_preferences()
    t.add_row("[bold green]✔ HARDENED[/bold green]", "Chromium Preferences", "; ".join(pref_logs) if pref_logs else "Enforced WebRTC & DNS prefetching profile preferences")

    # 4. Device Install ID
    adp = PATHS["ant_did_path"]
    if adp:
        if reset_did:
            os.makedirs(os.path.dirname(adp), exist_ok=True)
            new_uuid = str(uuid.uuid4())
            encoded = base64.b64encode(new_uuid.encode("utf-8")).decode("utf-8")
            with open(adp, "w") as f:
                f.write(encoded)
            try:
                os.chmod(adp, 0o600)
            except Exception:
                pass
            t.add_row("[bold green]✔ REGENERATED[/bold green]", "Install Identifier (ant-did)", f"Fresh UUID v4: {new_uuid}")
        else:
            t.add_row("[bold green]✔ VERIFIED[/bold green]", "Install Identifier (ant-did)", "Preserved for telemetry isolation")

    # 5. ASAR Multi-Layer Surgical Hardening
    ok_asar, msg_asar = _call_apply_asar(strict_sift=strict_sift)
    if ok_asar:
        t.add_row("[bold green]✔ NEUTRALIZED[/bold green]", "ASAR Multi-Layer Shield", msg_asar)
    else:
        t.add_row("[bold yellow]⚠ SKIPPED[/bold yellow]", "ASAR Multi-Layer Shield", msg_asar)

    console.print(t)
    if ok_asar:
        console.print(Panel("[bold green]✨ All enterprise policies, Chromium shields, hosts sinkholes & ASAR patches applied successfully![/bold green]", box=box.ROUNDED, border_style="green"))
    else:
        console.print(Panel(f"[bold yellow]⚠ Core policies, Chromium shields & hosts sinkholes applied, but ASAR patching was skipped: {msg_asar}[/bold yellow]", box=box.ROUNDED, border_style="yellow"))
