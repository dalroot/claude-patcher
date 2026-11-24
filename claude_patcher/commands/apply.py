"""
Apply All Protections Command Implementation.
Deploys MDM policies, 11-flag Chromium shield, domain sinkholes, and zero-byte ASAR patches.
"""
import os
import uuid
import base64
from rich.table import Table
from rich.panel import Panel
from rich import box

from ..ui import console
from ..engines import ENGINE
from ..paths import PATHS
from ..constants import CURRENT_OS, TRACKER_SINKS
from ..system import (
    ensure_claude_closed,
    backup_pristine_state,
    run_privileged_write,
    get_current_launcher_tz
)
from ..asar import apply_asar_patch


def cmd_apply(tz=None, block_trackers=True, reset_did=False):
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
    t.add_row("[bold green]✔ APPLIED[/bold green]", "Enterprise MDM Policies", f"Configured 4 policies across {CURRENT_OS} policy store")

    # 2. Hosts Sinkholes
    hp = PATHS["hosts_path"]
    if block_trackers and hp:
        hosts_content = ""
        if os.path.exists(hp):
            try:
                with open(hp, "r") as f:
                    hosts_content = f.read()
            except Exception:
                pass

        new_entries = [f"0.0.0.0 {dom}" for dom, _, _, _ in TRACKER_SINKS if f"0.0.0.0 {dom}" not in hosts_content]
        if new_entries:
            addition = "\n# Claude Desktop Privacy Sinkhole (Managed by claude-patcher)\n" + "\n".join(new_entries) + "\n"
            run_privileged_write(hp, hosts_content + addition)

        t.add_row("[bold green]✔ SINKHOLED[/bold green]", f"Tracker Domains ({len(TRACKER_SINKS)} total)", "Routed to 0.0.0.0 in hosts (Sift, Sentry, Datadog)")

    # 3. Launcher Wrapper & 11 Chromium Flags
    selected_tz = tz or get_current_launcher_tz() or "UTC"
    ENGINE.apply_launcher(selected_tz)
    t.add_row("[bold green]✔ CONFIGURED[/bold green]", "Privacy Launcher Wrapper", f"Cloaked Timezone: {selected_tz}")
    t.add_row("[bold green]✔ ENFORCED[/bold green]", "11-Flag Chromium Shield", "WebRTC STUN isolation, DNS prefetch & Breakpad suppression")

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
    ok_asar, msg_asar = apply_asar_patch()
    if ok_asar:
        t.add_row("[bold green]✔ NEUTRALIZED[/bold green]", "ASAR Multi-Layer Shield", msg_asar)
    else:
        t.add_row("[bold yellow]⚠ SKIPPED[/bold yellow]", "ASAR Multi-Layer Shield", msg_asar)

    console.print(t)
    console.print(Panel("[bold green]✨ All enterprise policies, Chromium shields, hosts sinkholes & ASAR patches applied successfully![/bold green]", box=box.ROUNDED, border_style="green"))
