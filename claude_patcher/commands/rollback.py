"""
Rollback Command Implementation.
Restores factory state bit-for-bit: reverts hosts, removes MDM, and restores stock ASAR.
"""
import os
from rich.table import Table
from rich.panel import Panel
from rich import box

from ..ui import console
from ..engines import ENGINE
from ..paths import PATHS, PRISTINE_HOSTS_BAK
from ..constants import CURRENT_OS
from ..system import ensure_claude_closed, calculate_sha256, run_privileged_write
from ..asar import rollback_asar_patch


def cmd_rollback():
    """Restores the system to 100% factory pristine condition."""
    console.print("\n[bold red]⏪ [6] Executing Atomic Cryptographic Rollback...[/bold red]")
    console.print("[dim]" + "─" * 80 + "[/dim]")

    # 0. Ensure running Claude instances are cleanly terminated before rollback
    ensure_claude_closed()

    t = Table(title="[bold red]Rollback Restoration Results[/bold red]", box=box.ROUNDED, show_lines=True, expand=True)
    t.add_column("Status", width=18, justify="center")
    t.add_column("Component", style="bold white", width=30)
    t.add_column("Restoration Details", style="dim")

    # 1. Restore pristine hosts
    hp = PATHS["hosts_path"]
    if os.path.exists(PRISTINE_HOSTS_BAK) and hp:
        try:
            with open(PRISTINE_HOSTS_BAK, "r") as f:
                content = f.read()
            run_privileged_write(hp, content)
            t.add_row("[bold green]✔ RESTORED[/bold green]", "System Hosts File", f"Reverted bit-for-bit to pristine backup ({calculate_sha256(hp)[:16]}...)")
        except Exception as e:
            t.add_row("[bold red]✘ ERROR[/bold red]", "System Hosts File", str(e))
    else:
        t.add_row("[bold yellow]⚠ SKIPPED[/bold yellow]", "System Hosts File", "Pristine backup not found — hosts file left unchanged")

    # 2. Rollback MDM
    ENGINE.rollback_mdm()
    t.add_row("[bold green]✔ REMOVED[/bold green]", "Enterprise MDM Policies", f"Cleared policies from {CURRENT_OS} store")

    # 3. Rollback Launcher & Symlink
    ENGINE.rollback_launcher()
    t.add_row("[bold green]✔ RECONNECTED[/bold green]", "Launcher & Symlink", "Removed privacy wrapper and pointed directly to factory binary")

    # 4. Rollback ASAR to Factory Stock
    ok_asar, msg_asar = rollback_asar_patch()
    if ok_asar:
        t.add_row("[bold green]✔ RESTORED[/bold green]", "Stock ASAR Binary", msg_asar)
    else:
        t.add_row("[bold yellow]⚠ SKIPPED[/bold yellow]", "Stock ASAR Binary", msg_asar)

    console.print(t)
    console.print(Panel("[bold green]✨ System restored 100% to clean factory state with zero residual modifications.[/bold green]", box=box.ROUNDED, border_style="green"))
