"""
Claude Asterisk Header Banner & System Telemetry Display.
"""
import os
import platform
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ..constants import CLAUDE_COLOR, CLAUDE_ASCII_LOGO, CURRENT_OS, VERSION
from ..engines import ENGINE
from ..paths import PATHS
from ..system import get_current_launcher_tz

console = Console()


def get_banner_status():
    """Computes an honest, dynamic configuration summary for the interactive header."""
    lp = PATHS.get("launcher_path")
    launcher_exists = bool(lp and os.path.exists(lp))
    try:
        mdm = ENGINE.check_mdm_status() or {}
        switches = ENGINE.check_launcher_status() or {}
    except Exception:
        return "[yellow]UNKNOWN (Run [1] Doctor to inspect)[/yellow]", launcher_exists

    mdm_total = len(mdm)
    mdm_active = sum(1 for v in mdm.values() if v)
    sw_total = len(switches)
    sw_active = sum(1 for v in switches.values() if v)

    if mdm_total > 0 and mdm_active == mdm_total and launcher_exists and sw_total > 0 and sw_active == sw_total:
        return "[bold cyan]CONFIGURED (Run [1] Doctor to verify)[/bold cyan]", launcher_exists
    if mdm_active > 0 or sw_active > 0 or launcher_exists:
        return (
            f"[bold yellow]PARTIAL (MDM {mdm_active}/{mdm_total}, Flags {sw_active}/{sw_total} — Run Doctor)[/bold yellow]",
            launcher_exists,
        )
    return "[dim]UNCONFIGURED (Stock / Not Hardened)[/dim]", launcher_exists


def print_header():
    """Renders the official Anthropic Claude asterisk logo alongside live system status."""
    console.clear()
    colored_logo = '\n'.join([f'[{CLAUDE_COLOR}]{line}[/{CLAUDE_COLOR}]' for line in CLAUDE_ASCII_LOGO])
    status_text, launcher_exists = get_banner_status()

    info_table = Table(box=None, show_header=False, pad_edge=False)
    info_table.add_column("Key", style="bold cyan", width=13)
    info_table.add_column("Val", style="bold white")

    info_table.add_row("Product:", "Claude Desktop Enterprise Security Shield")
    info_table.add_row("Version:", f"v{VERSION} ({CURRENT_OS})")
    info_table.add_row("Platform:", f"Dynamic Discovery ({platform.machine()})")
    info_table.add_row("Binary:", f"[dim]{PATHS.get('official_bin') or 'Not Found'}[/dim]")
    info_table.add_row("Target ASAR:", f"[dim]{PATHS.get('asar_path') or 'Not Found'}[/dim]")
    info_table.add_row("Parity:", "Linux JSON & Windows Dual-Hive (HKLM/HKCU)")
    info_table.add_row("Status:", status_text)
    if launcher_exists:
        info_table.add_row("Timezone:", f"[yellow]{get_current_launcher_tz()}[/yellow] [dim](Launcher Configured)[/dim]")
    else:
        info_table.add_row("Timezone:", "[dim]System Default (No Launcher)[/dim]")

    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="center", vertical="middle")
    grid.add_column(vertical="middle")
    grid.add_row(colored_logo, info_table)

    banner = Panel(
        grid,
        title=f"[bold {CLAUDE_COLOR}] Anthropic Claude Enterprise Security & Anti-Leak Suite [/bold {CLAUDE_COLOR}]",
        border_style=CLAUDE_COLOR,
        box=box.ROUNDED
    )
    console.print(banner)
