"""
Claude Asterisk Header Banner & System Telemetry Display.
"""
import platform
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ..constants import CLAUDE_COLOR, CLAUDE_ASCII_LOGO, CURRENT_OS
from ..paths import PATHS
from ..system import get_current_launcher_tz

console = Console()


def print_header():
    """Renders the official Anthropic Claude asterisk logo alongside live system status."""
    console.clear()
    colored_logo = '\n'.join([f'[{CLAUDE_COLOR}]{line}[/{CLAUDE_COLOR}]' for line in CLAUDE_ASCII_LOGO])

    info_table = Table(box=None, show_header=False, pad_edge=False)
    info_table.add_column("Key", style="bold cyan", width=13)
    info_table.add_column("Val", style="bold white")

    info_table.add_row("Product:", "Claude Desktop Enterprise Security Shield")
    info_table.add_row("Version:", f"v1.0-beta ({CURRENT_OS})")
    info_table.add_row("Platform:", f"Dynamic Discovery ({platform.machine()})")
    info_table.add_row("Binary:", f"[dim]{PATHS['official_bin'] or 'Not Found'}[/dim]")
    info_table.add_row("Target ASAR:", f"[dim]{PATHS['asar_path'] or 'Auto-Detected'}[/dim]")
    info_table.add_row("Parity:", "Linux JSON & Windows Dual-Hive (HKLM/HKCU)")
    info_table.add_row("Status:", "[bold green]HARDENED & VERIFIED[/bold green]")
    info_table.add_row("Timezone:", f"[yellow]{get_current_launcher_tz()}[/yellow] [dim](Privacy Cloaked)[/dim]")

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
