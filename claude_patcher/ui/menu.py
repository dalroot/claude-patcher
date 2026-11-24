"""
Interactive Control Center Menu Renderer.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_boxed_menu():
    """Renders the stylized rounded action menu."""
    menu = Table(box=box.ROUNDED, show_header=False, expand=True, border_style="cyan")
    menu.add_column("Option", style="bold yellow", width=8, justify="center")
    menu.add_column("Action", style="bold white", width=26)
    menu.add_column("Description", style="dim")

    menu.add_row("[1]", "Doctor & Audit", "Run evidence-based diagnostic on MDM, Anti-Leak & Sockets")
    menu.add_row("[2]", "Network & VPN Ping", "Test proxy encapsulation, latency, and geographic location")
    menu.add_row("[3]", "Set Timezone (Auto)", "Detect proxy country and cloak launcher timezone dynamically")
    menu.add_row("[4]", "Set Timezone (Manual)", "Choose a custom destination timezone from supported regions")
    menu.add_row("[5]", "Apply All Protections", "Deploy all shields: MDM, 11-flag Chromium, Hosts Sinkholes & ASAR Patch")
    menu.add_row("[6]", "Rollback to Stock", "Restore 100% factory state: remove policies, revert hosts & restore stock ASAR")
    menu.add_row("[7]", "Reset Install ID", "Generate fresh persistent install identifier (UUID v4)")
    menu.add_row("[8]", "Launch Claude", "Start Claude Desktop under active Privacy & Anti-Leak Shield")
    menu.add_row("[0]", "Exit", "Close Claude Patcher CLI")

    console.print(Panel(menu, title="[bold white]Control Center Actions[/bold white]", box=box.ROUNDED, border_style="cyan"))


def wait_for_menu_return():
    """Waits for user input to pause terminal output before clearing back to menu."""
    try:
        input("\nPress Enter or 0 to return to menu... ")
    except (KeyboardInterrupt, EOFError):
        pass
