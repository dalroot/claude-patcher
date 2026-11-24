"""
Timezone Cloaking Configuration Commands.
"""
from ..ui import console
from ..constants import COUNTRY_TIMEZONES
from ..network import check_vpn_network
from .apply import cmd_apply


def cmd_tz_auto():
    """Detects exit proxy country via geolocation API and applies matching timezone."""
    console.print("\n[bold cyan]🌐 [3] Detecting Proxy Location for Automatic Timezone Cloaking...[/bold cyan]")
    info = check_vpn_network()
    if info and info.get("status") == "success":
        tz = info.get("timezone", "UTC")
        console.print(f"[bold green]✔ Detected Proxy Country:[/bold green] {info.get('country')} ({info.get('countryCode')})")
        console.print(f"[bold green]✔ Applying Matching Timezone:[/bold green] [bold white]{tz}[/bold white]")
        cmd_apply(tz=tz)
    else:
        console.print("[bold red]✘ Could not reach location endpoint; falling back to UTC.[/bold red]")
        cmd_apply(tz="UTC")


def cmd_tz_manual():
    """Presents an interactive menu to manually select a target destination timezone."""
    console.print("\n[bold cyan]🕒 [4] Manual Timezone Configuration[/bold cyan]")
    console.print("[dim]" + "─" * 80 + "[/dim]")
    keys = list(COUNTRY_TIMEZONES.keys())
    for idx, code in enumerate(keys, 1):
        tz = COUNTRY_TIMEZONES[code]
        console.print(f"  [bold yellow]{idx:2d})[/bold yellow] [bold white]{code}[/bold white] - {tz}")

    choice = input("\nEnter choice number (or press Enter for UTC): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(keys):
        selected_tz = COUNTRY_TIMEZONES[keys[int(choice) - 1]]
    else:
        selected_tz = "UTC"

    cmd_apply(tz=selected_tz)
