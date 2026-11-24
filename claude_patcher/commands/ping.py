"""
Network & Proxy Latency Ping Command.
"""
from rich.table import Table
from rich import box

from ..ui import console
from ..network import check_vpn_network


def cmd_ping():
    """Queries external IP geolocation to verify proxy routing, location, and latency."""
    console.print("\n[bold cyan]🌐 [2] Testing Proxy Encapsulation & Egress Latency...[/bold cyan]")
    console.print("[dim]" + "─" * 80 + "[/dim]")
    info = check_vpn_network()
    if info and info.get("status") == "success":
        t = Table(box=box.ROUNDED, show_header=False, expand=True)
        t.add_column("Metric", style="bold cyan", width=20)
        t.add_column("Details", style="bold white")
        t.add_row("Exit IP Address:", info.get("query", "Unknown"))
        t.add_row("Geographic Country:", f"{info.get('country', 'Unknown')} ({info.get('countryCode', '')})")
        t.add_row("City & Region:", f"{info.get('city', '')}, {info.get('regionName', '')}")
        t.add_row("ISP / Organization:", info.get("isp", "Unknown"))
        t.add_row("Recommended Timezone:", info.get("timezone", "UTC"))
        console.print(t)
    else:
        console.print("[bold red]✘ Could not reach IP geolocation endpoint. Check network connectivity or proxy routing.[/bold red]")
