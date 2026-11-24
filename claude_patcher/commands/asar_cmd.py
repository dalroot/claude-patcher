"""
Interactive ASAR Patch Toggle Command.
"""
from ..ui import console
from ..asar import check_asar_patch_status, apply_asar_patch, rollback_asar_patch


def cmd_toggle_asar():
    """Interactively checks and toggles surgical zero-byte ASAR patches."""
    console.print("\n[bold cyan]⚡ [9] ASAR In-Place GrowthBook Device-ID Patch[/bold cyan]")
    console.print("[dim]" + "─" * 80 + "[/dim]")
    st = check_asar_patch_status()
    if not st["exists"]:
        console.print(f"[bold red]✘ app.asar not found on this system[/bold red]")
        return

    if st["status"] == "NEUTRALIZED":
        console.print("[bold green]Status: Current ASAR is NEUTRALIZED (GrowthBook device-id header disabled).[/bold green]")
        try:
            c = input("Do you want to ROLLBACK ASAR to factory stock? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if c == "y":
            ok, msg = rollback_asar_patch()
            if ok:
                console.print(f"[bold green]✔ {msg}[/bold green]")
            else:
                console.print(f"[bold red]✘ Rollback failed: {msg}[/bold red]")
    else:
        console.print("[bold yellow]Status: Current ASAR is STOCK (GrowthBook sends device-id to claude.ai).[/bold yellow]")
        try:
            c = input("Do you want to APPLY zero-byte surgical patch? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if c == "y":
            ok, msg = apply_asar_patch()
            if ok:
                console.print(f"[bold green]✔ {msg}[/bold green]")
            else:
                console.print(f"[bold red]✘ Patch failed: {msg}[/bold red]")
