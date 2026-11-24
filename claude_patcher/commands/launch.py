"""
Claude Desktop Launch Command.
"""
import os
import subprocess
from ..ui import console
from ..paths import PATHS


def cmd_launch_claude():
    """Spawns Claude Desktop under active Privacy & Anti-Leak Shield."""
    console.print("\n[bold green]🚀 [8] Launching Claude Desktop under Anti-Leak Shield...[/bold green]")
    lp = PATHS["launcher_path"]
    ob = PATHS["official_bin"]

    if lp and os.path.exists(lp):
        target = lp
    elif ob and os.path.exists(ob):
        target = ob
    else:
        target = "claude-desktop"

    console.print(f"[dim]Spawning process: {target}[/dim]")
    try:
        subprocess.Popen([target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        console.print("[bold green]✔ Claude Desktop process launched successfully![/bold green]")
    except Exception as e:
        console.print(f"[bold red]✘ Failed to launch Claude process: {e}[/bold red]")
