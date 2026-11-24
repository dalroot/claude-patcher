"""
Device Install Identifier Reset Command.
"""
from ..ui import console
from .apply import cmd_apply


def cmd_reset_did():
    """Forces regeneration of the machine-bound ant-did install identifier."""
    console.print("\n[bold yellow]🆔 [7] Regenerating Persistent Install Identifier (UUID v4)...[/bold yellow]")
    cmd_apply(reset_did=True)
