"""
Claude Patcher Commands Registry.
"""
from .doctor import cmd_doctor
from .ping import cmd_ping
from .apply import cmd_apply
from .rollback import cmd_rollback
from .timezone import cmd_tz_auto, cmd_tz_manual
from .did import cmd_reset_did
from .launch import cmd_launch_claude
from .asar_cmd import cmd_toggle_asar

__all__ = [
    "cmd_doctor",
    "cmd_ping",
    "cmd_apply",
    "cmd_rollback",
    "cmd_tz_auto",
    "cmd_tz_manual",
    "cmd_reset_did",
    "cmd_launch_claude",
    "cmd_toggle_asar",
]
