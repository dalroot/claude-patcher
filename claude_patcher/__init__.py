"""
Claude Desktop Enterprise Security Shield & Multi-Platform Patcher (clp)
Version: 1.0.0-beta (Linux & Windows)
"""

__version__ = "1.0.0-beta"
__author__ = "dalroot"

from .cli import main
from .constants import VERSION, CLAUDE_COLOR, MANAGED_POLICIES, TRACKER_SINKS, ANTI_LEAK_SWITCHES
from .paths import PATHS, DynamicPathFinder
from .engines import get_engine, ENGINE
from .asar import check_asar_patch_status, apply_asar_patch, rollback_asar_patch
from .commands import (
    cmd_doctor,
    cmd_ping,
    cmd_apply,
    cmd_rollback,
    cmd_tz_auto,
    cmd_tz_manual,
    cmd_reset_did,
    cmd_launch_claude,
)

__all__ = [
    "main",
    "__version__",
    "__author__",
    "VERSION",
    "CLAUDE_COLOR",
    "MANAGED_POLICIES",
    "TRACKER_SINKS",
    "ANTI_LEAK_SWITCHES",
    "PATHS",
    "DynamicPathFinder",
    "get_engine",
    "ENGINE",
    "check_asar_patch_status",
    "apply_asar_patch",
    "rollback_asar_patch",
    "cmd_doctor",
    "cmd_ping",
    "cmd_apply",
    "cmd_rollback",
    "cmd_tz_auto",
    "cmd_tz_manual",
    "cmd_reset_did",
    "cmd_launch_claude",
]
