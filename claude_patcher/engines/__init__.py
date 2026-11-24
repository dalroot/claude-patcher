"""
Platform engine registry and factory.
"""
from ..constants import CURRENT_OS
from .base import BasePlatformEngine
from .linux import LinuxEngine
from .windows import WindowsEngine


def get_engine() -> BasePlatformEngine:
    """Returns platform-specific engine instance based on runtime OS."""
    if CURRENT_OS == "Windows":
        return WindowsEngine()
    else:
        return LinuxEngine()


ENGINE = get_engine()

__all__ = ["BasePlatformEngine", "LinuxEngine", "WindowsEngine", "get_engine", "ENGINE"]
