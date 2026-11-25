"""
Abstract Base Platform Engine for OS-specific MDM and launcher implementations.
"""
from abc import ABC, abstractmethod


class BasePlatformEngine(ABC):
    """Abstract interface defining required platform policy and launcher hooks."""

    @abstractmethod
    def apply_mdm(self):
        """Enforces enterprise MDM policies in the platform policy store."""
        pass

    @abstractmethod
    def rollback_mdm(self):
        """Removes enterprise MDM policies from the platform policy store."""
        pass

    @abstractmethod
    def check_mdm_status(self):
        """Queries the platform policy store and returns a dictionary of active policy keys."""
        pass

    @abstractmethod
    def apply_launcher(self, tz="UTC"):
        """Deploys a hardened wrapper script enforcing Chromium anti-leak flags and timezone cloaking."""
        pass

    @abstractmethod
    def rollback_launcher(self):
        """Reverts the launcher wrapper and points back to the stock binary."""
        pass

    @abstractmethod
    def check_launcher_status(self):
        """Inspects the launcher script and returns a dictionary of active flag states."""
        pass

    def get_launcher_diagnostics(self):
        """Returns structured diagnostics on wrapper deployment and entrypoint linkage."""
        return {
            "wrapper_exists": False,
            "wrapper_path": None,
            "linked": False,
            "unlinked_warning": None,
        }
