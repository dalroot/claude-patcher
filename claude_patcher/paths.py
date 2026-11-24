"""
Dynamic Path Finder for Claude Desktop installation discovery across Linux, Windows, and macOS.
Zero-hardcode dynamic resolution pattern adhering to clig.dev.
"""
import os
import glob
import shutil
import platform


class DynamicPathFinder:
    """Dynamically resolves binary, config, registry, and hosts endpoints across OSes."""

    @staticmethod
    def discover():
        os_type = platform.system()
        if os_type == "Linux":
            return DynamicPathFinder._discover_linux()
        elif os_type == "Windows":
            return DynamicPathFinder._discover_windows()
        elif os_type == "Darwin":
            return DynamicPathFinder._discover_darwin()
        else:
            return DynamicPathFinder._discover_generic(os_type)

    @staticmethod
    def _discover_linux():
        bin_path = None
        for alias in ["claude-desktop", "claude"]:
            w = shutil.which(alias)
            if w and os.path.exists(w) and not os.path.islink(w):
                bin_path = w
                break

        if not bin_path:
            candidates = [
                "/usr/lib/claude-desktop/claude-desktop",
                "/usr/lib64/claude-desktop/claude-desktop",
                "/opt/Claude/claude-desktop",
                "/opt/claude-desktop/claude-desktop",
                os.path.expanduser("~/.local/lib/claude-desktop/claude-desktop"),
                os.path.expanduser("~/.local/bin/claude-desktop")
            ]
            for c in candidates:
                if os.path.exists(c) and not os.path.islink(c):
                    bin_path = c
                    break

        if not bin_path:
            bin_path = "/usr/lib/claude-desktop/claude-desktop"

        asar_path = None
        ion_asar_path = None
        if os.path.exists(bin_path):
            cand = os.path.join(os.path.dirname(bin_path), "resources", "app.asar")
            if os.path.exists(cand):
                asar_path = cand
            cand_ion = os.path.join(os.path.dirname(bin_path), "resources", "ion-dist.asar")
            if os.path.exists(cand_ion):
                ion_asar_path = cand_ion

        xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))

        return {
            "os": "Linux",
            "official_bin": bin_path,
            "asar_path": asar_path,
            "ion_asar_path": ion_asar_path,
            "cookies_path": os.path.join(xdg_config, "Claude", "Cookies"),
            "sentry_dir": os.path.join(xdg_config, "Claude", "sentry"),
            "managed_settings": "/etc/claude-desktop/managed-settings.json",
            "managed_dir": "/etc/claude-desktop",
            "hosts_path": "/etc/hosts",
            "ant_did_path": os.path.join(xdg_config, "Claude", "ant-did"),
            "launcher_path": "/usr/local/bin/claude-privacy",
            "bin_link_path": "/usr/bin/claude-desktop",
            "backup_dir": "/var/backups/claude-patcher"
        }

    @staticmethod
    def _discover_windows():
        local_app = os.environ.get("LOCALAPPDATA", "")
        user_prof = os.environ.get("USERPROFILE", r"C:\Users\Default")
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        app_data = os.environ.get("APPDATA", os.path.join(user_prof, "AppData", "Roaming"))

        bin_path = None
        # 1. Search PATH execution aliases
        for alias in ["claude-desktop.exe", "claude.exe"]:
            w = shutil.which(alias)
            if w and os.path.exists(w):
                bin_path = w
                break

        # 2. Search MSIX WindowsApps & LocalAppData installations
        if not bin_path and local_app:
            winapps_alias = os.path.join(local_app, "Microsoft", "WindowsApps", "claude-desktop.exe")
            if os.path.exists(winapps_alias):
                bin_path = winapps_alias
            else:
                patterns = [
                    os.path.join(local_app, "Microsoft", "WindowsApps", "*Claude*", "Claude.exe"),
                    os.path.join(prog_files, "WindowsApps", "*AnthropicClaude*", "Claude.exe"),
                    os.path.join(prog_files, "WindowsApps", "*AnthropicClaude*", "app", "Claude.exe"),
                    os.path.join(local_app, "Programs", "Claude", "Claude.exe"),
                    os.path.join(local_app, "AnthropicClaude", "Claude.exe"),
                    os.path.join(local_app, "Claude", "Claude.exe"),
                    os.path.join(prog_files, "Claude", "Claude.exe"),
                ]
                for pat in patterns:
                    matches = glob.glob(pat)
                    if matches:
                        bin_path = matches[0]
                        break

        if not bin_path:
            bin_path = os.path.join(local_app, "Programs", "Claude", "Claude.exe") if local_app else r"C:\Claude\Claude.exe"

        asar_path = None
        ion_asar_path = None
        if os.path.exists(bin_path):
            cand = os.path.join(os.path.dirname(bin_path), "resources", "app.asar")
            if os.path.exists(cand):
                asar_path = cand
            cand_ion = os.path.join(os.path.dirname(bin_path), "resources", "ion-dist.asar")
            if os.path.exists(cand_ion):
                ion_asar_path = cand_ion

        return {
            "os": "Windows",
            "official_bin": bin_path,
            "asar_path": asar_path,
            "ion_asar_path": ion_asar_path,
            "cookies_path": os.path.join(app_data, "Claude", "Network", "Cookies") if os.path.exists(os.path.join(app_data, "Claude", "Network", "Cookies")) else os.path.join(app_data, "Claude", "Cookies"),
            "sentry_dir": os.path.join(app_data, "Claude", "sentry"),
            "managed_settings_hklm": r"HKLM\SOFTWARE\Policies\Claude",
            "managed_settings_hkcu": r"HKCU\SOFTWARE\Policies\Claude",
            "hosts_path": os.path.join(sys_root, "System32", "drivers", "etc", "hosts"),
            "ant_did_path": os.path.join(app_data, "Claude", "ant-did"),
            "launcher_path": os.path.join(local_app or user_prof, "Programs", "Claude", "claude-privacy.cmd"),
            "backup_dir": os.path.join(local_app or user_prof, "ClaudePatcher", "backups")
        }

    @staticmethod
    def _discover_darwin():
        candidates = [
            "/Applications/Claude.app/Contents/MacOS/Claude",
            os.path.expanduser("~/Applications/Claude.app/Contents/MacOS/Claude")
        ]
        bin_path = None
        for c in candidates:
            if os.path.exists(c):
                bin_path = c
                break
        if not bin_path:
            bin_path = candidates[0]

        asar_path = "/Applications/Claude.app/Contents/Resources/app.asar" if os.path.exists(bin_path) else None

        return {
            "os": "Darwin",
            "official_bin": bin_path,
            "asar_path": asar_path,
            "managed_settings": "/Library/Managed Preferences/com.anthropic.claudefordesktop.plist",
            "hosts_path": "/etc/hosts",
            "ant_did_path": os.path.expanduser("~/Library/Application Support/Claude/ant-did"),
            "launcher_path": "/usr/local/bin/claude-privacy",
            "backup_dir": "/var/backups/claude-patcher"
        }

    @staticmethod
    def _discover_generic(os_type):
        return {
            "os": os_type,
            "official_bin": None,
            "asar_path": None,
            "hosts_path": "/etc/hosts",
            "ant_did_path": None,
            "launcher_path": None,
            "backup_dir": "/tmp/claude-patcher-backup"
        }


PATHS = DynamicPathFinder.discover()
PRISTINE_HOSTS_BAK = os.path.join(PATHS["backup_dir"], "pristine_hosts.bak")
