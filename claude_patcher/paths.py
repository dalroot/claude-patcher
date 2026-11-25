"""
Dynamic Path Finder for Claude Desktop installation discovery across Linux, Windows, and macOS.
Zero-hardcode dynamic resolution pattern adhering to clig.dev.
"""
import os
import glob
import plistlib
import shutil
import platform

# Electron @electron/fuses v1 sentinel (32 bytes)
ELECTRON_FUSES_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
FUSE_INDEX_ASAR_INTEGRITY = 4  # EnableEmbeddedAsarIntegrityValidation
FUSE_INDEX_ONLY_LOAD_ASAR = 5  # OnlyLoadAppFromAsar


def _has_electron_bundle_layout(app_dir):
    """Returns True if app_dir resembles an Electron Claude Desktop root directory."""
    if not app_dir or not os.path.isdir(app_dir):
        return False
    markers = (
        os.path.join(app_dir, "resources", "app.asar"),
        os.path.join(app_dir, "resources", "app.asar.stock.bak"),
        os.path.join(app_dir, "resources", "app"),
        os.path.join(app_dir, "app", "resources", "app.asar"),
        os.path.join(app_dir, "app", "resources", "app.asar.stock.bak"),
        os.path.join(app_dir, "resources.pak"),
    )
    return any(os.path.exists(m) for m in markers)


def _is_linux_desktop_binary(path):
    """
    Verifies that a candidate Linux path points to an actual Claude Desktop Electron binary,
    preventing non-desktop 'claude' binaries (Claude Code CLI) or shell wrappers from matching.
    """
    if not path or not os.path.exists(path):
        return False
    real = os.path.realpath(path)
    if not os.path.isfile(real) or not os.access(real, os.X_OK):
        return False
    if os.path.basename(real) == "claude-privacy":
        return False
    return _has_electron_bundle_layout(os.path.dirname(real))


def _is_windows_desktop_binary(path):
    """
    Verifies that a candidate Windows path belongs to Claude Desktop (Electron or MSIX),
    preventing Claude Code CLI ('claude.exe') from matching on PATH.
    """
    if not path or not os.path.exists(path):
        return False
    if not os.path.isfile(path):
        return False
    app_dir = os.path.dirname(path)
    if _has_electron_bundle_layout(app_dir):
        return True
    norm = os.path.normpath(path).lower()
    if "windowsapps" in norm and ("anthropicclaude" in norm or os.path.basename(norm) == "claude-desktop.exe"):
        return True
    return False


def _is_darwin_desktop_binary(path):
    """Verifies that a candidate macOS path belongs to a Claude.app bundle."""
    if not path or not os.path.exists(path):
        return False
    real = os.path.realpath(path)
    if not os.path.isfile(real):
        return False
    resources_dir = os.path.normpath(os.path.join(os.path.dirname(real), "..", "Resources"))
    return (
        os.path.exists(os.path.join(resources_dir, "app.asar"))
        or os.path.exists(os.path.join(resources_dir, "app.asar.stock.bak"))
        or os.path.exists(os.path.join(resources_dir, "app"))
    )


def read_electron_fuses(bin_path):
    """
    Inspects an Electron binary for the v1 @electron/fuses wire header.
    Returns a dict of parsed fuse flags, or None if unreadable or not present.
    """
    if not bin_path or not os.path.isfile(bin_path):
        return None
    sentinel = ELECTRON_FUSES_SENTINEL
    chunk_size = 4 * 1024 * 1024
    overlap = len(sentinel) + 64
    try:
        with open(bin_path, "rb") as f:
            tail = b""
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buf = tail + chunk
                idx = buf.find(sentinel)
                if idx != -1:
                    after = buf[idx + len(sentinel):]
                    if len(after) < 2:
                        after += f.read(64)
                    if len(after) >= 2:
                        version = after[0]
                        count = after[1]
                        if len(after) < 2 + count:
                            after += f.read(2 + count - len(after))
                        states = after[2:2 + count]
                        if len(states) == count:
                            return {
                                "version": version,
                                "count": count,
                                "raw": states.decode("ascii", errors="replace"),
                                "enable_embedded_asar_integrity_validation": (
                                    states[FUSE_INDEX_ASAR_INTEGRITY] == ord("1")
                                    if count > FUSE_INDEX_ASAR_INTEGRITY else None
                                ),
                                "only_load_app_from_asar": (
                                    states[FUSE_INDEX_ONLY_LOAD_ASAR] == ord("1")
                                    if count > FUSE_INDEX_ONLY_LOAD_ASAR else None
                                ),
                            }
                    break
                tail = buf[-overlap:] if len(buf) >= overlap else buf
    except OSError:
        return None
    return None


def inspect_asar_integrity_risk(official_bin, os_type, asar_path=None):
    """
    Evaluates Electron EnableEmbeddedAsarIntegrityValidation and package signing constraints
    on Windows (including MSIX/WindowsApps) and macOS (Info.plist + codesign).
    """
    bin_lower = (official_bin or "").lower()
    asar_lower = (asar_path or "").lower()
    is_msix = ("windowsapps" in bin_lower) or ("windowsapps" in asar_lower)
    fuses = read_electron_fuses(official_bin) if official_bin else None
    fuse_integrity = fuses.get("enable_embedded_asar_integrity_validation") if fuses else None

    if os_type == "Windows":
        if is_msix:
            enforced = fuse_integrity is not False
            warning = (
                "Windows Store/MSIX install detected (WindowsApps). Package files are "
                "read-only/TrustedInstaller-signed and Electron EnableEmbeddedAsarIntegrityValidation "
                "will abort startup if app.asar is modified without re-signing or fuse bypass. "
                "MDM policies, hosts sinkholes, and launcher protections remain safe."
            )
            return {
                "is_msix": True,
                "fuse_asar_integrity": fuse_integrity,
                "asar_integrity_enforced": enforced,
                "asar_integrity_warning": warning,
            }
        if fuse_integrity is True:
            return {
                "is_msix": False,
                "fuse_asar_integrity": True,
                "asar_integrity_enforced": True,
                "asar_integrity_warning": (
                    "Electron EnableEmbeddedAsarIntegrityValidation fuse is enabled in Claude.exe. "
                    "Modifying app.asar without updating PE integrity / re-signing will fail startup "
                    "validation. Use MDM policies, hosts sinkholes, and launcher flags instead or "
                    "disable the fuse cleanly."
                ),
            }
        return {
            "is_msix": False,
            "fuse_asar_integrity": fuse_integrity,
            "asar_integrity_enforced": False if fuse_integrity is False else None,
            "asar_integrity_warning": None,
        }

    if os_type == "Darwin":
        plist_integrity = False
        if official_bin:
            plist_path = os.path.normpath(os.path.join(os.path.dirname(official_bin), "..", "Info.plist"))
            if os.path.isfile(plist_path):
                try:
                    with open(plist_path, "rb") as pf:
                        plist_data = plistlib.load(pf)
                    plist_integrity = bool(plist_data.get("ElectronAsarIntegrity"))
                except Exception:
                    pass
        if plist_integrity or fuse_integrity is True:
            return {
                "is_msix": False,
                "fuse_asar_integrity": fuse_integrity,
                "asar_integrity_enforced": True,
                "asar_integrity_warning": (
                    "macOS Claude.app enables EnableEmbeddedAsarIntegrityValidation / Info.plist "
                    "ElectronAsarIntegrity and Apple code signing. Modifying app.asar without updating "
                    "Info.plist hashes, disabling the fuse, and re-signing breaks Gatekeeper/launch."
                ),
            }
        return {
            "is_msix": False,
            "fuse_asar_integrity": fuse_integrity,
            "asar_integrity_enforced": False if fuse_integrity is False else None,
            "asar_integrity_warning": None,
        }

    # Linux Electron does not enforce EnableEmbeddedAsarIntegrityValidation in ELF resources.
    return {
        "is_msix": False,
        "fuse_asar_integrity": fuse_integrity,
        "asar_integrity_enforced": False,
        "asar_integrity_warning": None,
    }


def _find_asar_in_dir(base_dir):
    """Resolves app.asar and ion-dist.asar from an Electron application or resources root."""
    if not base_dir:
        return None, None
    search_roots = [
        os.path.join(base_dir, "resources"),
        os.path.join(base_dir, "app", "resources"),
        os.path.normpath(os.path.join(base_dir, "..", "Resources")),
        os.path.normpath(os.path.join(base_dir, "..", "resources")),
    ]
    asar_path = None
    ion_asar_path = None
    for rdir in search_roots:
        if not os.path.isdir(rdir):
            continue
        if not asar_path:
            cand = os.path.join(rdir, "app.asar")
            if os.path.exists(cand):
                asar_path = cand
        if not ion_asar_path:
            cand_ion = os.path.join(rdir, "ion-dist.asar")
            if os.path.exists(cand_ion):
                ion_asar_path = cand_ion
        if asar_path and ion_asar_path:
            break
    return asar_path, ion_asar_path


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

        w_desktop = shutil.which("claude-desktop")
        if _is_linux_desktop_binary(w_desktop):
            bin_path = os.path.realpath(w_desktop)

        if not bin_path:
            candidates = [
                "/usr/lib/claude-desktop/claude-desktop",
                "/usr/lib64/claude-desktop/claude-desktop",
                "/opt/Claude/claude-desktop",
                "/opt/claude-desktop/claude-desktop",
                "/usr/share/claude-desktop/claude-desktop",
                os.path.expanduser("~/.local/lib/claude-desktop/claude-desktop"),
                os.path.expanduser("~/.local/share/claude-desktop/claude-desktop"),
                os.path.expanduser("~/.local/bin/claude-desktop"),
            ]
            for c in candidates:
                if _is_linux_desktop_binary(c):
                    bin_path = os.path.realpath(c)
                    break

        if not bin_path:
            # Only accept "claude" alias if it actually points to an Electron desktop bundle,
            # never Claude Code CLI.
            w_claude = shutil.which("claude")
            if _is_linux_desktop_binary(w_claude):
                bin_path = os.path.realpath(w_claude)

        asar_path, ion_asar_path = _find_asar_in_dir(os.path.dirname(bin_path)) if bin_path else (None, None)

        xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        claude_cfg = os.path.join(xdg_config, "Claude")
        net_cookies = os.path.join(claude_cfg, "Network", "Cookies")
        cookies_path = net_cookies if os.path.exists(net_cookies) else os.path.join(claude_cfg, "Cookies")

        risk = inspect_asar_integrity_risk(bin_path, "Linux", asar_path)

        return {
            "os": "Linux",
            "official_bin": bin_path,
            "asar_path": asar_path,
            "ion_asar_path": ion_asar_path,
            "cookies_path": cookies_path,
            "sentry_dir": os.path.join(claude_cfg, "sentry"),
            "managed_settings": "/etc/claude-desktop/managed-settings.json",
            "managed_dir": "/etc/claude-desktop",
            "managed_settings_hklm": None,
            "managed_settings_hkcu": None,
            "hosts_path": "/etc/hosts",
            "ant_did_path": os.path.join(claude_cfg, "ant-did"),
            "launcher_path": "/usr/local/bin/claude-privacy",
            "bin_link_path": "/usr/bin/claude-desktop",
            "backup_dir": "/var/backups/claude-patcher",
            "is_msix": risk["is_msix"],
            "asar_integrity_enforced": risk["asar_integrity_enforced"],
            "asar_integrity_warning": risk["asar_integrity_warning"],
        }

    @staticmethod
    def _discover_windows():
        local_app = os.environ.get("LOCALAPPDATA", "")
        user_prof = os.environ.get("USERPROFILE", r"C:\Users\Default")
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        prog_w6432 = os.environ.get("ProgramW6432", prog_files)
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        app_data = os.environ.get("APPDATA", os.path.join(user_prof, "AppData", "Roaming"))

        prog_roots = []
        for pr in (prog_files, prog_w6432):
            if pr and pr not in prog_roots:
                prog_roots.append(pr)

        bin_path = None
        # 1. Search PATH execution aliases (verified as desktop binary, not Claude Code CLI)
        for alias in ["claude-desktop.exe", "Claude.exe", "claude.exe"]:
            w = shutil.which(alias)
            if _is_windows_desktop_binary(w):
                bin_path = w
                break

        # 2. Search MSIX WindowsApps, Squirrel, and standard Electron installations
        bin_patterns = []
        for pr in prog_roots:
            bin_patterns.extend([
                os.path.join(pr, "WindowsApps", "*AnthropicClaude*", "app", "Claude.exe"),
                os.path.join(pr, "WindowsApps", "*AnthropicClaude*", "Claude.exe"),
                os.path.join(pr, "WindowsApps", "Claude_*", "app", "Claude.exe"),
                os.path.join(pr, "WindowsApps", "Claude_*", "Claude.exe"),
                os.path.join(pr, "Claude", "Claude.exe"),
                os.path.join(pr, "AnthropicClaude", "Claude.exe"),
            ])
        if local_app:
            bin_patterns.extend([
                os.path.join(local_app, "AnthropicClaude", "app-*", "Claude.exe"),
                os.path.join(local_app, "AnthropicClaude", "Claude.exe"),
                os.path.join(local_app, "Programs", "Claude", "Claude.exe"),
                os.path.join(local_app, "Programs", "AnthropicClaude", "Claude.exe"),
                os.path.join(local_app, "Claude", "Claude.exe"),
                os.path.join(local_app, "Microsoft", "WindowsApps", "*AnthropicClaude*", "Claude.exe"),
                os.path.join(local_app, "Microsoft", "WindowsApps", "claude-desktop.exe"),
                os.path.join(local_app, "Microsoft", "WindowsApps", "Claude.exe"),
            ])

        if not bin_path:
            for pat in bin_patterns:
                matches = sorted(glob.glob(pat), reverse=True)
                for m in matches:
                    if _is_windows_desktop_binary(m):
                        bin_path = m
                        break
                if bin_path:
                    break

        asar_path, ion_asar_path = _find_asar_in_dir(os.path.dirname(bin_path)) if bin_path else (None, None)

        # If bin_path was an App Execution Alias (Microsoft\WindowsApps), discover actual MSIX resources
        if not asar_path:
            asar_patterns = []
            for pr in prog_roots:
                asar_patterns.extend([
                    os.path.join(pr, "WindowsApps", "*AnthropicClaude*", "app", "resources", "app.asar"),
                    os.path.join(pr, "WindowsApps", "*AnthropicClaude*", "resources", "app.asar"),
                    os.path.join(pr, "WindowsApps", "Claude_*", "app", "resources", "app.asar"),
                    os.path.join(pr, "WindowsApps", "Claude_*", "resources", "app.asar"),
                    os.path.join(pr, "Claude", "resources", "app.asar"),
                    os.path.join(pr, "AnthropicClaude", "resources", "app.asar"),
                ])
            if local_app:
                asar_patterns.extend([
                    os.path.join(local_app, "AnthropicClaude", "app-*", "resources", "app.asar"),
                    os.path.join(local_app, "Programs", "Claude", "resources", "app.asar"),
                    os.path.join(local_app, "Programs", "AnthropicClaude", "resources", "app.asar"),
                    os.path.join(local_app, "Claude", "resources", "app.asar"),
                ])
            for pat in asar_patterns:
                matches = sorted(glob.glob(pat), reverse=True)
                if matches:
                    asar_path = matches[0]
                    cand_ion = os.path.join(os.path.dirname(asar_path), "ion-dist.asar")
                    if os.path.exists(cand_ion):
                        ion_asar_path = cand_ion
                    # Prefer real MSIX/Electron binary next to resources/app.asar if available
                    cand_exe = os.path.normpath(os.path.join(os.path.dirname(asar_path), "..", "Claude.exe"))
                    if os.path.isfile(cand_exe) and (not bin_path or "microsoft\\windowsapps" in bin_path.lower()):
                        bin_path = cand_exe
                    break

        claude_roaming = os.path.join(app_data, "Claude")
        net_cookies = os.path.join(claude_roaming, "Network", "Cookies")
        cookies_path = net_cookies if os.path.exists(net_cookies) else os.path.join(claude_roaming, "Cookies")
        risk = inspect_asar_integrity_risk(bin_path, "Windows", asar_path)

        return {
            "os": "Windows",
            "official_bin": bin_path,
            "asar_path": asar_path,
            "ion_asar_path": ion_asar_path,
            "cookies_path": cookies_path,
            "sentry_dir": os.path.join(claude_roaming, "sentry"),
            "managed_settings": r"HKCU\SOFTWARE\Policies\Claude",
            "managed_dir": None,
            "managed_settings_hklm": r"HKLM\SOFTWARE\Policies\Claude",
            "managed_settings_hkcu": r"HKCU\SOFTWARE\Policies\Claude",
            "hosts_path": os.path.join(sys_root, "System32", "drivers", "etc", "hosts"),
            "ant_did_path": os.path.join(claude_roaming, "ant-did"),
            "launcher_path": os.path.join(local_app or user_prof, "Programs", "Claude", "claude-privacy.cmd"),
            "bin_link_path": None,
            "backup_dir": os.path.join(local_app or user_prof, "ClaudePatcher", "backups"),
            "is_msix": risk["is_msix"],
            "asar_integrity_enforced": risk["asar_integrity_enforced"],
            "asar_integrity_warning": risk["asar_integrity_warning"],
        }

    @staticmethod
    def _discover_darwin():
        candidates = [
            "/Applications/Claude.app/Contents/MacOS/Claude",
            os.path.expanduser("~/Applications/Claude.app/Contents/MacOS/Claude"),
        ]
        bin_path = None
        for c in candidates:
            if _is_darwin_desktop_binary(c):
                bin_path = os.path.realpath(c)
                break

        if not bin_path:
            w_desktop = shutil.which("claude-desktop")
            if _is_darwin_desktop_binary(w_desktop):
                bin_path = os.path.realpath(w_desktop)

        asar_path, ion_asar_path = _find_asar_in_dir(os.path.dirname(bin_path)) if bin_path else (None, None)

        app_support = os.path.expanduser("~/Library/Application Support/Claude")
        net_cookies = os.path.join(app_support, "Network", "Cookies")
        cookies_path = net_cookies if os.path.exists(net_cookies) else os.path.join(app_support, "Cookies")
        risk = inspect_asar_integrity_risk(bin_path, "Darwin", asar_path)

        return {
            "os": "Darwin",
            "official_bin": bin_path,
            "asar_path": asar_path,
            "ion_asar_path": ion_asar_path,
            "cookies_path": cookies_path,
            "sentry_dir": os.path.join(app_support, "sentry"),
            "managed_settings": "/Library/Managed Preferences/com.anthropic.claudefordesktop.plist",
            "managed_dir": "/Library/Managed Preferences",
            "managed_settings_hklm": None,
            "managed_settings_hkcu": None,
            "hosts_path": "/etc/hosts",
            "ant_did_path": os.path.join(app_support, "ant-did"),
            "launcher_path": "/usr/local/bin/claude-privacy",
            "bin_link_path": None,
            "backup_dir": "/var/backups/claude-patcher",
            "is_msix": risk["is_msix"],
            "asar_integrity_enforced": risk["asar_integrity_enforced"],
            "asar_integrity_warning": risk["asar_integrity_warning"],
        }

    @staticmethod
    def _discover_generic(os_type):
        return {
            "os": os_type,
            "official_bin": None,
            "asar_path": None,
            "ion_asar_path": None,
            "cookies_path": None,
            "sentry_dir": None,
            "managed_settings": None,
            "managed_dir": None,
            "managed_settings_hklm": None,
            "managed_settings_hkcu": None,
            "hosts_path": "/etc/hosts",
            "ant_did_path": None,
            "launcher_path": None,
            "bin_link_path": None,
            "backup_dir": "/tmp/claude-patcher-backup",
            "is_msix": False,
            "asar_integrity_enforced": None,
            "asar_integrity_warning": None,
        }


PATHS = DynamicPathFinder.discover()
PRISTINE_HOSTS_BAK = os.path.join(PATHS["backup_dir"], "pristine_hosts.bak")
