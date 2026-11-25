"""
Windows Platform Engine: Dual-Hive Registry MDM (HKLM/HKCU), POSIX CRT TZ conversion,
Chromium Preferences hardening, and honest Batch/CMD launcher + shortcut (.lnk) wiring.
"""
import datetime
import glob
import json
import os
import re
import subprocess
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .base import BasePlatformEngine
from ..paths import PATHS
from ..constants import CURRENT_OS, MANAGED_POLICIES, ANTI_LEAK_SWITCHES
from ..sanitizer import harden_chromium_preferences

# Windows MSVC CRT (_tzset) requires POSIX TZ strings (e.g. "UTC0", "EST5EDT,M3.2.0,M11.1.0"),
# NOT Linux IANA names like "Europe/Amsterdam".
IANA_TO_POSIX_TZ = {
    "UTC": "UTC0",
    "Etc/UTC": "UTC0",
    "Etc/GMT": "GMT0",
    "GMT": "GMT0",
    "Europe/Amsterdam": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Berlin": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Paris": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Stockholm": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Zurich": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Vienna": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Warsaw": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/London": "GMT0BST,M3.5.0/1,M10.5.0",
    "Europe/Dublin": "IST-1GMT0,M10.5.0,M3.5.0/1",
    "Europe/Helsinki": "EET-2EEST,M3.5.0/3,M10.5.0/4",
    "Europe/Athens": "EET-2EEST,M3.5.0/3,M10.5.0/4",
    "Europe/Istanbul": "TRT-3",
    "Asia/Dubai": "GST-4",
    "Asia/Tokyo": "JST-9",
    "Asia/Seoul": "KST-9",
    "Asia/Singapore": "SGT-8",
    "Asia/Shanghai": "CST-8",
    "Asia/Kolkata": "IST-5:30",
    "America/New_York": "EST5EDT,M3.2.0,M11.1.0",
    "America/Toronto": "EST5EDT,M3.2.0,M11.1.0",
    "America/Chicago": "CST6CDT,M3.2.0,M11.1.0",
    "America/Denver": "MST7MDT,M3.2.0,M11.1.0",
    "America/Los_Angeles": "PST8PDT,M3.2.0,M11.1.0",
    "America/Phoenix": "MST7",
    "Australia/Sydney": "AEST-10AEDT,M10.1.0,M4.1.0/3",
}

_POSIX_TZ_RE = re.compile(r"^[A-Za-z]{2,}[+-]?\d{1,2}(:\d{2}(:\d{2})?)?([A-Za-z]{2,}.*)?$")


def _format_posix_offset(seconds: int) -> str:
    """Formats a UTC offset in seconds using POSIX TZ sign convention (west positive, east negative)."""
    posix_sec = -seconds
    sign = "-" if posix_sec < 0 else ""
    abs_sec = abs(posix_sec)
    hours, rem = divmod(abs_sec, 3600)
    minutes = (rem % 3600) // 60
    if minutes:
        return f"{sign}{hours}:{minutes:02d}"
    return f"{sign}{hours}"


def iana_to_windows_posix_tz(tz: str) -> str:
    """
    Converts an IANA timezone name (e.g. 'Europe/Amsterdam') to a Windows CRT POSIX TZ
    string (e.g. 'CET-1CEST,M3.5.0,M10.5.0/3' or 'UTC0').
    """
    if not tz or not tz.strip():
        return "UTC0"
    cleaned = tz.strip()
    if cleaned in IANA_TO_POSIX_TZ:
        return IANA_TO_POSIX_TZ[cleaned]
    if _POSIX_TZ_RE.match(cleaned):
        return cleaned

    try:
        zi = ZoneInfo(cleaned)
    except ZoneInfoNotFoundError:
        return "UTC0"

    jan = datetime.datetime(2026, 1, 15, 12, 0, tzinfo=zi)
    jul = datetime.datetime(2026, 7, 15, 12, 0, tzinfo=zi)
    jan_off = int(jan.utcoffset().total_seconds())
    jul_off = int(jul.utcoffset().total_seconds())

    if jan_off == jul_off:
        abbr = re.sub(r"[^A-Za-z]", "", jan.tzname() or "") or "STD"
        if len(abbr) < 3:
            abbr = "STD"
        return f"{abbr}{_format_posix_offset(jan_off)}"

    std_dt, dst_dt = (jan, jul) if jan_off < jul_off else (jul, jan)
    std_off = int(std_dt.utcoffset().total_seconds())
    std_abbr = re.sub(r"[^A-Za-z]", "", std_dt.tzname() or "") or "STD"
    dst_abbr = re.sub(r"[^A-Za-z]", "", dst_dt.tzname() or "") or "DST"
    if len(std_abbr) < 3:
        std_abbr = "STD"
    if len(dst_abbr) < 3:
        dst_abbr = "DST"
    return f"{std_abbr}{_format_posix_offset(std_off)}{dst_abbr}"


class WindowsEngine(BasePlatformEngine):
    """Engine implementation for Microsoft Windows."""

    REG_PATH = r"SOFTWARE\Policies\Claude"

    def __init__(self):
        self._last_launcher_diagnostics = None

    def apply_mdm(self):
        hives = [r"HKLM\SOFTWARE\Policies\Claude", r"HKCU\SOFTWARE\Policies\Claude"]
        hkcu_ok = True
        for hive in hives:
            for p in MANAGED_POLICIES:
                res = subprocess.run(
                    ["reg", "add", hive, "/v", p["key"], "/t", "REG_DWORD", "/d", "1", "/f"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if res.returncode != 0 and hive.startswith("HKCU"):
                    hkcu_ok = False
        return hkcu_ok

    def rollback_mdm(self):
        hkcu_ok = True
        for hive in [r"HKLM\SOFTWARE\Policies\Claude", r"HKCU\SOFTWARE\Policies\Claude"]:
            res = subprocess.run(
                ["reg", "delete", hive, "/f"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if res.returncode != 0 and hive.startswith("HKCU"):
                hkcu_ok = False
        return hkcu_ok

    def check_mdm_status(self):
        status = {}
        for p in MANAGED_POLICIES:
            is_active = False
            for hive in ["HKLM", "HKCU"]:
                res = subprocess.run(
                    ["reg", "query", f"{hive}\\{self.REG_PATH}", "/v", p["key"]],
                    capture_output=True,
                    text=True,
                )
                if res.returncode == 0 and "0x1" in res.stdout:
                    is_active = True
                    break
            status[p["key"]] = is_active
        return status

    def discover_shortcuts(self):
        """Discovers Claude Desktop .lnk shortcuts across Start Menu, Desktop, and Taskbar."""
        app_data = os.environ.get("APPDATA", "")
        user_prof = os.environ.get("USERPROFILE", "")
        prog_data = os.environ.get("ProgramData", "")
        public_dir = os.environ.get("PUBLIC", "")

        patterns = []
        if app_data:
            patterns.extend([
                os.path.join(app_data, "Microsoft", "Windows", "Start Menu", "Programs", "**", "*Claude*.lnk"),
                os.path.join(app_data, "Microsoft", "Internet Explorer", "Quick Launch", "User Pinned", "TaskBar", "*Claude*.lnk"),
            ])
        if prog_data:
            patterns.append(
                os.path.join(prog_data, "Microsoft", "Windows", "Start Menu", "Programs", "**", "*Claude*.lnk")
            )
        if user_prof:
            patterns.append(os.path.join(user_prof, "Desktop", "*Claude*.lnk"))
        if public_dir:
            patterns.append(os.path.join(public_dir, "Desktop", "*Claude*.lnk"))

        found = []
        seen = set()
        for pat in patterns:
            for m in glob.glob(pat, recursive=True):
                norm = os.path.normpath(m)
                if norm not in seen:
                    seen.add(norm)
                    found.append(norm)
        return sorted(found)

    def _shortcut_backup_path(self):
        bdir = PATHS.get("backup_dir") or os.path.join(
            os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
            "ClaudePatcher",
            "backups",
        )
        return os.path.join(bdir, "windows_shortcuts.json")

    def _wire_windows_shortcuts(self, lp, ob):
        """
        Attempts to update user-writable Claude .lnk shortcuts on Windows to launch via lp
        while backing up original shortcut targets for rollback.
        """
        shortcuts = self.discover_shortcuts()
        linked = []
        if CURRENT_OS != "Windows":
            return shortcuts, linked

        backups = {}
        bpath = self._shortcut_backup_path()
        if os.path.isfile(bpath):
            try:
                with open(bpath, "r", encoding="utf-8") as f:
                    backups = json.load(f)
            except Exception:
                backups = {}

        for lnk in shortcuts:
            ps_read = (
                "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:CLP_LNK);"
                "@{TargetPath=$s.TargetPath;Arguments=$s.Arguments;IconLocation=$s.IconLocation;"
                "WorkingDirectory=$s.WorkingDirectory;WindowStyle=$s.WindowStyle}|ConvertTo-Json -Compress"
            )
            env = {**os.environ, "CLP_LNK": lnk, "CLP_LP": lp, "CLP_OB": ob}
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_read],
                capture_output=True,
                text=True,
                env=env,
            )
            if res.returncode != 0 or not res.stdout.strip():
                continue
            try:
                meta = json.loads(res.stdout.strip())
            except Exception:
                continue

            if lnk not in backups:
                backups[lnk] = meta

            icon = meta.get("IconLocation") or f"{ob},0"
            if icon.startswith(","):
                icon = f"{ob}{icon}"
            env["CLP_ICON"] = icon
            ps_write = (
                "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:CLP_LNK);"
                "$s.TargetPath=$env:CLP_LP;"
                "$s.Arguments='';"
                "$s.IconLocation=$env:CLP_ICON;"
                "$s.WindowStyle=7;"
                "$s.Save()"
            )
            wres = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_write],
                capture_output=True,
                text=True,
                env=env,
            )
            if wres.returncode == 0:
                linked.append(lnk)

        if backups:
            os.makedirs(os.path.dirname(bpath), exist_ok=True)
            with open(bpath, "w", encoding="utf-8") as f:
                json.dump(backups, f, indent=2)

        return shortcuts, linked

    def apply_launcher(self, tz="UTC", lang="en-US"):
        lp = PATHS.get("launcher_path")
        if not lp:
            raise RuntimeError("Windows launcher_path is not configured")
        ob = PATHS.get("official_bin") or "Claude.exe"
        posix_tz = iana_to_windows_posix_tz(tz)

        os.makedirs(os.path.dirname(lp), exist_ok=True)
        script = f"""@echo off
rem Claude Desktop Privacy & Anti-Leak Shield Launcher
rem Managed automatically by claude-patcher (clp) v1.0-beta
rem Target IANA TZ: {tz} -> Windows CRT POSIX TZ: {posix_tz}

set TZ={posix_tz}
if defined CLAUDE_TZ set TZ=%CLAUDE_TZ%
set LANG={lang}
set LC_ALL={lang}
set ELECTRON_ENABLE_LOGGING=0
set ELECTRON_DISABLE_SECURITY_WARNINGS=1

start "" "{ob}" ^
  --disable-quic ^
  --lang={lang} ^
  --disable-logging ^
  %*
"""
        with open(lp, "w", encoding="utf-8") as f:
            f.write(script)

        harden_chromium_preferences()
        shortcuts, linked = self._wire_windows_shortcuts(lp, ob)
        warning = None
        if not linked:
            warning = (
                f"Wrapper written to {lp} (TZ={posix_tz}), but no Windows .lnk shortcut was wired "
                f"(found {len(shortcuts)} shortcut(s)). Launching Claude from Start Menu/Taskbar "
                "or MSIX App Execution Alias will bypass wrapper flags unless launched via 'clp launch'."
            )

        self._last_launcher_diagnostics = {
            "wrapper_exists": True,
            "wrapper_path": lp,
            "linked": bool(linked),
            "shortcuts_found": shortcuts,
            "shortcuts_linked": linked,
            "iana_tz": tz,
            "posix_tz": posix_tz,
            "unlinked_warning": warning,
        }
        return self._last_launcher_diagnostics

    def rollback_launcher(self):
        if CURRENT_OS == "Windows":
            bpath = self._shortcut_backup_path()
            if os.path.isfile(bpath):
                try:
                    with open(bpath, "r", encoding="utf-8") as f:
                        backups = json.load(f)
                    for lnk, meta in backups.items():
                        if not os.path.exists(lnk):
                            continue
                        env = {
                            **os.environ,
                            "CLP_LNK": lnk,
                            "CLP_TARGET": meta.get("TargetPath", ""),
                            "CLP_ARGS": meta.get("Arguments", ""),
                            "CLP_ICON": meta.get("IconLocation", ""),
                            "CLP_WD": meta.get("WorkingDirectory", ""),
                            "CLP_WS": str(meta.get("WindowStyle", 1)),
                        }
                        ps_restore = (
                            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:CLP_LNK);"
                            "$s.TargetPath=$env:CLP_TARGET;"
                            "$s.Arguments=$env:CLP_ARGS;"
                            "$s.IconLocation=$env:CLP_ICON;"
                            "$s.WorkingDirectory=$env:CLP_WD;"
                            "$s.WindowStyle=[int]$env:CLP_WS;"
                            "$s.Save()"
                        )
                        subprocess.run(
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_restore],
                            capture_output=True,
                            env=env,
                        )
                    os.remove(bpath)
                except Exception:
                    pass

        lp = PATHS.get("launcher_path")
        if lp and os.path.exists(lp):
            os.remove(lp)
        self._last_launcher_diagnostics = None
        return True

    def check_launcher_status(self):
        lp = PATHS.get("launcher_path")
        if not lp or not os.path.exists(lp):
            return {sw[1]: False for sw in ANTI_LEAK_SWITCHES}
        try:
            with open(lp, "r", encoding="utf-8") as f:
                c = f.read()
            status = {}
            for _, sw, _ in ANTI_LEAK_SWITCHES:
                if sw.startswith("--lang="):
                    status[sw] = ("--lang=" in c)
                else:
                    status[sw] = (sw in c)
            return status
        except Exception:
            return {sw[1]: False for sw in ANTI_LEAK_SWITCHES}

    def get_launcher_diagnostics(self):
        if self._last_launcher_diagnostics is not None:
            return self._last_launcher_diagnostics
        lp = PATHS.get("launcher_path")
        wrapper_exists = bool(lp and os.path.exists(lp))
        shortcuts = self.discover_shortcuts()
        warning = None
        if wrapper_exists:
            warning = (
                f"Wrapper exists at {lp}; verify Windows .lnk shortcuts point to it or launch via 'clp launch'."
            )
        return {
            "wrapper_exists": wrapper_exists,
            "wrapper_path": lp,
            "linked": False,
            "shortcuts_found": shortcuts,
            "shortcuts_linked": [],
            "unlinked_warning": warning,
        }
