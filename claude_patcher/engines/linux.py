"""
Linux Platform Engine: Managed JSON policies, Chromium Preferences hardening,
and verified-flag Bash launcher.
"""
import os
import json
import subprocess

from .base import BasePlatformEngine
from ..paths import PATHS
from ..constants import MANAGED_POLICIES, ANTI_LEAK_SWITCHES
from ..sanitizer import harden_chromium_preferences
from ..system import run_privileged_write

LOCAL_BIN_CLAUDE = "/usr/local/bin/claude-desktop"


def _privileged_symlink(target, link_path):
    """Creates or updates a symlink at link_path -> target, elevating via sudo on PermissionError."""
    if os.path.islink(link_path) and os.readlink(link_path) == target:
        return
    link_dir = os.path.dirname(link_path) or "."
    try:
        os.makedirs(link_dir, exist_ok=True)
        tmp_link = f"{link_path}.clp_tmp_{os.getpid()}"
        if os.path.lexists(tmp_link):
            os.unlink(tmp_link)
        os.symlink(target, tmp_link)
        os.replace(tmp_link, link_path)
    except PermissionError:
        subprocess.run(["sudo", "mkdir", "-p", link_dir], check=True)
        subprocess.run(["sudo", "ln", "-sf", target, link_path], check=True)


def _privileged_remove(target_path):
    """Removes a file if present, elevating via sudo on PermissionError."""
    if not os.path.lexists(target_path):
        return
    try:
        os.remove(target_path)
    except PermissionError:
        subprocess.run(["sudo", "rm", "-f", target_path], check=True)


def _lang_to_posix_locale(lang: str) -> str:
    if not lang or "-" not in lang:
        return "en_US.UTF-8"
    parts = lang.split("-", 1)
    return f"{parts[0].lower()}_{parts[1].upper()}.UTF-8"


class LinuxEngine(BasePlatformEngine):
    """Engine implementation for Linux operating systems."""

    def apply_mdm(self):
        msp = PATHS.get("managed_settings")
        md = PATHS.get("managed_dir")
        if not msp or not md:
            raise RuntimeError("Linux managed_settings path is not configured")

        settings = {p["key"]: True for p in MANAGED_POLICIES}
        run_privileged_write(msp, json.dumps(settings, indent=2) + "\n", mode=0o644)

        try:
            os.chmod(md, 0o755)
        except PermissionError:
            subprocess.run(["sudo", "chmod", "755", md], check=True)

        if md.startswith("/etc") and os.geteuid() != 0:
            if os.stat(md).st_uid != 0:
                subprocess.run(["sudo", "chown", "root:root", md], check=True)
            if os.stat(msp).st_uid != 0:
                subprocess.run(["sudo", "chown", "root:root", msp], check=True)
        return True

    def rollback_mdm(self):
        msp = PATHS.get("managed_settings")
        if msp:
            _privileged_remove(msp)
        return True

    def check_mdm_status(self):
        msp = PATHS.get("managed_settings")
        if not msp or not os.path.exists(msp):
            return {p["key"]: False for p in MANAGED_POLICIES}
        try:
            with open(msp, "r") as f:
                data = json.load(f)
            return {p["key"]: (data.get(p["key"]) is True) for p in MANAGED_POLICIES}
        except Exception:
            return {p["key"]: False for p in MANAGED_POLICIES}

    def apply_launcher(self, tz="UTC", lang="en-US"):
        lp = PATHS.get("launcher_path")
        if not lp:
            raise RuntimeError("Linux launcher_path is not configured")
        ob = PATHS.get("official_bin") or "/usr/lib/claude-desktop/claude-desktop"
        posix_locale = _lang_to_posix_locale(lang)
        script = f"""#!/bin/bash
# Claude Desktop Privacy & Anti-Leak Shield Launcher
# Managed automatically by claude-patcher (clp) v1.0-beta

export TZ="${{CLAUDE_TZ:-{tz}}}"
export LANG="{posix_locale}"
export LC_ALL="{posix_locale}"

# Block Electron telemetry / logging switches
export ELECTRON_ENABLE_LOGGING=0
export ELECTRON_DISABLE_SECURITY_WARNINGS=1

# Execute official binary with ELF-verified Chromium Anti-Leak Switches
exec {ob} \\
  --disable-quic \\
  --lang={lang} \\
  --disable-logging \\
  "$@"
"""
        run_privileged_write(lp, script, mode=0o755)

        blp = PATHS.get("bin_link_path")
        if blp:
            _privileged_symlink(lp, blp)
            # Also link /usr/local/bin/claude-desktop so GUI .desktop Exec=claude-desktop %U hits wrapper
            if blp == "/usr/bin/claude-desktop":
                _privileged_symlink(lp, LOCAL_BIN_CLAUDE)

        harden_chromium_preferences()
        return True

    def rollback_launcher(self):
        lp = PATHS.get("launcher_path")
        if lp and os.path.islink(LOCAL_BIN_CLAUDE) and os.readlink(LOCAL_BIN_CLAUDE) == lp:
            _privileged_remove(LOCAL_BIN_CLAUDE)
        if lp:
            _privileged_remove(lp)
        blp = PATHS.get("bin_link_path")
        ob = PATHS.get("official_bin")
        if blp and ob and os.path.exists(ob):
            _privileged_symlink(ob, blp)
        return True

    def check_launcher_status(self):
        lp = PATHS.get("launcher_path")
        if not lp or not os.path.exists(lp):
            return {sw[1]: False for sw in ANTI_LEAK_SWITCHES}
        try:
            with open(lp, "r") as f:
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
        lp = PATHS.get("launcher_path")
        blp = PATHS.get("bin_link_path")
        wrapper_exists = bool(lp and os.path.exists(lp))
        linked = False
        warning = None
        if wrapper_exists and blp:
            blp_ok = os.path.lexists(blp) and os.path.realpath(blp) == os.path.realpath(lp)
            local_ok = os.path.lexists(LOCAL_BIN_CLAUDE) and os.path.realpath(LOCAL_BIN_CLAUDE) == os.path.realpath(lp)
            if blp_ok or local_ok:
                linked = True
            else:
                warning = (
                    f"Launcher wrapper exists at {lp}, but {blp} does not point to it. "
                    "Desktop launches may bypass privacy flags."
                )
        return {
            "wrapper_exists": wrapper_exists,
            "wrapper_path": lp,
            "linked": linked,
            "link_path": blp,
            "unlinked_warning": warning,
        }
