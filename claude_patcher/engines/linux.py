"""
Linux Platform Engine: Managed JSON policies and hardened Bash launcher.
"""
import os
import json
import subprocess

from .base import BasePlatformEngine
from ..paths import PATHS
from ..constants import MANAGED_POLICIES, ANTI_LEAK_SWITCHES
from ..system import run_privileged_write


class LinuxEngine(BasePlatformEngine):
    """Engine implementation for Linux operating systems."""

    def apply_mdm(self):
        msp = PATHS["managed_settings"]
        md = PATHS["managed_dir"]
        os.makedirs(md, exist_ok=True)
        settings = {p["key"]: True for p in MANAGED_POLICIES}
        run_privileged_write(msp, json.dumps(settings, indent=2) + "\n")
        subprocess.run(["sudo", "chown", "root:root", msp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "chmod", "644", msp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "chown", "root:root", md], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "chmod", "755", md], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

    def rollback_mdm(self):
        msp = PATHS["managed_settings"]
        if os.path.exists(msp):
            subprocess.run(["sudo", "rm", "-f", msp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

    def check_mdm_status(self):
        msp = PATHS["managed_settings"]
        if not os.path.exists(msp):
            return {p["key"]: False for p in MANAGED_POLICIES}
        try:
            with open(msp, "r") as f:
                data = json.load(f)
            return {p["key"]: (data.get(p["key"]) is True) for p in MANAGED_POLICIES}
        except Exception:
            return {p["key"]: False for p in MANAGED_POLICIES}

    def apply_launcher(self, tz="UTC"):
        lp = PATHS["launcher_path"]
        ob = PATHS["official_bin"] or "/usr/lib/claude-desktop/claude-desktop"
        script = f"""#!/bin/bash
# Claude Desktop Privacy & Anti-Leak Shield Launcher
# Managed automatically by claude-patcher (clp) v1.0-beta

export TZ="${{CLAUDE_TZ:-{tz}}}"
export LANG="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"

# Block Electron telemetry / logging switches
export ELECTRON_ENABLE_LOGGING=0
export ELECTRON_DISABLE_SECURITY_WARNINGS=1

# Execute official binary with comprehensive Chromium Anti-Leak Shield
exec {ob} \\
  --disable-webrtc \\
  --force-webrtc-ip-handling-policy=disable_non_proxied_udp \\
  --enforce-webrtc-ip-permission-check \\
  --dns-prefetch-disable \\
  --disable-background-networking \\
  --disable-component-update \\
  --disable-domain-reliability \\
  --no-pings \\
  --disable-client-side-phishing-detection \\
  --disable-breakpad \\
  --lang=en-US \\
  "$@"
"""
        run_privileged_write(lp, script, mode=0o755)

        blp = PATHS["bin_link_path"]
        if blp:
            subprocess.run(["sudo", "-n", "ln", "-sf", lp, blp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

    def rollback_launcher(self):
        lp = PATHS["launcher_path"]
        if os.path.exists(lp):
            subprocess.run(["sudo", "rm", "-f", lp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        blp = PATHS["bin_link_path"]
        ob = PATHS["official_bin"]
        if blp and ob and os.path.exists(ob):
            subprocess.run(["sudo", "-n", "ln", "-sf", ob, blp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

    def check_launcher_status(self):
        lp = PATHS["launcher_path"]
        if not os.path.exists(lp):
            return {sw[1]: False for sw in ANTI_LEAK_SWITCHES}
        try:
            with open(lp, "r") as f:
                c = f.read()
            return {sw[1]: (sw[1] in c) for sw in ANTI_LEAK_SWITCHES}
        except Exception:
            return {sw[1]: False for sw in ANTI_LEAK_SWITCHES}
