"""
Windows Platform Engine: Dual-Hive Registry MDM (HKLM/HKCU) and hardened Batch/CMD launcher.
"""
import os
import subprocess

from .base import BasePlatformEngine
from ..paths import PATHS
from ..constants import MANAGED_POLICIES, ANTI_LEAK_SWITCHES


class WindowsEngine(BasePlatformEngine):
    """Engine implementation for Microsoft Windows."""
    REG_PATH = r"SOFTWARE\Policies\Claude"

    def apply_mdm(self):
        hives = [r"HKLM\SOFTWARE\Policies\Claude", r"HKCU\SOFTWARE\Policies\Claude"]
        success = True
        for hive in hives:
            for p in MANAGED_POLICIES:
                cmd = f'reg add "{hive}" /v {p["key"]} /t REG_DWORD /d 1 /f'
                res = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode != 0 and hive.startswith("HKLM"):
                    # Non-admin on HKLM is expected; HKCU will succeed
                    pass
        return success

    def rollback_mdm(self):
        for hive in [r"HKLM\SOFTWARE\Policies\Claude", r"HKCU\SOFTWARE\Policies\Claude"]:
            subprocess.run(f'reg delete "{hive}" /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

    def check_mdm_status(self):
        status = {}
        for p in MANAGED_POLICIES:
            is_active = False
            for hive in ["HKLM", "HKCU"]:
                cmd = f'reg query "{hive}\\{self.REG_PATH}" /v {p["key"]}'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if res.returncode == 0 and "0x1" in res.stdout:
                    is_active = True
                    break
            status[p["key"]] = is_active
        return status

    def apply_launcher(self, tz="UTC"):
        lp = PATHS["launcher_path"]
        ob = PATHS["official_bin"] or "Claude.exe"
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        script = f"""@echo off
rem Claude Desktop Privacy & Anti-Leak Shield Launcher
rem Managed automatically by claude-patcher (clp) v1.0-beta

set TZ=%CLAUDE_TZ%
if "%TZ%"=="" set TZ={tz}
set LANG=en_US.UTF-8
set LC_ALL=en_US.UTF-8
set ELECTRON_ENABLE_LOGGING=0
set ELECTRON_DISABLE_SECURITY_WARNINGS=1

start "" "{ob}" ^
  --disable-webrtc ^
  --force-webrtc-ip-handling-policy=disable_non_proxied_udp ^
  --enforce-webrtc-ip-permission-check ^
  --dns-prefetch-disable ^
  --disable-background-networking ^
  --disable-component-update ^
  --disable-domain-reliability ^
  --no-pings ^
  --disable-client-side-phishing-detection ^
  --disable-breakpad ^
  --lang=en-US ^
  %*
"""
        with open(lp, "w") as f:
            f.write(script)
        return True

    def rollback_launcher(self):
        lp = PATHS["launcher_path"]
        if os.path.exists(lp):
            os.remove(lp)
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
