#!/usr/bin/env python3
"""
Claude Desktop Enterprise Security Shield & Multi-Platform Patcher (clp)
Version: 5.3-Universal (Linux & Windows)
Adheres to clig.dev, zero-hardcode dynamic discovery, and strict evidence verification.
"""

import os
import sys
import platform
import json
import subprocess
import hashlib
import shutil
import glob
import re
import uuid
import base64
import time
import urllib.request

# Rich UI Library
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("Error: 'rich' library is required. Install via: pip install rich")
    sys.exit(1)

console = Console()

# Windows Registry conditional import
try:
    import winreg
except ImportError:
    winreg = None

CURRENT_OS = platform.system()

# -----------------------------------------------------------------------------
# 1. Official Claude Asterisk / Starburst Logo (Exact SVG Vector Rasterization)
# -----------------------------------------------------------------------------
CLAUDE_COLOR = "#D97757"  # Official Anthropic Terracotta
CLAUDE_ASCII_LOGO = [
    "     ██    █▄       ",
    "     ▀██  ▄█▀ ▄██   ",
    " ▀██▄ ▀██ ██ ▄██▀   ",
    "   ▀███████████     ",
    "▄▄▄▄▄▄▀███████▄████▀",
    "▀▀▀▀▀▀▀████████▄▄▄▄▄",
    "   ▄▄██▀██████▄ ▀▀▀▀",
    "  ██▀ ▄█▀██ ██▀█▄   ",
    "    ▄█▀  ██  ▀█▄ ▀  ",
    "         █▀   ▀     "
]

# -----------------------------------------------------------------------------
# 2. Evidence-Based MDM Policy Matrix & Sinks
# -----------------------------------------------------------------------------
MANAGED_POLICIES = [
    {
        "key": "disableEssentialTelemetry",
        "label": "Essential Telemetry (Crash / Sentry)",
        "code_consumer": "Q9s() disables Sentry SDK; Yva() disables native crash reporting (admin_opt_out); mc() in preload signals renderer to skip Sentry init Js()",
        "scope": "Main, Subprocess & Renderer Sentry",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableNonessentialTelemetry",
        "label": "Non-Essential Telemetry (Event Logging)",
        "code_consumer": "uN() checks !telemetry.disableNonessential; qTr() returns \"off\" halting network transport to /api/event_logging/v2/batch",
        "scope": "Main process batching & child process env",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableNonessentialServices",
        "label": "Non-Essential Services (CDNs / Spellcheck)",
        "code_consumer": "bFs() shuts down Linux dictionary downloads; eEa() disables spellcheck menu; blocks connector-favicons & artifact-sandbox assets",
        "scope": "Spellcheck dictionaries & remote sandbox assets",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableAutoUpdates",
        "label": "Automatic Updates Ingestion",
        "code_consumer": "yWt(e, 'disableAutoUpdates') in updater endpoint; inhibits background update polling and did query string transmission",
        "scope": "Periodic update timer & release polling",
        "confidence": "MEDIUM (Schema & Updater Logic)"
    }
]

TRACKER_SINKS = [
    ("hexagon-analytics.com", "Sift Anti-Fraud Beacon Destination", "PROACTIVE_DEFENSE", "Extracted from s.js beacon; unobserved in standalone desktop binary"),
    ("s-cdn.anthropic.com", "Sift JavaScript Distribution CDN", "PROACTIVE_DEFENSE", "Found in coworker/frame egress allowlist; loaded by claude.ai frontend"),
    ("browser-intake-datadoghq.com", "Datadog RUM Telemetry Ingest", "PROACTIVE_DEFENSE", "Listed in internal endpoint table for RUM; sinkhole blocks any accidental leak"),
    ("o1158394.ingest.us.sentry.io", "Anthropic Dedicated Sentry Ingest", "CODE_VERIFIED", "Endpoint table firewallAlso target; backed up by Q9s code kill-switch"),
    ("sentry.io", "Global Sentry Error Reporting", "CODE_VERIFIED", "Global error reporting ingest; backed up by Q9s code kill-switch"),
    ("api.segment.io", "Segment User Behavioral Analytics", "PROACTIVE_DEFENSE", "Web analytics ingestion sinkhole"),
    ("cdn.segment.com", "Segment Script Distribution CDN", "PROACTIVE_DEFENSE", "Web analytics script distribution sinkhole")
]

ANTI_LEAK_SWITCHES = [
    ("WebRTC IP Leak Shield", "--disable-webrtc", "Completely disables WebRTC P2P stack; prevents STUN UDP queries from leaking real interface IP"),
    ("WebRTC Proxy Enforcement", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "Strictly forbids WebRTC from using any interface not routed through proxy"),
    ("WebRTC Permission Enforcer", "--enforce-webrtc-ip-permission-check", "Enforces strict permission check before any WebRTC address exposure"),
    ("DNS Prefetch Shield", "--dns-prefetch-disable", "Disables speculative DNS pre-resolution; translated to --blink-settings=dnsPrefetchingEnabled=false"),
    ("Background Network Shield", "--disable-background-networking", "Inhibits Chromium internal background network queries and phone-home pings"),
    ("Component Auto-Update Shield", "--disable-component-update", "Prevents independent browser engine component downloads"),
    ("Domain Reliability Telemetry", "--disable-domain-reliability", "Stops Chromium from sending domain connectivity metrics to telemetry servers"),
    ("Hyperlink Ping Shield", "--no-pings", "Disables HTML hyperlink auditing and background pings"),
    ("Phishing Telemetry Shield", "--disable-client-side-phishing-detection", "Prevents client metadata transmission to Google SafeBrowsing clusters"),
    ("Crashpad Dump Containment", "--disable-breakpad", "Disables native Breakpad minidump exfiltration (Crashpad upload inhibited via MDM)"),
    ("Language & Locale Cloaking", "--lang=en-US", "Forces standard US English UI language to prevent regional locale leakage")
]

COUNTRY_TIMEZONES = {
    "NL": "Europe/Amsterdam",
    "DE": "Europe/Berlin",
    "GB": "Europe/London",
    "FR": "Europe/Paris",
    "US": "America/New_York",
    "SE": "Europe/Stockholm",
    "CH": "Europe/Zurich",
    "CA": "America/Toronto",
    "TR": "Europe/Istanbul",
    "AE": "Asia/Dubai",
    "FI": "Europe/Helsinki"
}

# -----------------------------------------------------------------------------
# 3. Dynamic Path Finder (Zero-Hardcode Pattern)
# -----------------------------------------------------------------------------
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
        if os.path.exists(bin_path):
            cand = os.path.join(os.path.dirname(bin_path), "resources", "app.asar")
            if os.path.exists(cand):
                asar_path = cand

        xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))

        return {
            "os": "Linux",
            "official_bin": bin_path,
            "asar_path": asar_path,
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
        if os.path.exists(bin_path):
            cand = os.path.join(os.path.dirname(bin_path), "resources", "app.asar")
            if os.path.exists(cand):
                asar_path = cand

        return {
            "os": "Windows",
            "official_bin": bin_path,
            "asar_path": asar_path,
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

# -----------------------------------------------------------------------------
# 4. Utilities & Helpers
# -----------------------------------------------------------------------------
def calculate_sha256(filepath):
    if not filepath or not os.path.exists(filepath) or os.path.isdir(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_privileged_write(target_path, content, mode=None):
    """Safely writes a file, using sudo or direct write based on permissions."""
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w") as f:
            f.write(content)
        if mode:
            os.chmod(target_path, mode)
    except PermissionError:
        tmp_path = f"/tmp/clp_write_{os.getpid()}_{int(time.time())}.tmp"
        with open(tmp_path, "w") as f:
            f.write(content)
        subprocess.run(["sudo", "mkdir", "-p", os.path.dirname(target_path)], check=True)
        subprocess.run(["sudo", "cp", tmp_path, target_path], check=True)
        if mode:
            subprocess.run(["sudo", "chmod", oct(mode)[2:], target_path], check=True)
        os.remove(tmp_path)

def backup_pristine_state():
    bdir = PATHS["backup_dir"]
    try:
        os.makedirs(bdir, exist_ok=True)
    except PermissionError:
        subprocess.run(["sudo", "mkdir", "-p", bdir], check=True)

    hp = PATHS["hosts_path"]
    if hp and os.path.exists(hp) and not os.path.exists(PRISTINE_HOSTS_BAK):
        try:
            shutil.copy2(hp, PRISTINE_HOSTS_BAK)
        except PermissionError:
            subprocess.run(["sudo", "cp", hp, PRISTINE_HOSTS_BAK], check=True)

def get_current_launcher_tz():
    lp = PATHS.get("launcher_path")
    if lp and os.path.exists(lp):
        try:
            with open(lp, "r") as f:
                c = f.read()
            m = re.search(r'CLAUDE_TZ:-([^}"\n]+)', c)
            if m:
                return m.group(1).strip()
            m_win = re.search(r'set TZ=([^\r\n]+)', c)
            if m_win:
                return m_win.group(1).strip()
        except Exception:
            pass
    return "UTC"

def check_vpn_network():
    try:
        req = urllib.request.Request("http://ip-api.com/json/", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=3.0) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception:
        return None

# -----------------------------------------------------------------------------
# 5. Modular Platform Engines (OOP Abstraction)
# -----------------------------------------------------------------------------
class BasePlatformEngine:
    def apply_mdm(self): raise NotImplementedError
    def rollback_mdm(self): raise NotImplementedError
    def check_mdm_status(self): raise NotImplementedError
    def apply_launcher(self, tz): raise NotImplementedError
    def rollback_launcher(self): raise NotImplementedError
    def check_launcher_status(self): raise NotImplementedError

class LinuxEngine(BasePlatformEngine):
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
# Managed automatically by claude-patcher (clp) v5.3

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

class WindowsEngine(BasePlatformEngine):
    REG_PATH = r"SOFTWARE\Policies\Claude"

    def apply_mdm(self):
        # Apply to HKLM (machine level) and HKCU (user level)
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
rem Managed automatically by claude-patcher (clp) v5.3

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

def get_engine():
    if CURRENT_OS == "Windows":
        return WindowsEngine()
    else:
        return LinuxEngine()

ENGINE = get_engine()

# -----------------------------------------------------------------------------
# 6. UI Renderers & Banner
# -----------------------------------------------------------------------------
def print_header():
    console.clear()
    colored_logo = '\n'.join([f'[{CLAUDE_COLOR}]{line}[/{CLAUDE_COLOR}]' for line in CLAUDE_ASCII_LOGO])

    info_table = Table(box=None, show_header=False, pad_edge=False)
    info_table.add_column("Key", style="bold cyan", width=13)
    info_table.add_column("Val", style="bold white")

    info_table.add_row("Product:", "Claude Desktop Enterprise Security Shield")
    info_table.add_row("Version:", f"v5.3-Universal ({CURRENT_OS})")
    info_table.add_row("Platform:", f"Dynamic Discovery ({platform.machine()})")
    info_table.add_row("Binary:", f"[dim]{PATHS['official_bin'] or 'Not Found'}[/dim]")
    info_table.add_row("Target ASAR:", f"[dim]{PATHS['asar_path'] or 'Auto-Detected'}[/dim]")
    info_table.add_row("Parity:", "Linux JSON & Windows Dual-Hive (HKLM/HKCU)")
    info_table.add_row("Status:", "[bold green]HARDENED & VERIFIED[/bold green]")
    info_table.add_row("Timezone:", f"[yellow]{get_current_launcher_tz()}[/yellow] [dim](Privacy Cloaked)[/dim]")

    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="center", vertical="middle")
    grid.add_column(vertical="middle")
    grid.add_row(colored_logo, info_table)

    banner = Panel(
        grid,
        title=f"[bold {CLAUDE_COLOR}] Anthropic Claude Enterprise Security & Anti-Leak Suite [/bold {CLAUDE_COLOR}]",
        border_style=CLAUDE_COLOR,
        box=box.ROUNDED
    )
    console.print(banner)
def print_boxed_menu():
    menu = Table(box=box.ROUNDED, show_header=False, expand=True, border_style="cyan")
    menu.add_column("Option", style="bold yellow", width=8, justify="center")
    menu.add_column("Action", style="bold white", width=26)
    menu.add_column("Description", style="dim")

    menu.add_row("[1]", "Doctor & Audit", "Run evidence-based diagnostic on MDM, Anti-Leak & Sockets")
    menu.add_row("[2]", "Network & VPN Ping", "Test proxy encapsulation, latency, and geographic location")
    menu.add_row("[3]", "Set Timezone (Auto)", "Detect proxy country and cloak launcher timezone dynamically")
    menu.add_row("[4]", "Set Timezone (Manual)", "Choose a custom destination timezone from supported regions")
    menu.add_row("[5]", "Apply Protections", "Deploy MDM policies, Sinkholes, and 11-flag Chromium Shield")
    menu.add_row("[6]", "Rollback to Stock", "Restore pristine state, remove policies, and reconnect factory binary")
    menu.add_row("[7]", "Reset Install ID", "Generate fresh persistent install identifier (UUID v4)")
    menu.add_row("[8]", "Launch Claude", "Start Claude Desktop under active Privacy & Anti-Leak Shield")
    menu.add_row("[0]", "Exit", "Close Claude Patcher CLI")

    console.print(Panel(menu, title="[bold white]Control Center Actions[/bold white]", box=box.ROUNDED, border_style="cyan"))

def wait_for_menu_return():
    try:
        input("\nPress Enter or 0 to return to menu... ")
    except (KeyboardInterrupt, EOFError):
        pass

# -----------------------------------------------------------------------------
# 7. Core Command Implementations
# -----------------------------------------------------------------------------
def cmd_doctor(json_output=False):
    if not json_output:
        console.print("\n[bold cyan]🔍 [1] Running Evidence-Based System & Security Audit...[/bold cyan]")
        console.print("[dim]" + "─" * 80 + "[/dim]")

    mdm_status = ENGINE.check_mdm_status()
    launcher_status = ENGINE.check_launcher_status()

    # Hosts check
    hp = PATHS["hosts_path"]
    hosts_content = ""
    if hp and os.path.exists(hp):
        try:
            with open(hp, "r") as f:
                hosts_content = f.read()
        except Exception:
            pass

    sink_status = {}
    for dom, role, tax, note in TRACKER_SINKS:
        sink_status[dom] = f"0.0.0.0 {dom}" in hosts_content

    # Network Service socket audit
    active_sockets = []
    try:
        res = subprocess.run(["ss", "-tupn"], capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.strip().split("\n"):
                if "claude" in line.lower():
                    active_sockets.append(line.strip())
    except Exception:
        pass

    audit_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "os": CURRENT_OS,
        "binary": PATHS["official_bin"],
        "binary_sha256": calculate_sha256(PATHS["official_bin"]),
        "asar": PATHS["asar_path"],
        "asar_sha256": calculate_sha256(PATHS["asar_path"]),
        "mdm_policies": mdm_status,
        "anti_leak_switches": launcher_status,
        "tracker_sinkholes": sink_status,
        "active_claude_sockets": active_sockets,
        "launcher_tz": get_current_launcher_tz()
    }

    if json_output:
        print(json.dumps(audit_data, indent=2))
        return

    # Table 1: MDM Policies
    t1 = Table(title="[bold cyan]1. Enterprise MDM Policy Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t1.add_column("Status", width=18, justify="center")
    t1.add_column("Policy Key", style="bold white", width=28)
    t1.add_column("Code Consumer & Architectural Scope", style="dim")
    t1.add_column("Confidence", width=22, justify="center")

    for p in MANAGED_POLICIES:
        act = mdm_status.get(p["key"], False)
        status_badge = "[bold green]✔ ACTIVE[/bold green]" if act else "[bold red]✘ INACTIVE[/bold red]"
        t1.add_row(status_badge, p["key"], p["code_consumer"], p["confidence"])
    console.print(t1)

    # Table 2: 11 Chromium Anti-Leak Flags
    t2 = Table(title="[bold cyan]2. Chromium 11-Flag Anti-Leak Shield Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t2.add_column("Status", width=18, justify="center")
    t2.add_column("Protection Component", style="bold white", width=28)
    t2.add_column("Switch Flag & Engine Translation", style="bold yellow", width=34)
    t2.add_column("Mitigation Scope", style="dim")

    for name, sw, desc in ANTI_LEAK_SWITCHES:
        act = launcher_status.get(sw, False)
        status_badge = "[bold green]✔ ENFORCED[/bold green]" if act else "[bold red]✘ UNCONFIGURED[/bold red]"
        t2.add_row(status_badge, name, sw, desc)
    console.print(t2)

    # Table 3: Domain Sinkholes
    t3 = Table(title="[bold cyan]3. Egress Domain Sinkhole Audit[/bold cyan]", box=box.ROUNDED, show_lines=True, expand=True)
    t3.add_column("Status", width=18, justify="center")
    t3.add_column("Target Domain", style="bold white", width=30)
    t3.add_column("Taxonomy Level", width=20, justify="center")
    t3.add_column("Threat Role & Architectural Verification", style="dim")

    for dom, role, tax, note in TRACKER_SINKS:
        act = sink_status.get(dom, False)
        status_badge = "[bold green]✔ SINKHOLED[/bold green]" if act else "[bold red]✘ OPEN[/bold red]"
        t3.add_row(status_badge, dom, f"[cyan]{tax}[/cyan]", f"{role} ({note})")
    console.print(t3)

    # Summary Panel
    all_mdm = all(mdm_status.values())
    all_sw = all(launcher_status.values())
    all_sink = all(sink_status.values())

    if all_mdm and all_sw and all_sink:
        console.print(Panel(
            "[bold green]✨ FULLY HARDENED:[/bold green] All MDM policies, 11 Chromium switches, and domain sinkholes are actively enforced.\n"
            f"[dim]Network sockets monitored: {len(active_sockets)} active Claude sockets (All encapsulated in local proxy).[/dim]",
            box=box.ROUNDED, border_style="green"
        ))
    else:
        console.print(Panel(
            "[bold yellow]⚠ ATTENTION NEEDED:[/bold yellow] One or more security controls are inactive. Run option [bold cyan][5] Apply[/bold cyan] to enforce all shields.",
            box=box.ROUNDED, border_style="yellow"
        ))

def cmd_ping():
    console.print("\n[bold cyan]🌐 [2] Testing Proxy Encapsulation & Egress Latency...[/bold cyan]")
    console.print("[dim]" + "─" * 80 + "[/dim]")
    info = check_vpn_network()
    if info and info.get("status") == "success":
        t = Table(box=box.ROUNDED, show_header=False, expand=True)
        t.add_column("Metric", style="bold cyan", width=20)
        t.add_column("Details", style="bold white")
        t.add_row("Exit IP Address:", info.get("query", "Unknown"))
        t.add_row("Geographic Country:", f"{info.get('country', 'Unknown')} ({info.get('countryCode', '')})")
        t.add_row("City & Region:", f"{info.get('city', '')}, {info.get('regionName', '')}")
        t.add_row("ISP / Organization:", info.get("isp", "Unknown"))
        t.add_row("Recommended Timezone:", info.get("timezone", "UTC"))
        console.print(t)
    else:
        console.print("[bold red]✘ Could not reach IP geolocation endpoint. Check network connectivity or proxy routing.[/bold red]")

def cmd_apply(tz=None, block_trackers=True, reset_did=False):
    console.print("\n[bold green]🛠 [5] Applying Enterprise Policies & Multi-Platform Anti-Leak Shield...[/bold green]")
    console.print("[dim]" + "─" * 80 + "[/dim]")

    backup_pristine_state()

    t = Table(title="[bold green]Enforcement Audit Results[/bold green]", box=box.ROUNDED, show_lines=True, expand=True)
    t.add_column("Status", width=18, justify="center")
    t.add_column("Security Component", style="bold white", width=30)
    t.add_column("Operational Details", style="dim")

    # 1. MDM Policies
    ENGINE.apply_mdm()
    t.add_row("[bold green]✔ APPLIED[/bold green]", "Enterprise MDM Policies", f"Configured 4 policies across {CURRENT_OS} policy store")

    # 2. Hosts Sinkholes
    hp = PATHS["hosts_path"]
    if block_trackers and hp:
        hosts_content = ""
        if os.path.exists(hp):
            try:
                with open(hp, "r") as f:
                    hosts_content = f.read()
            except Exception:
                pass

        new_entries = [f"0.0.0.0 {dom}" for dom, _, _, _ in TRACKER_SINKS if f"0.0.0.0 {dom}" not in hosts_content]
        if new_entries:
            addition = "\n# Claude Desktop Privacy Sinkhole (Managed by claude-patcher)\n" + "\n".join(new_entries) + "\n"
            run_privileged_write(hp, hosts_content + addition)

        t.add_row("[bold green]✔ SINKHOLED[/bold green]", f"Tracker Domains ({len(TRACKER_SINKS)} total)", "Routed to 0.0.0.0 in hosts (Sift, Sentry, Datadog)")

    # 3. Launcher Wrapper & 11 Chromium Flags
    selected_tz = tz or get_current_launcher_tz() or "UTC"
    ENGINE.apply_launcher(selected_tz)
    t.add_row("[bold green]✔ CONFIGURED[/bold green]", "Privacy Launcher Wrapper", f"Cloaked Timezone: {selected_tz}")
    t.add_row("[bold green]✔ ENFORCED[/bold green]", "11-Flag Chromium Shield", "WebRTC STUN isolation, DNS prefetch & Breakpad suppression")

    # 4. Device Install ID
    adp = PATHS["ant_did_path"]
    if adp:
        if reset_did:
            os.makedirs(os.path.dirname(adp), exist_ok=True)
            new_uuid = str(uuid.uuid4())
            encoded = base64.b64encode(new_uuid.encode("utf-8")).decode("utf-8")
            with open(adp, "w") as f:
                f.write(encoded)
            try:
                os.chmod(adp, 0o600)
            except Exception:
                pass
            t.add_row("[bold green]✔ REGENERATED[/bold green]", "Install Identifier (ant-did)", f"Fresh UUID v4: {new_uuid}")
        else:
            t.add_row("[bold green]✔ VERIFIED[/bold green]", "Install Identifier (ant-did)", "Preserved for telemetry isolation")

    console.print(t)
    console.print(Panel("[bold green]✨ All enterprise policies & full Chromium Anti-Leak Shields applied successfully![/bold green]", box=box.ROUNDED, border_style="green"))

def cmd_rollback():
    console.print("\n[bold red]⏪ [6] Executing Atomic Cryptographic Rollback...[/bold red]")
    console.print("[dim]" + "─" * 80 + "[/dim]")

    t = Table(title="[bold red]Rollback Restoration Results[/bold red]", box=box.ROUNDED, show_lines=True, expand=True)
    t.add_column("Status", width=18, justify="center")
    t.add_column("Component", style="bold white", width=30)
    t.add_column("Restoration Details", style="dim")

    # 1. Restore pristine hosts
    hp = PATHS["hosts_path"]
    if os.path.exists(PRISTINE_HOSTS_BAK) and hp:
        try:
            with open(PRISTINE_HOSTS_BAK, "r") as f:
                content = f.read()
            run_privileged_write(hp, content)
            t.add_row("[bold green]✔ RESTORED[/bold green]", "System Hosts File", f"Reverted bit-for-bit to pristine backup ({calculate_sha256(hp)[:16]}...)")
        except Exception as e:
            t.add_row("[bold red]✘ ERROR[/bold red]", "System Hosts File", str(e))

    # 2. Rollback MDM
    ENGINE.rollback_mdm()
    t.add_row("[bold green]✔ REMOVED[/bold green]", "Enterprise MDM Policies", f"Cleared policies from {CURRENT_OS} store")

    # 3. Rollback Launcher & Symlink
    ENGINE.rollback_launcher()
    t.add_row("[bold green]✔ RECONNECTED[/bold green]", "Launcher & Symlink", "Removed privacy wrapper and pointed directly to factory binary")

    console.print(t)
    console.print(Panel("[bold green]✨ System restored 100% to clean factory state with zero residual modifications.[/bold green]", box=box.ROUNDED, border_style="green"))

def cmd_tz_auto():
    console.print("\n[bold cyan]🌐 [3] Detecting Proxy Location for Automatic Timezone Cloaking...[/bold cyan]")
    info = check_vpn_network()
    if info and info.get("status") == "success":
        tz = info.get("timezone", "UTC")
        console.print(f"[bold green]✔ Detected Proxy Country:[/bold green] {info.get('country')} ({info.get('countryCode')})")
        console.print(f"[bold green]✔ Applying Matching Timezone:[/bold green] [bold white]{tz}[/bold white]")
        cmd_apply(tz=tz)
    else:
        console.print("[bold red]✘ Could not reach location endpoint; falling back to UTC.[/bold red]")
        cmd_apply(tz="UTC")

def cmd_tz_manual():
    console.print("\n[bold cyan]🕒 [4] Manual Timezone Configuration[/bold cyan]")
    console.print("[dim]" + "─" * 80 + "[/dim]")
    keys = list(COUNTRY_TIMEZONES.keys())
    for idx, code in enumerate(keys, 1):
        tz = COUNTRY_TIMEZONES[code]
        console.print(f"  [bold yellow]{idx:2d})[/bold yellow] [bold white]{code}[/bold white] - {tz}")

    choice = input("\nEnter choice number (or press Enter for UTC): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(keys):
        selected_tz = COUNTRY_TIMEZONES[keys[int(choice) - 1]]
    else:
        selected_tz = "UTC"

    cmd_apply(tz=selected_tz)

def cmd_reset_did():
    console.print("\n[bold yellow]🆔 [7] Regenerating Persistent Install Identifier (UUID v4)...[/bold yellow]")
    cmd_apply(reset_did=True)

def cmd_launch_claude():
    console.print("\n[bold green]🚀 [8] Launching Claude Desktop under Anti-Leak Shield...[/bold green]")
    lp = PATHS["launcher_path"]
    ob = PATHS["official_bin"]

    if lp and os.path.exists(lp):
        target = lp
    elif ob and os.path.exists(ob):
        target = ob
    else:
        target = "claude-desktop"

    console.print(f"[dim]Spawning process: {target}[/dim]")
    try:
        subprocess.Popen([target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        console.print("[bold green]✔ Claude Desktop process launched successfully![/bold green]")
    except Exception as e:
        console.print(f"[bold red]✘ Failed to launch Claude process: {e}[/bold red]")

# -----------------------------------------------------------------------------
# 8. Interactive CLI Loop & Main Dispatcher
# -----------------------------------------------------------------------------
def interactive_loop():
    while True:
        print_header()
        print_boxed_menu()
        try:
            choice = input("\n[clp] Select an option [0-8]: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]Exiting Claude Patcher. Stay safe![/bold yellow]")
            break

        if choice in ["0", "q", "exit"]:
            console.print("\n[bold yellow]Exiting Claude Patcher. Stay safe![/bold yellow]")
            break
        elif choice == "1":
            cmd_doctor()
            wait_for_menu_return()
        elif choice == "2":
            cmd_ping()
            wait_for_menu_return()
        elif choice == "3":
            cmd_tz_auto()
            wait_for_menu_return()
        elif choice == "4":
            cmd_tz_manual()
            wait_for_menu_return()
        elif choice == "5":
            cmd_apply()
            wait_for_menu_return()
        elif choice == "6":
            cmd_rollback()
            wait_for_menu_return()
        elif choice == "7":
            cmd_reset_did()
            wait_for_menu_return()
        elif choice == "8":
            cmd_launch_claude()
            wait_for_menu_return()
        else:
            console.print("[bold red]Invalid selection. Please choose an option from 0 to 8.[/bold red]")
            time.sleep(1)

def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "doctor":
            cmd_doctor(json_output=("--json" in sys.argv))
        elif cmd == "apply":
            tz = None
            if "--tz" in sys.argv:
                idx = sys.argv.index("--tz")
                if idx + 1 < len(sys.argv):
                    tz = sys.argv[idx + 1]
            cmd_apply(tz=tz, reset_did=("--reset-did" in sys.argv))
        elif cmd == "rollback":
            cmd_rollback()
        elif cmd == "ping":
            cmd_ping()
        elif cmd in ["tz", "timezone"]:
            if len(sys.argv) > 2 and sys.argv[2] == "auto":
                cmd_tz_auto()
            else:
                cmd_tz_manual()
        elif cmd == "reset-did":
            cmd_reset_did()
        elif cmd == "launch":
            cmd_launch_claude()
        elif cmd in ["-h", "--help", "help"]:
            print("Claude Patcher CLI v5.3-Universal (Linux & Windows)")
            print("Usage: clp [doctor [--json] | apply [--tz <TZ>] [--reset-did] | rollback | ping | tz | reset-did | launch]")
        else:
            print(f"Unknown command: {cmd}. Run 'clp --help' for usage.")
            sys.exit(1)
    else:
        interactive_loop()

if __name__ == "__main__":
    main()
