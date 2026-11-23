# Claude Patcher (`clp`)

<p align="center">
  <a href="https://github.com/dalroot/claude-patcher/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License MIT"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.9+-brightgreen.svg?style=flat-square" alt="Python 3.9+"></a>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blueviolet.svg?style=flat-square" alt="Platform Linux | Windows">
  <img src="https://img.shields.io/badge/method-Native%20MDM%20%26%20Chromium%20Flags-success.svg?style=flat-square" alt="Native MDM">
</p>

```text
     ██    █▄       
     ▀██  ▄█▀ ▄██     Anthropic Claude Desktop
 ▀██▄ ▀██ ██ ▄██▀     Privacy & Telemetry Hardening Tool
   ▀███████████       Command-Line Interface: clp
▄▄▄▄▄▄▀███████▄████▀
▀▀▀▀▀▀▀████████▄▄▄▄▄   Universal Engine (Linux & Windows)
   ▄▄██▀██████▄ ▀▀▀▀   Evidence-Based Security & Zero Binary Tampering
  ██▀ ▄█▀██ ██▀█▄   
    ▄█▀  ██  ▀█▄ ▀  
         █▀   ▀     
```

## What is Claude Patcher and What Does It Do?

`claude-patcher` (`clp`) is a lightweight configuration and launch manager for the official Claude Desktop application on Linux and Windows. 

It does **not** crack, patch, decompile, or modify official application binaries or packages. Instead, it manages three standard operating system layers:

1. **Enables Official Enterprise MDM Policies:** It writes standard enterprise configuration files (`managed-settings.json` on Linux, registry keys on Windows) provided by Anthropic. This natively instructs Claude Desktop to disable event logging batch transmission, crash reporting, and automatic update polling.
2. **Applies Chromium Engine Privacy Flags:** It launches Claude through a wrapper script with native Chromium switches (such as disabling WebRTC UDP IP leakage, disabling DNS prefetching, and disabling background networking).
3. **Sinkholes Analytics Domains Locally:** It maps known telemetry and tracking domains (such as Sentry and Sift fraud beacons) to `0.0.0.0` in the local operating system `hosts` file.
4. **Provides an Audit & Rollback Tool:** It audits your current protection status (`clp doctor`) and allows 100% clean, one-click restoration to default factory state at any time (`clp rollback`).

---

<p align="center">
  <img src="docs/assets/clp_terminal_preview.png" alt="Claude Patcher Interactive Terminal and Evidence-Based Audit" width="800">
</p>

---

## ⚡ Global Installation

You can install `claude-patcher` globally across any operating system using a single command. Once installed, the `clp` command is available immediately from any terminal window.

### 🐧 Linux & 🍏 macOS
```bash
curl -fsSL https://raw.githubusercontent.com/dalroot/claude-patcher/main/install.sh | sudo bash
```
*(Verifies Python, installs dependencies, places binary in `/usr/local/bin/claude-patcher`, and creates the global `/usr/local/bin/clp` command)*

### 🪟 Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/dalroot/claude-patcher/main/install.ps1 | iex
```
*(Installs to `%LOCALAPPDATA%\Programs\claude-patcher` and registers `clp.cmd` into PATH and WindowsApps for immediate use)*

### 🐍 Universal Python Package (pipx / pip)
```bash
# Recommended via pipx
pipx install git+https://github.com/dalroot/claude-patcher.git

# Or standard pip
pip install git+https://github.com/dalroot/claude-patcher.git
```

---

## 🚀 Usage & Commands

Run `clp` from any terminal to launch the interactive terminal interface, or pass subcommands directly:

```bash
# Launch Interactive Terminal Interface
clp

# Run Diagnostic Health Audit
clp doctor

# Machine-Readable JSON Export (for scripts and CI/CD)
clp doctor --json

# Apply All Protections (MDM Settings, Chromium Switches, Hosts Sinkhole)
sudo clp apply

# Apply with Custom Timezone Cloaking (e.g. UTC, America/New_York)
sudo clp apply --tz UTC

# Rollback All Changes (Restore pristine factory state)
sudo clp rollback

# Network & Proxy Latency Check
clp ping

# Regenerate Anonymous Installation Identifier (UUID v4)
clp reset-did

# Launch Hardened Claude Desktop Session
clp launch
```

---

## 🛠️ How It Works (Technical Breakdown)

### 1. Enterprise Policies (Native Application Settings)
Claude Desktop contains internal routines that query enterprise settings on startup (`jJt` in Linux and `AJt` / `kJt` in Windows). `clp` creates these official configuration records:

- `disableEssentialTelemetry`: Disables Sentry error reporting SDK and flags crash reporting as `admin_opt_out`.
- `disableNonessentialTelemetry`: Halts event logging flushes to `/api/event_logging/v2/batch`.
- `disableNonessentialServices`: Disables remote dictionary and asset downloads.
- `disableAutoUpdates`: Inhibits periodic update polling and device ID query strings.

### 2. Chromium Engine CLI Switches
Injected into the launcher wrapper before the Electron binary executes:

- **WebRTC IP Protection:** `--disable-webrtc`, `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, `--enforce-webrtc-ip-permission-check`
- **DNS Prefetch Disabling:** `--dns-prefetch-disable` *(automatically translated by Chromium to `--blink-settings=dnsPrefetchingEnabled=false` in Renderers)*
- **Background Networking Shutdown:** `--disable-background-networking`, `--disable-component-update`, `--disable-domain-reliability`, `--no-pings`, `--disable-client-side-phishing-detection`
- **Crash Containment & Locale Cloaking:** `--disable-breakpad`, `ELECTRON_ENABLE_LOGGING=0`, `--lang=en-US`, `LANG=en_US.UTF-8`

### 3. Operating System Hosts Sinkhole
Redirects known telemetry endpoints directly to `0.0.0.0` at the OS resolver level:
- `hexagon-analytics.com` (Sift beacon endpoint)
- `s-cdn.anthropic.com` (Sift JavaScript distribution)
- `browser-intake-datadoghq.com` (Datadog RUM ingest)
- `o1158394.ingest.us.sentry.io` & `sentry.io` (Sentry error collection)
- `api.segment.io` & `cdn.segment.com` (Segment analytics)

---

## ⚖️ Cross-Platform Parity

| Feature | Linux | Windows |
| :--- | :--- | :--- |
| **MDM Configuration** | `/etc/claude-desktop/managed-settings.json` | Registry `HKLM` & `HKCU\SOFTWARE\Policies\Claude` |
| **Non-Admin Support** | Supported | **Supported** (via `HKCU` user hive) |
| **Hosts Sinkhole** | `/etc/hosts` | `%SystemRoot%\System32\drivers\etc\hosts` |
| **Launcher Wrapper** | `/usr/local/bin/claude-privacy` (Bash) | `%LOCALAPPDATA%\Claude\claude-privacy.cmd` (Batch) |
| **Discovery Engine** | `DynamicPathFinder` (auto-locates binaries) | `DynamicPathFinder` (auto-locates MSIX / WindowsApps) |
| **Rollback Support** | Atomic restore of hosts & launcher | Atomic registry cleanup & hosts restore |

---

## 🔄 Uninstallation & Clean Rollback

To completely remove all configurations and return Claude Desktop to factory stock:

```bash
# On Linux / macOS
sudo clp rollback

# On Windows
clp rollback
```

To remove the `clp` binary itself:
- **Linux / macOS:** `sudo rm -f /usr/local/bin/claude-patcher /usr/local/bin/clp`
- **Windows:** Remove folder `%LOCALAPPDATA%\Programs\claude-patcher`

---

## ⚖️ Disclaimer

This project is an independent open-source utility and is **not affiliated with, endorsed by, or sponsored by Anthropic PBC**. All product names, logos, and brands are property of their respective owners.
