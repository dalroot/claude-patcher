# Claude Patcher (`clp`)

A privacy, telemetry-blocking, and security-hardening suite for Claude Desktop on Linux and Windows.

## Key Capabilities

- **Enterprise MDM Configuration:** Automatically configures enterprise policies (`disableEssentialTelemetry`, `disableNonessentialTelemetry`, `disableNonessentialServices`, `disableAutoUpdates`) without modifying application binaries.
- **Chromium Anti-Leak Switches:** Enforces WebRTC isolation, DNS prefetch disabling, crash dump suppression, and background network telemetry isolation.
- **Network Egress Sinkholing:** Redirects known telemetry and analytics domains to `0.0.0.0` at the OS hosts layer.
- **Evidence-Based Auditing (`clp doctor`):** Audits running processes, MDM policies, active sockets, and anti-leak switches with structured JSON export support (`clp doctor --json`).
- **Atomic Rollback Engine (`clp rollback`):** Restores pristine system configurations, hosts files, and desktop launchers atomically.
- **Cross-Platform Compatibility:** Dynamic discovery across Linux (JSON policies) and Windows (HKLM/HKCU registry policies).

## Quick Start

### Linux Installation
```bash
git clone https://github.com/dalroot/claude-patcher.git
cd claude-patcher
./install.sh
```

### Windows Installation (PowerShell)
```powershell
git clone https://github.com/dalroot/claude-patcher.git
cd claude-patcher
.\install.ps1
```

### Basic Commands
- Interactive TUI: `clp`
- Health Audit: `clp doctor`
- JSON Diagnostic: `clp doctor --json`
- Apply Hardening: `clp apply`
- Rollback System: `clp rollback`

## Disclaimer
This project is an independent open-source utility and is not affiliated with, endorsed by, or sponsored by Anthropic PBC.
