#!/usr/bin/env bash
set -e

# Claude Patcher (clp) Quick Installer for Linux
echo "=== Claude Patcher (clp) Installer ==="

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "[-] Error: python3 is required but not installed." >&2
    exit 1
fi

# Check Python version >= 3.9
py_ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Detected Python version: $py_ver"

# Install requirements
echo "[+] Installing dependencies..."
python3 -m pip install --quiet rich>=13.0.0 || pip3 install --quiet rich>=13.0.0

# Install script to /usr/local/bin
TARGET_BIN="/usr/local/bin/claude-patcher"
TARGET_LINK="/usr/local/bin/clp"

echo "[+] Installing binary to $TARGET_BIN..."
sudo cp claude_patcher.py "$TARGET_BIN"
sudo chmod 755 "$TARGET_BIN"

echo "[+] Creating shortcut symlink $TARGET_LINK..."
sudo ln -sf "$TARGET_BIN" "$TARGET_LINK"

echo ""
echo "[✓] Installation complete!"
echo "    Run 'clp' to open the interactive Security Center,"
echo "    or 'clp doctor' to audit your current system protections."
