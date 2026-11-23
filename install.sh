#!/usr/bin/env bash
set -e

# ==============================================================================
# Claude Patcher (clp) Universal Global Installer for Linux & macOS
# ==============================================================================

echo "=========================================================="
echo "   Claude Desktop Privacy & Security Shield (clp)       "
echo "=========================================================="

# 1. Verify Python 3
if ! command -v python3 &>/dev/null; then
    echo "[-] Error: python3 is required but not installed." >&2
    echo "    Please install Python 3 (sudo apt install python3 python3-pip)" >&2
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Detected Python version: $PY_VER"

# 2. Install dependency: rich
echo "[+] Ensuring dependencies (rich>=13.0.0)..."
python3 -m pip install --quiet --break-system-packages rich>=13.0.0 2>/dev/null || \
python3 -m pip install --quiet rich>=13.0.0 2>/dev/null || \
pip3 install --quiet rich>=13.0.0 2>/dev/null || {
    echo "[!] Warning: pip install failed. Checking if rich is already importable..."
    python3 -c 'import rich' 2>/dev/null || {
        echo "[-] Error: Failed to install 'rich'. Please run: pip install rich" >&2
        exit 1
    }
}

# 3. Determine source file
SCRIPT_SOURCE=""
if [ -f "$(dirname "$0")/claude_patcher.py" ]; then
    SCRIPT_SOURCE="$(dirname "$0")/claude_patcher.py"
elif [ -f "./claude_patcher.py" ]; then
    SCRIPT_SOURCE="./claude_patcher.py"
else
    TEMP_DIR=$(mktemp -d)
    echo "[+] Downloading latest claude_patcher.py from GitHub..."
    curl -fsSL "https://raw.githubusercontent.com/dalroot/claude-patcher/main/claude_patcher.py" -o "$TEMP_DIR/claude_patcher.py"
    SCRIPT_SOURCE="$TEMP_DIR/claude_patcher.py"
fi

# 4. Global Target Paths
TARGET_DIR="/usr/local/bin"
TARGET_BIN="$TARGET_DIR/claude-patcher"
TARGET_LINK="$TARGET_DIR/clp"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo "[-] Error: Root privileges required to install to $TARGET_DIR. Run as root or with sudo." >&2
        exit 1
    fi
fi

echo "[+] Installing global binary to $TARGET_BIN..."
$SUDO mkdir -p "$TARGET_DIR"
$SUDO cp "$SCRIPT_SOURCE" "$TARGET_BIN"
$SUDO chmod 755 "$TARGET_BIN"

echo "[+] Creating global symlink $TARGET_LINK -> $TARGET_BIN..."
$SUDO ln -sf "$TARGET_BIN" "$TARGET_LINK"

# Clean up temp if used
[ -n "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"

echo ""
echo "=========================================================="
echo " [✓] Claude Patcher (clp) installed globally!"
echo "=========================================================="
echo " You can now run 'clp' from ANY terminal window:"
echo "   - clp          : Open Interactive Security Center"
echo "   - clp doctor   : Run Evidence-Based Security Audit"
echo "   - clp apply    : Deploy Enterprise MDM & Anti-Leak Shield"
echo "   - clp rollback : 100% Atomic Rollback to Factory State"
echo "=========================================================="
