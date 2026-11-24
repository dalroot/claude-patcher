#!/usr/bin/env bash
set -e

# ==============================================================================
# Claude Patcher (clp) Universal Global Installer for Linux & macOS
# Modular Enterprise Edition
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

# 2. Install package via pip (Modular Package Architecture)
INSTALL_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"

if [ -f "$INSTALL_DIR/pyproject.toml" ] && [ -d "$INSTALL_DIR/claude_patcher" ]; then
    echo "[+] Installing local modular package from $INSTALL_DIR..."
    python3 -m pip install --quiet --upgrade --break-system-packages "$INSTALL_DIR" 2>/dev/null || \
    python3 -m pip install --quiet --upgrade "$INSTALL_DIR" 2>/dev/null || \
    pip3 install --quiet --upgrade "$INSTALL_DIR" 2>/dev/null || {
        echo "[!] Standard pip failed, attempting sudo pip install..."
        sudo python3 -m pip install --quiet --upgrade --break-system-packages "$INSTALL_DIR"
    }
else
    echo "[+] Installing latest modular package from GitHub repository..."
    python3 -m pip install --quiet --upgrade --break-system-packages "git+https://github.com/dalroot/claude-patcher.git" 2>/dev/null || \
    python3 -m pip install --quiet --upgrade "git+https://github.com/dalroot/claude-patcher.git" 2>/dev/null || \
    pip3 install --quiet --upgrade "git+https://github.com/dalroot/claude-patcher.git" 2>/dev/null || {
        echo "[!] Standard pip failed, attempting sudo pip install..."
        sudo python3 -m pip install --quiet --upgrade --break-system-packages "git+https://github.com/dalroot/claude-patcher.git"
    }
fi

# 3. Global Symlink Resolution
TARGET_DIR="/usr/local/bin"
TARGET_LINK="$TARGET_DIR/clp"
TARGET_ALT="$TARGET_DIR/claude-patcher"

PIP_BIN=$(command -v clp || true)
if [ -z "$PIP_BIN" ]; then
    USER_BASE=$(python3 -m site --user-base 2>/dev/null || echo "$HOME/.local")
    if [ -f "$USER_BASE/bin/clp" ]; then
        PIP_BIN="$USER_BASE/bin/clp"
    fi
fi

if [ -n "$PIP_BIN" ] && [ -x "$PIP_BIN" ]; then
    if [ "$PIP_BIN" != "$TARGET_LINK" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            ln -sf "$PIP_BIN" "$TARGET_LINK"
            ln -sf "$PIP_BIN" "$TARGET_ALT"
        elif command -v sudo &>/dev/null; then
            sudo ln -sf "$PIP_BIN" "$TARGET_LINK" 2>/dev/null || true
            sudo ln -sf "$PIP_BIN" "$TARGET_ALT" 2>/dev/null || true
        fi
    fi
fi

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
