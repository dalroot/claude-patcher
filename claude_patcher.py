#!/usr/bin/env python3
"""
Claude Desktop Enterprise Security Shield & Multi-Platform Patcher (clp)
Version: 1.0.0-beta (Linux & Windows)

Root execution wrapper for backwards compatibility with direct script execution:
    ./claude_patcher.py [command]
    python3 claude_patcher.py [command]
"""
import os
import sys

# Ensure local package directory is prioritized in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from claude_patcher.cli import main

if __name__ == "__main__":
    main()
