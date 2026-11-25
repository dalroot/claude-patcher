"""Tests for exact process matching in system.py and safe closure in cli.py."""
import os
import signal
import sys
from unittest.mock import patch

import pytest

from claude_patcher import cli, system


def _make_proc_entry(proc_root, pid, exe_target=None, comm=None, cmdline=None):
    pdir = proc_root / str(pid)
    pdir.mkdir(parents=True, exist_ok=True)
    if exe_target is not None:
        (pdir / "exe").symlink_to(exe_target)
    if comm is not None:
        (pdir / "comm").write_text(comm + "\n", encoding="utf-8")
    if cmdline is not None:
        (pdir / "cmdline").write_bytes(b"\x00".join(arg.encode("utf-8") for arg in cmdline) + b"\x00")


def test_find_claude_pids_exact_matching(tmp_path):
    proc_root = tmp_path / "proc"
    proc_root.mkdir()

    official = "/usr/lib/claude-desktop/claude-desktop"

    # Real Claude Desktop main & helper processes -> MUST match
    _make_proc_entry(proc_root, 1001, exe_target=official, comm="claude-desktop")
    _make_proc_entry(proc_root, 1002, exe_target=official + " (deleted)", comm="claude-desktop")
    _make_proc_entry(
        proc_root,
        1003,
        exe_target="/usr/lib/claude-desktop/chrome_crashpad_handler",
        comm="chrome_crashpad",
    )
    # Fallback when exe is unreadable (e.g. PermissionError) and comm is exact
    _make_proc_entry(proc_root, 1004, exe_target=None, comm="claude-desktop")

    # Unrelated processes mentioning "claude-desktop" in cmdline -> MUST NOT match
    _make_proc_entry(
        proc_root,
        2001,
        exe_target="/usr/bin/vim",
        comm="vim",
        cmdline=["vim", "/home/user/claude-desktop/notes.md"],
    )
    _make_proc_entry(
        proc_root,
        2002,
        exe_target="/usr/bin/bash",
        comm="bash",
        cmdline=["bash", "-c", "grep claude-desktop /var/log/syslog"],
    )
    _make_proc_entry(
        proc_root,
        2003,
        exe_target="/usr/bin/python3",
        comm="python3",
        cmdline=["python3", "-m", "pytest", "-k", "claude-desktop"],
    )
    _make_proc_entry(
        proc_root,
        2004,
        exe_target="/usr/lib/vscode/chrome_crashpad_handler",
        comm="chrome_crashpad",
    )
    _make_proc_entry(
        proc_root,
        2005,
        exe_target="/usr/local/bin/claude",
        comm="claude",
    )
    # Unreadable exe with unrelated comm
    _make_proc_entry(proc_root, 2006, exe_target=None, comm="grep")

    matched = system.find_claude_pids(proc_root=str(proc_root), official_bin=official)
    assert matched == [1001, 1002, 1003, 1004]


def test_ensure_claude_closed_signals_only_matched_pids(tmp_path, monkeypatch):
    proc_root = tmp_path / "proc"
    proc_root.mkdir()

    _make_proc_entry(proc_root, 3001, exe_target="/usr/lib/claude-desktop/claude-desktop", comm="claude-desktop")
    _make_proc_entry(proc_root, 3002, exe_target="/usr/bin/vim", comm="vim", cmdline=["vim", "claude-desktop"])

    monkeypatch.setattr(system, "CURRENT_OS", "Linux")
    monkeypatch.setitem(system.PATHS, "official_bin", "/usr/lib/claude-desktop/claude-desktop")

    killed = []

    def fake_kill(pid, sig):
        killed.append((pid, sig))
        # Simulate process exiting on SIGTERM
        if sig == signal.SIGTERM:
            for item in (proc_root / str(pid)).iterdir():
                item.unlink()
            (proc_root / str(pid)).rmdir()

    monkeypatch.setattr(os, "kill", fake_kill)
    closed = system.ensure_claude_closed(proc_root=str(proc_root), timeout=0.5)
    assert closed is True
    assert killed == [(3001, signal.SIGTERM)]


@pytest.mark.parametrize(
    "subcmd,target_fn",
    [
        ("patch-asar", "apply_asar_patch"),
        ("rollback-asar", "rollback_asar_patch"),
    ],
)
def test_cli_asar_commands_call_ensure_claude_closed(monkeypatch, subcmd, target_fn):
    events = []
    monkeypatch.setattr(cli, "ensure_claude_closed", lambda: events.append("closed") or True)
    monkeypatch.setattr(cli, target_fn, lambda: events.append(target_fn) or (True, "done"))

    with patch.object(sys, "argv", ["clp", subcmd]):
        cli.main()

    assert events == ["closed", target_fn]
