"""
System operations, process lifecycle management, pristine backups, and privileged filesystem utilities.
"""
import os
import re
import time
import hashlib
import shutil
import subprocess
from rich.console import Console

from .paths import PATHS, PRISTINE_HOSTS_BAK
from .constants import CURRENT_OS

console = Console()


def calculate_sha256(filepath):
    """Calculates SHA-256 cryptographic hash of a target file."""
    if not filepath or not os.path.exists(filepath) or os.path.isdir(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_privileged_write(target_path, content, mode=None):
    """Safely writes a file, escalating via sudo when direct write lacks permissions."""
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
    """Takes a pristine bit-level backup of system hosts before any sinkhole additions."""
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
    """Extracts current cloaked timezone configured in launcher script."""
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


def get_target_user_dirs():
    """Discovers all local user profile directories to ensure multi-profile sanitization."""
    dirs = []
    dirs.append(os.path.expanduser("~"))
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            dirs.append(pwd.getpwnam(sudo_user).pw_dir)
        except Exception:
            pass
    if os.path.exists("/home"):
        try:
            for u in os.listdir("/home"):
                p = os.path.join("/home", u)
                if os.path.isdir(p) and p not in dirs:
                    dirs.append(p)
        except Exception:
            pass
    return list(set(dirs))


def ensure_claude_closed():
    """
    Detects if Claude Desktop is running and terminates it gracefully (or forcefully if hung),
    ensuring all file locks, caches, and SQLite handles are released before applying or rolling back patches.
    """
    closed = False
    if CURRENT_OS == "Windows":
        try:
            res = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Claude.exe", "/FO", "CSV"], capture_output=True, text=True)
            if "Claude.exe" in res.stdout:
                console.print("[yellow]⚠ Detected running Claude Desktop process. Terminating to apply patches cleanly...[/yellow]")
                subprocess.run(["taskkill", "/F", "/IM", "Claude.exe", "/T"], capture_output=True)
                time.sleep(1)
                console.print("[bold green]✔ Successfully closed Claude Desktop.[/bold green]")
                closed = True
        except Exception as e:
            console.print(f"[dim]Process cleanup: {e}[/dim]")
    else:
        try:
            res = subprocess.run(["pgrep", "-f", "claude-desktop"], capture_output=True, text=True)
            pids = [p.strip() for p in res.stdout.strip().split() if p.strip() and p.strip() != str(os.getpid())]
            if pids:
                console.print(f"[yellow]⚠ Detected running Claude Desktop process (PIDs: {', '.join(pids)}). Closing application...[/yellow]")
                subprocess.run(["pkill", "-TERM", "-f", "claude-desktop"], capture_output=True)
                time.sleep(1.5)
                # Verify and force kill if lingering
                check_res = subprocess.run(["pgrep", "-f", "claude-desktop"], capture_output=True, text=True)
                lingering = [p.strip() for p in check_res.stdout.strip().split() if p.strip() and p.strip() != str(os.getpid())]
                if lingering:
                    subprocess.run(["pkill", "-KILL", "-f", "claude-desktop"], capture_output=True)
                    time.sleep(0.5)
                console.print("[bold green]✔ Successfully closed Claude Desktop.[/bold green]")
                closed = True
        except Exception as e:
            console.print(f"[dim]Process cleanup: {e}[/dim]")
    return closed
