"""
System operations, process lifecycle management, pristine backups, and privileged filesystem utilities.
"""
import os
import re
import time
import signal
import hashlib
import shutil
import subprocess
import tempfile
from rich.console import Console

from .paths import PATHS, PRISTINE_HOSTS_BAK
from .constants import CURRENT_OS

console = Console()

SINKHOLE_IPS = frozenset({"0.0.0.0", "127.0.0.1", "::", "::0", "::1"})
CLAUDE_LINUX_HELPER_BINS = frozenset({
    "claude-desktop",
    "chrome_crashpad_handler",
    "cowork-linux-helper",
    "chrome-sandbox",
})


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
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
        if mode is not None:
            os.chmod(target_path, mode)
    except PermissionError:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="clp_write_",
                suffix=".tmp",
                delete=False,
            ) as tf:
                tf.write(content)
                tmp_path = tf.name
            subprocess.run(["sudo", "mkdir", "-p", os.path.dirname(target_path)], check=True)
            subprocess.run(["sudo", "cp", tmp_path, target_path], check=True)
            if mode is not None:
                subprocess.run(["sudo", "chmod", oct(mode)[2:], target_path], check=True)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)


def parse_sinkholed_domains(hosts_content):
    """Extracts the set of active sinkholed hostnames from an /etc/hosts string."""
    sinkholed = set()
    if not hosts_content:
        return sinkholed
    for raw_line in hosts_content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] in SINKHOLE_IPS:
            for host in parts[1:]:
                sinkholed.add(host.lower())
    return sinkholed


def is_domain_sinkholed(hosts_content, domain):
    """Returns True only if domain is actively mapped to a sinkhole IP (not commented or substring)."""
    if not domain:
        return False
    return domain.strip().lower() in parse_sinkholed_domains(hosts_content)


def get_missing_sinkhole_domains(hosts_content, domains):
    """Returns domains from the iterable that are not yet actively sinkholed in hosts_content."""
    sinkholed = parse_sinkholed_domains(hosts_content)
    return [dom for dom in domains if dom and dom.strip().lower() not in sinkholed]


def validate_js_syntax(js_code, input_type=None, node_bin=None):
    """Validates JavaScript syntax using `node --check` via stdin without touching disk."""
    node = node_bin or shutil.which("node")
    if not node:
        return False, "node binary not found in PATH"

    payload = js_code.encode("utf-8") if isinstance(js_code, str) else js_code

    def _run_check(mod_type):
        cmd = [node, "--check"]
        if mod_type:
            cmd.extend(["--input-type", mod_type])
        return subprocess.run(cmd, input=payload, capture_output=True)

    proc = _run_check(input_type)
    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 and input_type is None:
        if (
            "Cannot use import statement outside a module" in stderr
            or "Unexpected token 'export'" in stderr
        ):
            proc = _run_check("module")
            stderr = proc.stderr.decode("utf-8", errors="replace").strip()

    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    return proc.returncode == 0, (stderr or stdout)


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


def _is_claude_proc_match(pid_dir, official_bin, real_official_bin, app_dirs):
    """Checks a single /proc/<pid> directory using exact executable path or comm matching."""
    exe_path = os.path.join(pid_dir, "exe")
    try:
        exe_raw = os.readlink(exe_path)
    except OSError:
        if not os.path.isdir(pid_dir):
            return False
        comm_path = os.path.join(pid_dir, "comm")
        try:
            with open(comm_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip() == "claude-desktop"
        except OSError:
            return False

    if exe_raw.endswith(" (deleted)"):
        exe_raw = exe_raw[:-10]

    exe_norm = os.path.normpath(exe_raw)
    exe_real = os.path.realpath(exe_norm) if os.path.isabs(exe_norm) else exe_norm

    if official_bin and (exe_norm == official_bin or exe_real == real_official_bin):
        return True
    if os.path.basename(exe_norm) == "claude-desktop":
        return True
    if any(exe_norm.startswith(d + os.sep) or exe_real.startswith(d + os.sep) for d in app_dirs):
        return os.path.basename(exe_norm) in CLAUDE_LINUX_HELPER_BINS
    return False


def find_claude_pids(proc_root="/proc", official_bin=None):
    """
    Finds PIDs belonging to Claude Desktop via exact /proc/<pid>/exe and /proc/<pid>/comm matching.
    Never uses broad cmdline matching so editors, shells, grep, or python processes are untouched.
    """
    if CURRENT_OS == "Darwin" and proc_root == "/proc":
        try:
            res = subprocess.run(["pgrep", "-x", "Claude"], capture_output=True, text=True)
            if res.returncode != 0:
                return []
            my_pid = os.getpid()
            return sorted(
                int(p.strip())
                for p in res.stdout.splitlines()
                if p.strip().isdigit() and int(p.strip()) != my_pid
            )
        except Exception:
            return []

    if not proc_root or not os.path.isdir(proc_root):
        return []

    if official_bin is None:
        official_bin = PATHS.get("official_bin")

    real_official_bin = os.path.realpath(official_bin) if official_bin else None
    app_dirs = {
        d
        for d in (
            os.path.dirname(official_bin) if official_bin else None,
            os.path.dirname(real_official_bin) if real_official_bin else None,
        )
        if d
    }

    my_pid = os.getpid()
    pids = []
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return []

    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == my_pid:
            continue
        pid_dir = os.path.join(proc_root, entry)
        if _is_claude_proc_match(pid_dir, official_bin, real_official_bin, app_dirs):
            pids.append(pid)
    return sorted(pids)


def _signal_pids(pids, sig):
    """Sends a signal to each PID safely, returning any PIDs blocked by PermissionError."""
    denied = []
    for pid in pids:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            denied.append(pid)
    return denied


def ensure_claude_closed(proc_root="/proc", timeout=1.5):
    """
    Detects if Claude Desktop is running and terminates it gracefully (or forcefully if hung),
    ensuring all file locks, caches, and SQLite handles are released before applying or rolling back patches.
    """
    closed = False
    if CURRENT_OS == "Windows":
        try:
            res = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Claude.exe", "/FO", "CSV"], capture_output=True, text=True)
            if '"Claude.exe"' in res.stdout:
                console.print("[yellow]⚠ Detected running Claude Desktop process. Terminating to apply patches cleanly...[/yellow]")
                subprocess.run(["taskkill", "/F", "/IM", "Claude.exe", "/T"], capture_output=True)
                time.sleep(1)
                console.print("[bold green]✔ Successfully closed Claude Desktop.[/bold green]")
                closed = True
        except Exception as e:
            console.print(f"[dim]Process cleanup: {e}[/dim]")
    else:
        try:
            pids = find_claude_pids(proc_root=proc_root)
            if pids:
                pid_str = ", ".join(str(p) for p in pids)
                console.print(f"[yellow]⚠ Detected running Claude Desktop process (PIDs: {pid_str}). Closing application...[/yellow]")
                denied = _signal_pids(pids, signal.SIGTERM)
                deadline = time.monotonic() + max(0.0, timeout)
                while time.monotonic() < deadline:
                    lingering = [p for p in find_claude_pids(proc_root=proc_root) if p not in denied]
                    if not lingering:
                        break
                    time.sleep(0.15)
                lingering = [p for p in find_claude_pids(proc_root=proc_root) if p not in denied]
                if lingering:
                    denied.extend(_signal_pids(lingering, signal.SIGKILL))
                    time.sleep(0.2)
                if denied:
                    console.print(f"[yellow]⚠ Permission denied closing PID(s): {', '.join(str(p) for p in sorted(set(denied)))}[/yellow]")
                else:
                    console.print("[bold green]✔ Successfully closed Claude Desktop.[/bold green]")
                    closed = True
        except Exception as e:
            console.print(f"[dim]Process cleanup: {e}[/dim]")
    return closed
