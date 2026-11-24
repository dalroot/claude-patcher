"""
Zero-Byte ASAR Surgical Patcher & Deep Telemetry Neutralizer.
Guarantees byte-level length preservation to maintain ASAR header offset integrity.
"""
import os
import shutil
import subprocess

from .paths import PATHS
from .constants import SURGICAL_PATCHES
from .sanitizer import sanitize_local_telemetry_artifacts


def check_asar_patch_status():
    """
    Scans app.asar and ion-dist.asar to audit the status of all 8 surgical patches.
    Returns structured dictionary with overall status and per-patch verification.
    """
    report = {
        "exists": False,
        "status": "NOT_FOUND",
        "backup_exists": False,
        "patches": {},
        "backups": {}
    }

    file_contents = {}
    for p in SURGICAL_PATCHES:
        fkey = p["file_key"]
        fpath = PATHS.get(fkey)
        if fpath and fpath not in file_contents:
            if os.path.exists(fpath):
                bak_path = fpath + ".stock.bak"
                report["backups"][fkey] = os.path.exists(bak_path)
                try:
                    with open(fpath, "rb") as f:
                        file_contents[fpath] = f.read()
                except Exception:
                    file_contents[fpath] = None
            else:
                report["backups"][fkey] = False
                file_contents[fpath] = None

    if not file_contents:
        return report

    report["exists"] = True
    report["backup_exists"] = report["backups"].get("asar_path", False) and report["backups"].get("ion_asar_path", False)
    total = len(SURGICAL_PATCHES)
    neutralized_count = 0
    stock_count = 0

    for p in SURGICAL_PATCHES:
        pid = p["id"]
        fpath = PATHS.get(p["file_key"])
        data = file_contents.get(fpath)
        if data is None:
            report["patches"][pid] = {"status": "FILE_NOT_FOUND", "name": p["name"], "file": fpath}
            continue

        if p["patched"] in data:
            report["patches"][pid] = {"status": "NEUTRALIZED", "name": p["name"], "file": fpath}
            neutralized_count += 1
        elif p["stock"] in data:
            report["patches"][pid] = {"status": "STOCK", "name": p["name"], "file": fpath}
            stock_count += 1
        else:
            report["patches"][pid] = {"status": "UNKNOWN", "name": p["name"], "file": fpath}

    if neutralized_count == total:
        report["status"] = "NEUTRALIZED"
    elif neutralized_count > 0:
        report["status"] = "PARTIALLY_PATCHED"
    elif stock_count == total:
        report["status"] = "STOCK"
    else:
        report["status"] = "UNKNOWN"

    return report


def apply_asar_patch():
    """
    Applies in-place surgical zero-byte patches to app.asar and ion-dist.asar.
    Creates stock backups prior to patching and enforces zero-byte drift integrity.
    """
    files_to_patch = {}
    for p in SURGICAL_PATCHES:
        fkey = p["file_key"]
        fpath = PATHS.get(fkey)
        if fpath and fpath not in files_to_patch:
            files_to_patch[fpath] = []
        if fpath:
            files_to_patch[fpath].append(p)

    if not files_to_patch:
        return False, "Target ASAR files not found on this system"

    # Step 1: Ensure stock backups exist
    for fpath in files_to_patch.keys():
        if not os.path.exists(fpath):
            return False, f"Target file not found: {fpath}"
        bak_path = fpath + ".stock.bak"
        if not os.path.exists(bak_path):
            try:
                shutil.copy2(fpath, bak_path)
            except PermissionError:
                subprocess.run(["sudo", "cp", "-p", fpath, bak_path], check=True)

    # Step 2: Apply in-place replacements per file
    applied_patches = 0
    already_patched = 0

    for fpath, patches in files_to_patch.items():
        with open(fpath, "rb") as f:
            content = f.read()

        orig_len = len(content)
        modified_content = bytearray(content)

        for p in patches:
            stock = p["stock"]
            patched = p["patched"]
            exp_count = p.get("expected_count", 1)

            if bytes(patched) in modified_content:
                already_patched += 1
                continue

            cnt = modified_content.count(stock)
            if cnt != exp_count:
                return False, f"Signature count mismatch for '{p['name']}' in {os.path.basename(fpath)}: expected {exp_count}, found {cnt}"

            modified_content = modified_content.replace(stock, patched)

        if len(modified_content) != orig_len:
            return False, f"Fatal: Byte length shifted for {os.path.basename(fpath)}! Aborting for integrity."

        if modified_content != content:
            tmp_path = f"/tmp/{os.path.basename(fpath)}_{os.getpid()}.tmp"
            with open(tmp_path, "wb") as f:
                f.write(modified_content)
            try:
                shutil.copy2(tmp_path, fpath)
            except PermissionError:
                subprocess.run(["sudo", "cp", tmp_path, fpath], check=True)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            applied_patches += 1

    # Step 3: Sanitize local SQLite cookies and sentry queues
    san_logs = sanitize_local_telemetry_artifacts()

    return True, f"Enforced {len(SURGICAL_PATCHES)} surgical in-place patches (Zero-Byte Drift). " + "; ".join(san_logs)


def rollback_asar_patch():
    """Restores stock app.asar and ion-dist.asar files from pristine backups."""
    files_to_restore = set()
    for p in SURGICAL_PATCHES:
        fpath = PATHS.get(p["file_key"])
        if fpath:
            files_to_restore.add(fpath)

    restored = []
    for fpath in files_to_restore:
        bak_path = fpath + ".stock.bak"
        if os.path.exists(bak_path):
            try:
                shutil.copy2(bak_path, fpath)
                restored.append(os.path.basename(fpath))
            except PermissionError:
                subprocess.run(["sudo", "cp", "-p", bak_path, fpath], check=True)
                restored.append(os.path.basename(fpath) + " (sudo)")
        else:
            with open(fpath, "rb") as f:
                content = f.read()
            modified = bytearray(content)
            for p in SURGICAL_PATCHES:
                if p["file_key"] in fpath or PATHS.get(p["file_key"]) == fpath:
                    modified = modified.replace(p["patched"], p["stock"])
            if modified != content:
                tmp_path = f"/tmp/{os.path.basename(fpath)}_rb_{os.getpid()}.tmp"
                with open(tmp_path, "wb") as f:
                    f.write(modified)
                try:
                    shutil.copy2(tmp_path, fpath)
                except PermissionError:
                    subprocess.run(["sudo", "cp", tmp_path, fpath], check=True)
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                restored.append(os.path.basename(fpath) + " (reverted)")

    return True, f"Restored {', '.join(restored)} to factory stock state"
