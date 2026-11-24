"""
Local client storage sanitization, SQLite cookie scrubber, and hardware identifier management.
"""
import os
import base64
import sqlite3

from .paths import PATHS
from .constants import CURRENT_OS
from .system import get_target_user_dirs


def sanitize_local_telemetry_artifacts():
    """
    Sanitizes local persistent tracking tokens across all detected user home directories:
    1. Removes 'anthropic-device-id' cookie from SQLite Cookies database.
    2. Purges pending offline Sentry envelope queue directories.
    """
    results = []
    for udir in get_target_user_dirs():
        # 1. SQLite Cookies
        cp = os.path.join(udir, ".config", "Claude", "Cookies") if CURRENT_OS != "Windows" else os.path.join(udir, "AppData", "Roaming", "Claude", "Cookies")
        if os.path.exists(cp):
            try:
                conn = sqlite3.connect(cp)
                cur = conn.cursor()
                cur.execute("DELETE FROM cookies WHERE name='anthropic-device-id'")
                deleted = cur.rowcount
                conn.commit()
                conn.close()
                if deleted > 0:
                    results.append(f"Deleted {deleted} anthropic-device-id cookie(s) in {os.path.basename(udir)}")
            except Exception as e:
                results.append(f"Cookies sanitization skipped for {udir}: {e}")

        # 2. Sentry offline queue
        sq = os.path.join(udir, ".config", "Claude", "sentry") if CURRENT_OS != "Windows" else os.path.join(udir, "AppData", "Roaming", "Claude", "sentry")
        if os.path.exists(sq):
            queue_dir = os.path.join(sq, "queue")
            if os.path.exists(queue_dir):
                try:
                    purged = 0
                    for item in os.listdir(queue_dir):
                        fp = os.path.join(queue_dir, item)
                        if os.path.isfile(fp):
                            os.remove(fp)
                            purged += 1
                    if purged > 0:
                        results.append(f"Purged {purged} queued Sentry envelope(s) in {os.path.basename(udir)}")
                except Exception as e:
                    results.append(f"Sentry queue purge error for {udir}: {e}")

    return results


def check_ant_did_status():
    """Reads and decodes the local ant-did device identifier if present."""
    dp = PATHS.get("ant_did_path")
    if not dp or not os.path.exists(dp):
        return {"exists": False, "uuid": None, "mode": "EPHEMERAL_OR_ABSENT"}
    try:
        with open(dp, "rb") as f:
            raw = f.read().strip()
        decoded = base64.b64decode(raw).decode("utf-8").strip()
        return {"exists": True, "uuid": decoded, "mode": "PERSISTENT_IDENTIFIER"}
    except Exception:
        return {"exists": True, "uuid": "INVALID_FORMAT", "mode": "UNKNOWN"}
