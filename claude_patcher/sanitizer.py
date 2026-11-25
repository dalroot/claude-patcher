"""
Local client storage sanitization, SQLite cookie scrubber, Chromium Preferences hardening,
and hardware identifier management.
"""
import base64
import copy
import json
import os
import sqlite3

from .paths import PATHS
from .constants import CURRENT_OS, CHROMIUM_HARDENING_PREFS, TELEMETRY_COOKIE_NAMES
from .system import get_target_user_dirs


def _candidate_claude_data_dirs():
    """Collects unique Claude profile directories across detected user homes and active PATHS."""
    dirs = []
    seen = set()

    def _add(p):
        if p:
            norm = os.path.normpath(p)
            if norm not in seen:
                seen.add(norm)
                dirs.append(norm)

    for key in ("cookies_path", "sentry_dir", "ant_did_path"):
        val = PATHS.get(key)
        if val:
            if key == "cookies_path" and os.path.basename(os.path.dirname(val)) == "Network":
                _add(os.path.dirname(os.path.dirname(val)))
            else:
                _add(os.path.dirname(val))

    for udir in get_target_user_dirs():
        if CURRENT_OS == "Windows":
            _add(os.path.join(udir, "AppData", "Roaming", "Claude"))
        elif CURRENT_OS == "Darwin":
            _add(os.path.join(udir, "Library", "Application Support", "Claude"))
        else:
            _add(os.path.join(udir, ".config", "Claude"))

    return dirs


def _deep_merge_dicts(target: dict, overlay: dict) -> dict:
    for key, val in overlay.items():
        if isinstance(val, dict) and isinstance(target.get(key), dict):
            _deep_merge_dicts(target[key], val)
        else:
            target[key] = copy.deepcopy(val)
    return target


def harden_chromium_preferences() -> list[str]:
    """
    Merges WebRTC, DNS prefetch, and invasive permission hardening into Claude's Chromium
    Preferences JSON across detected user profile directories, preserving existing keys.
    """
    results = []
    for cdir in _candidate_claude_data_dirs():
        if not os.path.isdir(cdir):
            continue
        pref_path = os.path.join(cdir, "Preferences")
        data = {}
        if os.path.isfile(pref_path):
            try:
                with open(pref_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
            except Exception as e:
                results.append(f"Preferences read skipped for {pref_path}: {e}")
                continue
        _deep_merge_dicts(data, CHROMIUM_HARDENING_PREFS)
        try:
            with open(pref_path, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))
            results.append(f"Hardened Preferences in {cdir}")
        except Exception as e:
            results.append(f"Preferences write error for {pref_path}: {e}")
    return results


def check_chromium_preferences() -> dict:
    """Audits Chromium Preferences WebRTC/DNS/permission hardening in the active Claude profile."""
    cdirs = _candidate_claude_data_dirs()
    pref_path = None
    for cdir in cdirs:
        cand = os.path.join(cdir, "Preferences")
        if os.path.isfile(cand):
            pref_path = cand
            break

    if not pref_path:
        return {
            "exists": False,
            "path": None,
            "webrtc_policy_ok": False,
            "multiple_routes_disabled": False,
            "dns_prefetch_disabled": False,
            "geolocation_denied": False,
            "notifications_denied": False,
        }

    try:
        with open(pref_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}

    webrtc = data.get("webrtc", {}) if isinstance(data, dict) else {}
    dns_pref = data.get("dns_prefetching", {}) if isinstance(data, dict) else {}
    perms = (
        data.get("profile", {}).get("default_content_setting_values", {})
        if isinstance(data, dict) else {}
    )
    return {
        "exists": True,
        "path": pref_path,
        "webrtc_policy_ok": webrtc.get("ip_handling_policy") == "disable_non_proxied_udp",
        "multiple_routes_disabled": webrtc.get("multiple_routes_enabled") is False,
        "dns_prefetch_disabled": dns_pref.get("enabled") is False,
        "geolocation_denied": perms.get("geolocation") == 2,
        "notifications_denied": perms.get("notifications") == 2,
    }


def sanitize_local_telemetry_artifacts():
    """
    Sanitizes local persistent tracking artifacts across all detected Claude profile directories:
    1. Clears tracking cookies (_dd_s_v2, ajs_anonymous_id, _fbp) while preserving auth/CF
       cookies (sessionKey*, cf_*) and stable anthropic-device-id.
    2. Purges pending Sentry offline queues/session state and local Crashpad dump queues.
    """
    results = []
    placeholders = ",".join("?" for _ in TELEMETRY_COOKIE_NAMES)
    for cdir in _candidate_claude_data_dirs():
        # 1. SQLite Cookies (both legacy Cookies and Chromium >=96 Network/Cookies)
        for cp in (os.path.join(cdir, "Cookies"), os.path.join(cdir, "Network", "Cookies")):
            if os.path.exists(cp):
                try:
                    with sqlite3.connect(cp, timeout=5.0) as conn:
                        cur = conn.cursor()
                        cur.execute(
                            f"DELETE FROM cookies WHERE name IN ({placeholders})",
                            TELEMETRY_COOKIE_NAMES,
                        )
                        deleted = cur.rowcount
                        conn.commit()
                    if deleted > 0:
                        results.append(f"Cleared {deleted} tracking cookie(s) in {cdir}")
                except Exception as e:
                    results.append(f"Cookies sanitization skipped for {cp}: {e}")

        # 2. Sentry offline queue & session files
        sq = os.path.join(cdir, "sentry")
        if os.path.exists(sq):
            purged = 0
            queue_dir = os.path.join(sq, "queue")
            if os.path.exists(queue_dir):
                try:
                    for item in os.listdir(queue_dir):
                        fp = os.path.join(queue_dir, item)
                        if os.path.isfile(fp):
                            os.remove(fp)
                            purged += 1
                except Exception as e:
                    results.append(f"Sentry queue purge error for {cdir}: {e}")
            for fname in ("session.json", "scope_v3.json", "dump-organizations.json"):
                fp = os.path.join(sq, fname)
                if os.path.isfile(fp):
                    try:
                        os.remove(fp)
                        purged += 1
                    except Exception:
                        pass
            if purged > 0:
                results.append(f"Purged {purged} Sentry artifact(s) in {cdir}")

        # 3. Crashpad pending/completed/reports dumps (preserve settings/client_id)
        cp_dir = os.path.join(cdir, "Crashpad")
        if os.path.isdir(cp_dir):
            cp_purged = 0
            for sub in ("pending", "completed", "reports"):
                sub_dir = os.path.join(cp_dir, sub)
                if os.path.isdir(sub_dir):
                    for item in os.listdir(sub_dir):
                        fp = os.path.join(sub_dir, item)
                        if os.path.isfile(fp):
                            try:
                                os.remove(fp)
                                cp_purged += 1
                            except Exception:
                                pass
            if cp_purged > 0:
                results.append(f"Purged {cp_purged} Crashpad dump(s) in {cdir}")

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
