"""
Network introspection, proxy validation, and IP geolocation utilities.
"""
import json
import urllib.request


def check_vpn_network():
    """Queries external geolocation endpoint to inspect egress proxy IP, country, and timezone."""
    try:
        req = urllib.request.Request("http://ip-api.com/json/", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=3.0) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception:
        return None
