"""
Network introspection, proxy validation, and HTTPS IP geolocation utilities.
"""
import json
import os
import shutil
import ssl
import subprocess
import urllib.parse
import urllib.request

DEFAULT_USER_AGENT = "claude-patcher/1.0"
SOCKS_SCHEMES = ("socks4://", "socks4a://", "socks5://", "socks5h://")


def _normalize_ipwho(raw):
    if not isinstance(raw, dict) or raw.get("success") is False or not raw.get("ip"):
        return None
    conn = raw.get("connection") or {}
    tz_obj = raw.get("timezone") or {}
    tz_id = tz_obj.get("id") if isinstance(tz_obj, dict) else (tz_obj or "UTC")
    return {
        "status": "success",
        "query": raw.get("ip"),
        "country": raw.get("country") or raw.get("country_code") or "Unknown",
        "countryCode": raw.get("country_code") or "",
        "city": raw.get("city") or "",
        "regionName": raw.get("region") or "",
        "isp": conn.get("isp") or conn.get("org") or "Unknown",
        "timezone": tz_id or "UTC",
        "provider": "ipwho.is",
    }


def _normalize_ipinfo(raw):
    if not isinstance(raw, dict) or not raw.get("ip"):
        return None
    cc = raw.get("country") or ""
    return {
        "status": "success",
        "query": raw.get("ip"),
        "country": raw.get("country_name") or cc or "Unknown",
        "countryCode": cc,
        "city": raw.get("city") or "",
        "regionName": raw.get("region") or "",
        "isp": raw.get("org") or "Unknown",
        "timezone": raw.get("timezone") or "UTC",
        "provider": "ipinfo.io",
    }


def _normalize_freeipapi(raw):
    if not isinstance(raw, dict) or not raw.get("ipAddress"):
        return None
    tzs = raw.get("timeZones")
    tz_val = tzs[0] if isinstance(tzs, list) and tzs else "UTC"
    return {
        "status": "success",
        "query": raw.get("ipAddress"),
        "country": raw.get("countryName") or raw.get("countryCode") or "Unknown",
        "countryCode": raw.get("countryCode") or "",
        "city": raw.get("cityName") or "",
        "regionName": raw.get("regionName") or "",
        "isp": raw.get("asnOrganization") or "Unknown",
        "timezone": tz_val or "UTC",
        "provider": "freeipapi.com",
    }


GEO_ENDPOINTS = [
    ("ipwho.is", "https://ipwho.is/", _normalize_ipwho),
    ("ipinfo.io", "https://ipinfo.io/json", _normalize_ipinfo),
    ("freeipapi.com", "https://freeipapi.com/api/json", _normalize_freeipapi),
]


def _should_bypass_proxy(url, no_proxy=None):
    """Checks whether url host matches NO_PROXY / no_proxy rules."""
    raw_no_proxy = no_proxy if no_proxy is not None else (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "")
    if not raw_no_proxy:
        return False
    hostname = (urllib.parse.urlparse(url).hostname or "").lower()
    if not hostname:
        return False
    for entry in raw_no_proxy.split(","):
        token = entry.strip().lower()
        if not token:
            continue
        if token == "*":
            return True
        token_host = token.split(":", 1)[0].lstrip(".")
        if hostname == token_host or hostname.endswith("." + token_host):
            return True
    return False


def resolve_proxy_url(url=None, proxy=None):
    """Resolves effective proxy URL from explicit override or environment variables."""
    if proxy:
        return proxy.strip()
    if url and _should_bypass_proxy(url):
        return None
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(var, "").strip()
        if val:
            return val
    return None


def _fetch_via_socks(url, proxy_url, timeout):
    """Fetches HTTPS JSON via SOCKS proxy with strict TLS certificate verification."""
    try:
        import requests  # type: ignore
        import socks  # noqa: F401  # type: ignore
        resp = requests.get(
            url,
            proxies={"http": proxy_url, "https": proxy_url},
            headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
            verify=True,
        )
        resp.raise_for_status()
        return resp.json()
    except ImportError:
        pass

    curl_bin = shutil.which("curl")
    if curl_bin:
        proc = subprocess.run(
            [
                curl_bin,
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                str(max(1, int(round(timeout)))),
                "--proxy",
                proxy_url,
                "-A",
                DEFAULT_USER_AGENT,
                "-H",
                "Accept: application/json",
                url,
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
        raise RuntimeError(proc.stderr.strip() or f"curl failed with exit code {proc.returncode}")

    raise RuntimeError("SOCKS proxy configured but neither PySocks/requests nor curl is available")


def fetch_https_json(url, proxy=None, timeout=4.0, ssl_context=None):
    """Fetches JSON over verified HTTPS (never plain HTTP) with optional HTTP/HTTPS/SOCKS proxy."""
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ValueError(f"Refusing non-HTTPS geolocation URL: {url}")

    proxy_url = resolve_proxy_url(url=url, proxy=proxy)
    if proxy_url and proxy_url.lower().startswith(SOCKS_SCHEMES):
        return _fetch_via_socks(url, proxy_url, timeout)

    ctx = ssl_context or ssl.create_default_context()
    proxy_handler = (
        urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url})
        if proxy_url
        else urllib.request.ProxyHandler({})
    )
    opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(
        url,
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"},
    )
    with opener.open(req, timeout=timeout) as res:
        return json.loads(res.read().decode("utf-8"))


def check_vpn_network(proxy=None, timeout=4.0):
    """Queries HTTPS geolocation endpoints with TLS + proxy support to inspect egress IP and timezone."""
    for _, url, normalizer in GEO_ENDPOINTS:
        try:
            raw = fetch_https_json(url, proxy=proxy, timeout=timeout)
            normalized = normalizer(raw)
            if normalized and normalized.get("status") == "success" and normalized.get("query"):
                return normalized
        except Exception:
            continue
    return None


def resolve_proxy_timezone(explicit_tz=None, current_tz=None, has_launcher=False, proxy=None, timeout=3.0):
    """
    Resolves the safest timezone for anti-ban consistency:
    - Uses explicit_tz when provided (unless 'auto').
    - Preserves existing launcher TZ if configured and explicit_tz is None.
    - Otherwise queries HTTPS geo-lookup so TZ matches the proxy exit IP country.
    Returns (timezone_str, geo_info_or_none).
    """
    if explicit_tz and str(explicit_tz).lower() != "auto":
        return str(explicit_tz), None
    if has_launcher and current_tz and explicit_tz is None:
        return current_tz, None

    info = check_vpn_network(proxy=proxy, timeout=timeout)
    if info and info.get("timezone"):
        return info["timezone"], info
    return (current_tz or "UTC"), None
