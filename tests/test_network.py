"""Tests for HTTPS geolocation, strict TLS rejection of HTTP, proxy resolution & fallback."""
import pytest

from claude_patcher import network


def test_fetch_https_json_rejects_plain_http():
    with pytest.raises(ValueError, match="Refusing non-HTTPS"):
        network.fetch_https_json("http://ip-api.com/json/")


def test_resolve_proxy_url_env_and_no_proxy(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:10808")
    assert network.resolve_proxy_url("https://ipwho.is/") == "socks5h://127.0.0.1:10808"

    monkeypatch.setenv("NO_PROXY", "ipwho.is")
    assert network.resolve_proxy_url("https://ipwho.is/") is None
    assert network.resolve_proxy_url("https://ipinfo.io/json") == "socks5h://127.0.0.1:10808"


def test_check_vpn_network_fallback_and_normalization(monkeypatch):
    responses = {
        "https://ipwho.is/": RuntimeError("timeout"),
        "https://ipinfo.io/json": {
            "ip": "203.0.113.10",
            "country": "NL",
            "region": "North Holland",
            "city": "Amsterdam",
            "org": "AS1234 Example Net",
            "timezone": "Europe/Amsterdam",
        },
    }

    def fake_fetch(url, proxy=None, timeout=4.0, ssl_context=None):
        val = responses[url]
        if isinstance(val, Exception):
            raise val
        return val

    monkeypatch.setattr(network, "fetch_https_json", fake_fetch)
    info = network.check_vpn_network()
    assert info is not None
    assert info["status"] == "success"
    assert info["query"] == "203.0.113.10"
    assert info["countryCode"] == "NL"
    assert info["timezone"] == "Europe/Amsterdam"
    assert info["provider"] == "ipinfo.io"


def test_check_vpn_network_freeipapi_and_all_fail(monkeypatch):
    def fake_fetch_third(url, proxy=None, timeout=4.0, ssl_context=None):
        if "freeipapi.com" in url:
            return {
                "ipAddress": "198.51.100.7",
                "countryName": "Germany",
                "countryCode": "DE",
                "regionName": "Hesse",
                "cityName": "Frankfurt",
                "asnOrganization": "Example GmbH",
                "timeZones": ["Europe/Berlin"],
            }
        raise OSError("network down")

    monkeypatch.setattr(network, "fetch_https_json", fake_fetch_third)
    info = network.check_vpn_network()
    assert info is not None
    assert info["timezone"] == "Europe/Berlin"
    assert info["provider"] == "freeipapi.com"

    monkeypatch.setattr(network, "fetch_https_json", lambda *a, **kw: (_ for _ in ()).throw(OSError("down")))
    assert network.check_vpn_network() is None


def test_resolve_proxy_timezone_auto_sync(monkeypatch):
    monkeypatch.setattr(
        network,
        "check_vpn_network",
        lambda proxy=None, timeout=3.0: {"status": "success", "timezone": "Europe/Amsterdam", "countryCode": "NL"},
    )
    # No launcher yet & no explicit TZ -> syncs to proxy exit IP timezone
    tz, info = network.resolve_proxy_timezone(explicit_tz=None, current_tz="UTC", has_launcher=False)
    assert tz == "Europe/Amsterdam"
    assert info["countryCode"] == "NL"

    # Explicit 'auto' always syncs even if launcher exists
    tz2, info2 = network.resolve_proxy_timezone(explicit_tz="auto", current_tz="UTC", has_launcher=True)
    assert tz2 == "Europe/Amsterdam"
    assert info2 is not None

    # Explicit concrete TZ is respected without geo-lookup
    tz3, info3 = network.resolve_proxy_timezone(explicit_tz="America/New_York", current_tz="UTC", has_launcher=True)
    assert tz3 == "America/New_York"
    assert info3 is None
