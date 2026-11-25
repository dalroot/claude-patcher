"""Tests for /etc/hosts sinkhole parsing, deduplication, and cmd_apply integration."""
from unittest.mock import MagicMock

from claude_patcher.commands import apply as apply_cmd
from claude_patcher.system import (
    get_missing_sinkhole_domains,
    is_domain_sinkholed,
    parse_sinkholed_domains,
)


def test_parse_sinkholed_domains_ignores_comments_and_substrings():
    hosts = "\n".join([
        "# 0.0.0.0 sentry.io",
        "   #0.0.0.0 api.segment.io",
        "0.0.0.0 sentry.io.local",
        "0.0.0.0 mysentry.io",
        "0.0.0.0 sub.sentry.io",
        "192.168.1.50 us5.datadoghq.com",
        "0.0.0.0\tbrowser-intake-us5-datadoghq.com  # active",
        "127.0.0.1 CDN.SEGMENT.COM",
        ":: hexagon-analytics.com",
    ])
    parsed = parse_sinkholed_domains(hosts)
    assert "sentry.io" not in parsed
    assert "api.segment.io" not in parsed
    assert "us5.datadoghq.com" not in parsed
    assert "browser-intake-us5-datadoghq.com" in parsed
    assert "cdn.segment.com" in parsed
    assert "hexagon-analytics.com" in parsed

    assert is_domain_sinkholed(hosts, "sentry.io") is False
    assert is_domain_sinkholed(hosts, "cdn.segment.com") is True
    assert is_domain_sinkholed(hosts, "CDN.SEGMENT.COM") is True


def test_get_missing_sinkhole_domains_exact_dedup():
    hosts = (
        "# 0.0.0.0 sentry.io\n"
        "0.0.0.0 sentry.io.evil.com\n"
        "0.0.0.0 us5.datadoghq.com\n"
    )
    missing = get_missing_sinkhole_domains(
        hosts,
        ["sentry.io", "us5.datadoghq.com", "api.segment.io"],
    )
    assert missing == ["sentry.io", "api.segment.io"]


def test_cmd_apply_hosts_dedup_and_no_comment_skip(tmp_path, monkeypatch):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "127.0.0.1 localhost\n"
        "# 0.0.0.0 sentry.io\n"
        "0.0.0.0 sentry.io.backup\n"
        "0.0.0.0 us5.datadoghq.com\n",
        encoding="utf-8",
    )

    monkeypatch.setitem(apply_cmd.PATHS, "hosts_path", str(hosts_file))
    monkeypatch.setitem(apply_cmd.PATHS, "ant_did_path", str(tmp_path / "ant-did"))
    monkeypatch.setattr(apply_cmd, "ensure_claude_closed", lambda: False)
    monkeypatch.setattr(apply_cmd, "backup_pristine_state", lambda: None)
    monkeypatch.setattr(apply_cmd, "apply_asar_patch", lambda **kw: (True, "ok"))
    monkeypatch.setattr(apply_cmd, "harden_chromium_preferences", lambda: ["prefs-ok"])
    monkeypatch.setattr(apply_cmd, "ENGINE", MagicMock())

    apply_cmd.cmd_apply(tz="UTC", block_trackers=True, reset_did=False)

    updated = hosts_file.read_text(encoding="utf-8")
    # Commented sentry.io must still trigger an active 0.0.0.0 sentry.io entry
    assert "\n0.0.0.0 sentry.io\n" in updated
    # Already-active us5.datadoghq.com must NOT be duplicated
    assert updated.count("0.0.0.0 us5.datadoghq.com") == 1
