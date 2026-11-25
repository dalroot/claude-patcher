"""Tests for Phase B doctor diagnostics, ASAR/V8/flag/artifact audits, and banner status."""
import json
import os
import sqlite3
from unittest.mock import MagicMock

from claude_patcher.asar import pack_asar
from claude_patcher.commands import doctor as doctor_cmd
from claude_patcher.constants import ANTI_LEAK_SWITCHES, MANAGED_POLICIES, TRACKER_SINKS
from claude_patcher.ui import banner


def test_doctor_json_and_hosts_check(tmp_path, monkeypatch, capsys):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "# 0.0.0.0 sentry.io\n"
        "0.0.0.0 sentry.io.local\n"
        "0.0.0.0 us5.datadoghq.com\n",
        encoding="utf-8",
    )

    fake_engine = MagicMock()
    fake_engine.check_mdm_status.return_value = {p["key"]: True for p in MANAGED_POLICIES}
    fake_engine.check_launcher_status.return_value = {sw[1]: True for sw in ANTI_LEAK_SWITCHES}

    monkeypatch.setattr(doctor_cmd, "ENGINE", fake_engine)
    monkeypatch.setitem(doctor_cmd.PATHS, "hosts_path", str(hosts_file))
    monkeypatch.setitem(doctor_cmd.PATHS, "official_bin", str(tmp_path / "missing-bin"))
    monkeypatch.setitem(doctor_cmd.PATHS, "asar_path", None)
    monkeypatch.setitem(doctor_cmd.PATHS, "ion_asar_path", None)
    monkeypatch.setitem(doctor_cmd.PATHS, "launcher_path", str(tmp_path / "missing-launcher"))
    monkeypatch.setitem(doctor_cmd.PATHS, "cookies_path", str(tmp_path / "Cookies"))
    monkeypatch.setitem(doctor_cmd.PATHS, "sentry_dir", str(tmp_path / "sentry"))
    monkeypatch.setattr(
        doctor_cmd,
        "check_asar_patch_status",
        lambda: {"exists": False, "status": "NOT_FOUND", "patches": {}, "backups": {}},
    )
    monkeypatch.setattr(
        doctor_cmd,
        "check_ant_did_status",
        lambda: {"exists": False, "uuid": None, "mode": "EPHEMERAL_OR_ABSENT"},
    )
    monkeypatch.setattr(doctor_cmd, "get_current_launcher_tz", lambda: "UTC")

    doctor_cmd.cmd_doctor(json_output=True, check_network=False)
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["asar_patch_status"] == "NOT_FOUND"
    assert payload["tracker_sinkholes"]["us5.datadoghq.com"] is True
    assert payload["tracker_sinkholes"]["sentry.io"] is False
    assert len(payload["tracker_sinkholes"]) == len(TRACKER_SINKS)
    assert "asar_internals" in payload
    assert "launcher_audit" in payload
    assert "proxy_audit" in payload


def test_audit_asar_internals_real_guarantees(tmp_path):
    app_asar = tmp_path / "app.asar"
    ion_asar = tmp_path / "ion-dist.asar"

    # 1. Hardened app.asar (no .x64.jsc, 1p unlocked, artifactAppMayRequest preserved, session-created hooked, WebRTC enforced)
    mdm_1p_block = (
        b'const m1={flatKey:"disableEssentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]}}};\n'
        b'const m2={flatKey:"disableNonessentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]}}};\n'
        b'const m3={flatKey:"disableNonessentialServices",support:{enabled:{scopes:["3p","1p"]}}};\n'
    )
    pre_js = mdm_1p_block + b'function Cde(){return!1;}\n'
    chunk_js = (
        mdm_1p_block
        + b'function g(zv,e,t){if(zv?.("evenWhenOff")?.artifactAppMayRequest?.(e)===!1)return t({cancel:!0});}\n'
        b'u.app.on("session-created",(s)=>{s.webRequest.onBeforeRequest((e,cb)=>{if(/datadoghq|api\\/v2\\/rum/.test(e.url))return cb({cancel:!0});cb({});});});\n'
        b'u.app.on("web-contents-created",(_,wc)=>{wc.setWebRTCIPHandlingPolicy("disable_non_proxied_udp");});\n'
    )
    app_asar.write_bytes(pack_asar({
        ".vite/build/index.pre.js": pre_js,
        ".vite/build/index.chunk-DqepnCaA.js": chunk_js,
    }))
    ion_asar.write_bytes(pack_asar({"assets/index.js": b"function Ect(e,t){return!0;}"}))

    res = doctor_cmd.audit_asar_internals(str(app_asar), str(ion_asar))
    assert res["compile_cache_status"] == "ABSENT"
    assert res["artifact_app_may_request_preserved"] is True
    assert res["session_created_hook_active"] is True
    assert res["webrtc_policy_enforced"] is True
    assert res["mdm_1p_unlocked"] is True
    assert res["js_syntax_ok"] is True
    assert res["ion_dist_status"] == "CLEAN_OR_STOCK"

    # 2. Stock .x64.jsc present + broken legacy Ect in ion-dist.asar -> caught!
    app_asar.write_bytes(pack_asar({
        ".vite/build/index.pre.js": pre_js,
        ".vite/build/index.chunk-DqepnCaA.js": chunk_js,
        "compile-cache/index.pre.js.x64.jsc": b"\xd6\x06\xde\xc0" + b"\x00" * 16,
    }))
    ion_asar.write_bytes(pack_asar({"assets/index.js": b"function Ect(e,t){return/*clp_drop*/!1;}"}))
    res_bad = doctor_cmd.audit_asar_internals(str(app_asar), str(ion_asar))
    assert res_bad["compile_cache_status"] == "ACTIVE_STOCK_BYTECODE"
    assert res_bad["ion_dist_status"] == "BROKEN_LEGACY_ECT_PATCH"


def test_audit_launcher_flags_and_artifacts_and_proxy_tz(tmp_path, monkeypatch):
    launcher = tmp_path / "claude-privacy"
    launcher.write_text("#!/bin/bash\nexec /bin/true --disable-webrtc --disable-quic --proxy-server=http://127.0.0.1:10808\n", encoding="utf-8")
    la = doctor_cmd.audit_launcher_flags(str(launcher))
    assert la["exists"] is True
    assert "--disable-webrtc" in la["dead_flags_found"]
    assert la["proxy_flag_configured"] is True

    # Cookies & sentry/session.json (counts only, no values)
    claude_dir = tmp_path / "Claude"
    sentry_dir = claude_dir / "sentry"
    sentry_dir.mkdir(parents=True)
    (sentry_dir / "session.json").write_text('{"sid":"test"}', encoding="utf-8")
    (claude_dir / "Preferences").write_text(json.dumps({"webrtc": {"ip_handling_policy": "disable_non_proxied_udp"}}), encoding="utf-8")

    cookies_db = claude_dir / "Cookies"
    conn = sqlite3.connect(str(cookies_db))
    conn.execute("CREATE TABLE cookies (name TEXT, value TEXT)")
    conn.execute("INSERT INTO cookies VALUES ('_dd_s_v2', 'secret-val-never-logged')")
    conn.execute("INSERT INTO cookies VALUES ('anthropic-device-id', 'secret-did')")
    conn.commit()
    conn.close()

    monkeypatch.setitem(doctor_cmd.PATHS, "cookies_path", str(cookies_db))
    monkeypatch.setitem(doctor_cmd.PATHS, "sentry_dir", str(sentry_dir))
    prefs, sentry, counts = doctor_cmd.audit_preferences_and_artifacts()
    assert prefs["webrtc_policy"] == "disable_non_proxied_udp"
    assert sentry["session_exists"] is True
    assert sentry["recently_active"] is True
    assert counts["_dd_s_v2"] == 1
    assert counts["anthropic-device-id"] == 1

    # Proxy TZ mismatch detection
    monkeypatch.setattr(doctor_cmd, "check_vpn_network", lambda timeout=2.0: {"status": "success", "timezone": "Europe/Berlin", "countryCode": "DE"})
    pa = doctor_cmd.audit_proxy_and_tz("UTC", la, check_network=True)
    assert pa["hosts_bypass_warning"] is True
    assert pa["tz_consistent"] is False


def test_banner_status_never_hardcodes_hardened_and_verified(tmp_path, monkeypatch):
    fake_engine = MagicMock()
    monkeypatch.setattr(banner, "ENGINE", fake_engine)

    # 1. Unconfigured
    launcher = tmp_path / "claude-privacy"
    monkeypatch.setitem(banner.PATHS, "launcher_path", str(launcher))
    fake_engine.check_mdm_status.return_value = {p["key"]: False for p in MANAGED_POLICIES}
    fake_engine.check_launcher_status.return_value = {sw[1]: False for sw in ANTI_LEAK_SWITCHES}
    status_text, exists = banner.get_banner_status()
    assert exists is False
    assert "HARDENED & VERIFIED" not in status_text
    assert "UNCONFIGURED" in status_text

    # 2. Configured (launcher exists + all flags/MDM active) -> directs to Doctor, never claims VERIFIED
    launcher.write_text("#!/bin/bash\n", encoding="utf-8")
    fake_engine.check_mdm_status.return_value = {p["key"]: True for p in MANAGED_POLICIES}
    fake_engine.check_launcher_status.return_value = {sw[1]: True for sw in ANTI_LEAK_SWITCHES}
    status_text2, exists2 = banner.get_banner_status()
    assert exists2 is True
    assert "HARDENED & VERIFIED" not in status_text2
    assert "CONFIGURED" in status_text2
