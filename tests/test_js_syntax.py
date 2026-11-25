"""Tests for JS syntax validation hooks using `node --check` and Phase B ASAR patches."""
import os
import shutil
import pytest

from claude_patcher import asar as asar_mod
from claude_patcher.asar import apply_asar_patch, pack_asar, parse_asar, rebuild_asar
from claude_patcher.commands.doctor import audit_asar_internals
from claude_patcher.constants import SURGICAL_PATCHES, build_webrequest_iife
from claude_patcher.system import validate_js_syntax

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node binary not installed")

STOCK_BAK = "/usr/lib/claude-desktop/resources/app.asar.stock.bak"


def test_validate_js_syntax_valid_cjs_and_esm():
    ok_cjs, err_cjs = validate_js_syntax("function add(a, b) { return a + b; }\nmodule.exports = add;\n")
    assert ok_cjs is True, err_cjs

    ok_esm, err_esm = validate_js_syntax("export function add(a, b) { return a + b; }\n")
    assert ok_esm is True, err_esm


def test_validate_js_syntax_catches_unmatched_brace():
    broken = "function Ect(e,t){return/*clp_drop*/!1;}return!0}\n"
    ok, err = validate_js_syntax(broken)
    assert ok is False
    assert "SyntaxError" in err


def test_build_webrequest_iife_syntax():
    for strict in (False, True):
        ok, err = validate_js_syntax(build_webrequest_iife(strict_sift=strict) + b";")
        assert ok is True, f"strict_sift={strict}: {err}"


def test_patched_asar_js_passes_node_check(tmp_path):
    src = tmp_path / "app.asar"
    orig_js = (
        b"function run(zv, e, t) {\n"
        b'  if(zv?.("evenWhenOff")?.artifactAppMayRequest?.(e)===!1)return t({cancel:!0});\n'
        b"  return true;\n"
        b"}\n"
    )
    src.write_bytes(pack_asar({".vite/build/main.js": orig_js}))

    rebuilt = rebuild_asar(
        str(src),
        file_patches=[
            {
                "archive_path": ".vite/build/main.js",
                "stock": b'if(zv?.("evenWhenOff")?.artifactAppMayRequest?.(e)===!1)return t({cancel:!0});',
                "patched": b'if(/datadoghq|sentry\\.io/.test(e.url))return t({cancel:!0});',
                "expected_count": 1,
            }
        ],
    )
    patched_js = parse_asar(rebuilt).read_file(".vite/build/main.js")
    ok, err = validate_js_syntax(patched_js)
    assert ok is True, err


def test_all_surgical_patch_snippets_syntax():
    wrappers = {
        "sentry_startup_init": (b"", b""),
        "crashpad_sentry_start": (b"", b";"),
        "crashpad_controller_stub": (b"", b"true){}"),
        "mdm_1p_essential_pre": (b"const o={", b"}}};"),
        "mdm_1p_nonessential_pre": (b"const o={", b"}}};"),
        "mdm_1p_services_pre": (b"const o={", b"}}};"),
        "event_logging_transport": (b"", b""),
        "sentry_egress_lock": (b"let ", b";"),
        "sentry_mdm_kill_9s": (b"let ", b";"),
        "nonessential_services_guard": (b"function f(){", b"}"),
        "xfs_1p_unlock": (b"", b";"),
        "growthbook_header": (b"const h={", b"};"),
        "mdm_1p_essential_chunk": (b"const o={", b"}}};"),
        "mdm_1p_nonessential_chunk": (b"const o={", b"}}};"),
        "mdm_1p_services_chunk": (b"const o={", b"}}};"),
        "electron_webrequest_firewall": (b"", b";"),
        "preload_sentry_main": (b"function f(){return ", b"}"),
        "preload_sentry_quick": (b"function f(){return ", b"}"),
        "preload_sentry_about": (b"function f(){return ", b"}"),
        "preload_sentry_find": (b"function f(){return ", b"}"),
    }
    for patch in SURGICAL_PATCHES:
        pid = patch["id"]
        pre, post = wrappers[pid]
        ok, err = validate_js_syntax(pre + patch["patched"] + post)
        assert ok is True, f"{pid} failed node --check: {err}"


@pytest.mark.skipif(not os.path.isfile(STOCK_BAK), reason="stock app.asar.stock.bak not present")
def test_real_stock_app_asar_patch_and_node_check(tmp_path, monkeypatch):
    work_asar = tmp_path / "app.asar"
    work_bak = tmp_path / "app.asar.stock.bak"
    shutil.copyfile(STOCK_BAK, work_asar)
    shutil.copyfile(STOCK_BAK, work_bak)

    monkeypatch.setitem(asar_mod.PATHS, "asar_path", str(work_asar))
    monkeypatch.setitem(asar_mod.PATHS, "ion_asar_path", None)
    monkeypatch.setattr(asar_mod, "sanitize_local_telemetry_artifacts", lambda: ["ok"])

    ok, msg = apply_asar_patch()
    assert ok is True, msg

    internals = audit_asar_internals(str(work_asar), None)
    assert internals["compile_cache_status"] == "ABSENT"
    assert internals["artifact_app_may_request_preserved"] is True
    assert internals["session_created_hook_active"] is True
    assert internals["webrtc_policy_enforced"] is True
    assert internals["mdm_1p_unlocked"] is True
    assert internals["js_syntax_ok"] is True, internals["js_syntax_errors"]
