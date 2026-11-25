"""Tests for ASAR binary parser/packer roundtrip, zero-byte & length-changing patching."""
import json
import pytest

from claude_patcher import asar as asar_mod
from claude_patcher.asar import (
    AsarArchive,
    apply_asar_patch,
    check_asar_patch_status,
    compute_asar_integrity,
    pack_asar,
    parse_asar,
    rebuild_asar,
    rollback_asar_patch,
)
from claude_patcher.constants import SURGICAL_PATCHES


def _sample_files():
    return {
        "package.json": json.dumps({"name": "claude-test", "version": "1.0.0"}).encode("utf-8"),
        ".vite/build/index.pre.js": (
            b"function init(){\n"
            b"  function Awt(){return Kf(),kwt}\n"
            b"  return Awt();\n"
            b"}\n"
        ),
        ".vite/build/bin-helper": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 17,
        "compile-cache/index.pre.js.x64.jsc": b"JSC_MAGIC_HEADER" + b"\xab" * 32,
    }


def test_asar_parser_packer_roundtrip():
    files = _sample_files()
    raw = pack_asar(files, recompute_integrity=True, executable_paths={".vite/build/bin-helper"})
    arc = parse_asar(raw)

    assert sorted(arc.list_files()) == sorted(files.keys())
    for rel_path, expected in files.items():
        assert arc.has_file(rel_path)
        assert arc.read_file(rel_path) == expected

    bin_entry = arc.header["files"][".vite"]["files"]["build"]["files"]["bin-helper"]
    assert bin_entry.get("executable") is True
    assert "integrity" in bin_entry
    assert bin_entry["integrity"] == compute_asar_integrity(files[".vite/build/bin-helper"])


def test_compute_asar_integrity_multiblock():
    data = b"A" * 10 + b"B" * 5
    integrity = compute_asar_integrity(data, block_size=10)
    assert integrity["algorithm"] == "SHA256"
    assert integrity["blockSize"] == 10
    assert len(integrity["blocks"]) == 2


def test_asar_length_changing_patch_and_rebuild(tmp_path):
    src_path = tmp_path / "app.asar"
    dst_path = tmp_path / "app.patched.asar"
    files = _sample_files()
    src_path.write_bytes(pack_asar(files, executable_paths={".vite/build/bin-helper"}))

    # Grow index.pre.js significantly so all subsequent file offsets shift
    new_js = (
        b"function init(){\n"
        b"  /* length-changing-patch-expanded-comment-for-offset-shift */\n"
        b"  function Awt(){return !1;}\n"
        b"  return Awt();\n"
        b"}\n"
    )
    assert len(new_js) > len(files[".vite/build/index.pre.js"])

    rebuilt = rebuild_asar(
        str(src_path),
        target_path=str(dst_path),
        file_replacements={".vite/build/index.pre.js": new_js},
        compile_cache_mode="remove",
    )
    arc = AsarArchive.from_bytes(rebuilt)
    assert arc.read_file(".vite/build/index.pre.js") == new_js
    assert arc.read_file("package.json") == files["package.json"]
    assert arc.read_file(".vite/build/bin-helper") == files[".vite/build/bin-helper"]
    assert not arc.has_file("compile-cache/index.pre.js.x64.jsc")

    # Also test shrinking via AsarArchive.patch_file (length-changing)
    arc.patch_file(".vite/build/index.pre.js", b"/* length-changing-patch-expanded-comment-for-offset-shift */", b"/*s*/")
    shrunk_arc = parse_asar(arc.to_bytes())
    assert b"expanded-comment" not in shrunk_arc.read_file(".vite/build/index.pre.js")
    assert shrunk_arc.read_file("package.json") == files["package.json"]


def test_asar_compile_cache_modes():
    files = _sample_files()
    arc = parse_asar(pack_asar(files))
    affected = arc.handle_compile_cache(mode="invalidate", invalidate_bytes=b"INVALID")
    assert affected == ["compile-cache/index.pre.js.x64.jsc"]
    assert arc.read_file("compile-cache/index.pre.js.x64.jsc") == b"INVALID"

    arc2 = parse_asar(pack_asar(files))
    arc2.handle_compile_cache(mode="replace", replacements={"compile-cache/index.pre.js.x64.jsc": b"NEW_JSC"})
    assert arc2.read_file("compile-cache/index.pre.js.x64.jsc") == b"NEW_JSC"


def test_apply_and_rollback_synthetic_asar(tmp_path, monkeypatch):
    app_asar = tmp_path / "app.asar"
    files_map = {"package.json": b'{"name":"claude-test","version":"6.0.0"}'}

    for p in SURGICAL_PATCHES:
        ap = p.get("archive_path")
        if not ap:
            continue
        existing = files_map.get(ap, b"")
        stock = p["stock"]
        if p["id"] == "crashpad_controller_stub":
            line = stock + b"x()){}\n"
        elif p["id"].startswith("preload_sentry_"):
            line = b"function p(){return" + stock + b"}\n"
        elif p["id"].startswith("mdm_1p_"):
            line = b"const " + p["id"].encode() + b"={" + stock + b"}}};\n"
        elif p["id"] == "growthbook_header":
            line = b"const g={" + stock + b"};\n"
        else:
            line = stock + b"\n"
        files_map[ap] = existing + line

    files_map["compile-cache/index.pre.js.x64.jsc"] = b"\xd6\x06\xde\xc0" + b"\x00" * 16
    app_bytes = pack_asar(files_map)
    app_asar.write_bytes(app_bytes)

    monkeypatch.setitem(asar_mod.PATHS, "asar_path", str(app_asar))
    monkeypatch.setitem(asar_mod.PATHS, "ion_asar_path", None)
    monkeypatch.setattr(asar_mod, "sanitize_local_telemetry_artifacts", lambda: ["sanitized-ok"])

    st_before = check_asar_patch_status()
    assert st_before["status"] == "STOCK"

    ok, msg = apply_asar_patch()
    assert ok is True, msg
    assert (tmp_path / "app.asar.stock.bak").read_bytes() == app_bytes

    rebuilt = parse_asar(app_asar.read_bytes())
    assert not rebuilt.has_file("compile-cache/index.pre.js.x64.jsc")

    st_after = check_asar_patch_status()
    assert st_after["status"] == "NEUTRALIZED"

    ok_rb, _ = rollback_asar_patch()
    assert ok_rb is True
    assert app_asar.read_bytes() == app_bytes
    assert check_asar_patch_status()["status"] == "STOCK"
