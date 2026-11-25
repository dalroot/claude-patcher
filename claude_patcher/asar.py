"""
ASAR Surgical Patcher, Binary ASAR Parser/Packer & Deep Telemetry Neutralizer.
Supports zero-byte in-place patching and full ASAR rebuilding with offset/integrity
recalculation and V8 compile-cache (*.x64.jsc) removal/invalidation.
"""
import copy
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile

from .paths import PATHS
from .constants import SURGICAL_PATCHES, build_webrequest_iife
from .sanitizer import sanitize_local_telemetry_artifacts

DEFAULT_BLOCK_SIZE = 4194304  # 4 MiB standard Electron ASAR integrity block size

_LEGACY_ION_PATCHES = (
    (b"function Ect(e,t){return/*clp_drop*/!1;                }", b"function Ect(e,t){if($st(e,lp().siftCdnHost,t))return!1;"),
    (b"sessionSampleRate:  0", b"sessionSampleRate:100"),
)


def compute_asar_integrity(data: bytes, block_size: int = DEFAULT_BLOCK_SIZE) -> dict:
    """Computes Electron ASAR SHA-256 file and block integrity metadata."""
    file_hash = hashlib.sha256(data).hexdigest()
    if not data:
        blocks = [hashlib.sha256(b"").hexdigest()]
    else:
        blocks = [
            hashlib.sha256(data[i:i + block_size]).hexdigest()
            for i in range(0, len(data), block_size)
        ]
    return {
        "algorithm": "SHA256",
        "hash": file_hash,
        "blockSize": block_size,
        "blocks": blocks,
    }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str | None:
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _write_bytes_privileged(target_path: str, data: bytes) -> None:
    """
    Atomically writes bytes to target_path using secure unique temporary files.
    Falls back to sudo cp when direct write lacks directory/file permissions.
    """
    orig_mode = 0o644
    if os.path.exists(target_path):
        orig_mode = stat.S_IMODE(os.stat(target_path).st_mode)

    target_dir = os.path.dirname(os.path.abspath(target_path)) or "."
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=target_dir, prefix=".clp_", suffix=".tmp", delete=False) as tf:
            tmp_path = tf.name
            tf.write(data)
            tf.flush()
        os.chmod(tmp_path, orig_mode)
        os.replace(tmp_path, target_path)
        tmp_path = None
    except PermissionError:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
            tmp_path = None
        with tempfile.NamedTemporaryFile(prefix="clp_", suffix=".tmp", delete=False) as tf:
            tmp_path = tf.name
            tf.write(data)
            tf.flush()
        subprocess.run(["sudo", "cp", tmp_path, target_path], check=True)
        subprocess.run(["sudo", "chmod", oct(orig_mode)[2:], target_path], check=True)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


def _copy_file_privileged(src_path: str, dst_path: str) -> None:
    """Copies src_path to dst_path preserving metadata, elevating via sudo on PermissionError."""
    try:
        shutil.copy2(src_path, dst_path)
    except PermissionError:
        subprocess.run(["sudo", "cp", "-p", src_path, dst_path], check=True)


def _count_disjoint(buf: bytes, stock: bytes, patched: bytes) -> tuple[int, int]:
    """
    Counts non-overlapping occurrences of stock and patched in buf.
    Handles empty patched/stock and substring overlap safely without infinite loops.
    """
    if not stock or not patched or (stock not in patched and patched not in stock):
        return (buf.count(stock) if stock else 0), (buf.count(patched) if patched else 0)

    stock_cnt = 0
    patched_cnt = 0
    idx = 0
    n = len(buf)
    prefer_patched = len(patched) >= len(stock)
    while idx < n:
        if prefer_patched:
            if buf.startswith(patched, idx):
                patched_cnt += 1
                idx += len(patched)
                continue
            if buf.startswith(stock, idx):
                stock_cnt += 1
                idx += len(stock)
                continue
        else:
            if buf.startswith(stock, idx):
                stock_cnt += 1
                idx += len(stock)
                continue
            if buf.startswith(patched, idx):
                patched_cnt += 1
                idx += len(patched)
                continue
        idx += 1
    return stock_cnt, patched_cnt


def _replace_stock_only(buf: bytes | bytearray, stock: bytes, patched: bytes) -> bytearray:
    """Replaces stock with patched without disturbing already-patched occurrences."""
    if not stock or not patched or stock not in patched:
        return bytearray(bytes(buf).replace(stock, patched) if stock else buf)

    out = bytearray()
    idx = 0
    n = len(buf)
    raw = bytes(buf)
    while idx < n:
        if raw.startswith(patched, idx):
            out.extend(patched)
            idx += len(patched)
        elif raw.startswith(stock, idx):
            out.extend(patched)
            idx += len(stock)
        else:
            out.append(raw[idx])
            idx += 1
    return out


class AsarArchive:
    """
    In-memory Electron ASAR archive parser, editor, and packer.
    Preserves directory hierarchy, executable/unpacked/link attributes, and recalculates
    offsets, sizes, and SHA-256 block integrity hashes upon serialization.
    """

    def __init__(self, header: dict | None = None, files: dict[str, bytes] | None = None):
        self.header = header if header is not None else {"files": {}}
        self.files = files if files is not None else {}

    @staticmethod
    def _normalize_path(archive_path: str) -> str:
        norm = archive_path.replace("\\", "/").strip("/")
        if not norm or ".." in norm.split("/"):
            raise ValueError(f"Invalid ASAR archive path: {archive_path!r}")
        return norm

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AsarArchive":
        """Parses a binary ASAR buffer into an AsarArchive instance."""
        if len(raw) < 16:
            raise ValueError("Invalid ASAR archive: buffer smaller than 16-byte header")

        u1, header_size, u2, json_len = struct.unpack("<IIII", raw[:16])
        if u1 != 4 or header_size < 8 or u2 != header_size - 4:
            raise ValueError(
                f"Invalid ASAR pickle header: u1={u1}, header_size={header_size}, u2={u2}"
            )
        if json_len > u2 - 4:
            raise ValueError(f"Invalid ASAR JSON length {json_len} exceeds pickle size {u2 - 4}")

        payload_offset = 8 + header_size
        if payload_offset > len(raw):
            raise ValueError("Invalid ASAR archive: header exceeds file length")

        try:
            header = json.loads(raw[16:16 + json_len].decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Malformed ASAR JSON header: {exc}") from exc

        if not isinstance(header, dict) or "files" not in header:
            raise ValueError("Invalid ASAR JSON header: missing root 'files' object")

        files: dict[str, bytes] = {}

        def _walk(node: dict, prefix: str = "") -> None:
            for name, entry in node.get("files", {}).items():
                rel = f"{prefix}/{name}" if prefix else name
                if "files" in entry:
                    _walk(entry, rel)
                elif not entry.get("unpacked") and "link" not in entry:
                    off = int(entry["offset"])
                    size = int(entry["size"])
                    start = payload_offset + off
                    end = start + size
                    if end > len(raw):
                        raise ValueError(f"ASAR entry {rel!r} exceeds archive bounds ({end} > {len(raw)})")
                    files[rel] = raw[start:end]

        _walk(header)
        return cls(header=header, files=files)

    @classmethod
    def from_file(cls, path: str) -> "AsarArchive":
        """Reads and parses an ASAR archive from disk."""
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    def list_files(self, include_unpacked: bool = False) -> list[str]:
        """Returns sorted list of file paths inside the archive."""
        out: list[str] = []

        def _walk(node: dict, prefix: str = "") -> None:
            for name, entry in node.get("files", {}).items():
                rel = f"{prefix}/{name}" if prefix else name
                if "files" in entry:
                    _walk(entry, rel)
                elif include_unpacked or not entry.get("unpacked"):
                    out.append(rel)

        _walk(self.header)
        return sorted(out)

    def _get_entry(self, archive_path: str) -> tuple[dict, str, dict]:
        norm = self._normalize_path(archive_path)
        parts = norm.split("/")
        node = self.header
        for part in parts[:-1]:
            children = node.get("files", {})
            if part not in children or "files" not in children[part]:
                raise KeyError(archive_path)
            node = children[part]
        leaf = parts[-1]
        children = node.get("files", {})
        if leaf not in children or "files" in children[leaf]:
            raise KeyError(archive_path)
        return node, leaf, children[leaf]

    def has_file(self, archive_path: str) -> bool:
        """Returns True if archive_path exists as a file entry in the archive."""
        try:
            self._get_entry(archive_path)
            return True
        except (KeyError, ValueError):
            return False

    def read_file(self, archive_path: str) -> bytes:
        """Returns raw bytes for a packed file inside the archive."""
        norm = self._normalize_path(archive_path)
        if norm not in self.files:
            raise KeyError(archive_path)
        return self.files[norm]

    def write_file(self, archive_path: str, data: bytes, executable: bool | None = None) -> None:
        """Adds or overwrites a packed file entry in the archive."""
        norm = self._normalize_path(archive_path)
        parts = norm.split("/")
        node = self.header
        for part in parts[:-1]:
            children = node.setdefault("files", {})
            if part not in children or "files" not in children[part]:
                children[part] = {"files": {}}
            node = children[part]

        children = node.setdefault("files", {})
        leaf = parts[-1]
        entry = children.get(leaf)
        if not isinstance(entry, dict) or "files" in entry:
            entry = {}
            children[leaf] = entry
        entry.pop("unpacked", None)
        entry.pop("link", None)
        if executable is True:
            entry["executable"] = True
        elif executable is False:
            entry.pop("executable", None)
        entry["size"] = len(data)
        self.files[norm] = bytes(data)

    def remove_file(self, archive_path: str, prune_empty_dirs: bool = True) -> bool:
        """Removes a file entry from the archive, optionally pruning empty parent directories."""
        try:
            norm = self._normalize_path(archive_path)
        except ValueError:
            return False
        parts = norm.split("/")
        trail = []
        node = self.header
        for part in parts[:-1]:
            children = node.get("files", {})
            if part not in children or "files" not in children[part]:
                return False
            trail.append((node, part))
            node = children[part]

        leaf = parts[-1]
        children = node.get("files", {})
        if leaf not in children or "files" in children[leaf]:
            return False

        del children[leaf]
        self.files.pop(norm, None)

        if prune_empty_dirs:
            for parent, dir_name in reversed(trail):
                dir_node = parent["files"].get(dir_name, {})
                if not dir_node.get("files"):
                    del parent["files"][dir_name]
                else:
                    break
        return True

    def list_compile_cache(self) -> list[str]:
        """Returns sorted list of compile-cache/*.jsc entries present in the archive."""
        return [
            p for p in self.list_files()
            if fnmatch.fnmatch(p, "compile-cache/*.jsc") or fnmatch.fnmatch(p, "compile-cache/**/*.jsc")
        ]

    def handle_compile_cache(
        self,
        mode: str = "remove",
        replacements: dict[str, bytes] | None = None,
        invalidate_bytes: bytes = b"",
    ) -> list[str]:
        """
        Manages V8 compile-cache (*.x64.jsc / *.jsc) entries inside the ASAR archive:
        - 'remove': deletes compile-cache/*.jsc entries (and prunes empty compile-cache dir).
        - 'invalidate': replaces compile-cache/*.jsc payloads with invalidate_bytes (default b'').
        - 'replace': replaces matching compile-cache entries using replacements mapping.
        Returns sorted list of affected archive paths.
        """
        if mode not in ("remove", "invalidate", "replace"):
            raise ValueError(f"Unsupported compile-cache mode: {mode!r}")

        targets = self.list_compile_cache()
        affected: list[str] = []

        if mode == "remove":
            for path in targets:
                if self.remove_file(path, prune_empty_dirs=True):
                    affected.append(path)
        elif mode == "invalidate":
            for path in targets:
                self.write_file(path, invalidate_bytes)
                affected.append(path)
        elif mode == "replace":
            repl = replacements or {}
            for path in targets:
                base = os.path.basename(path)
                if path in repl:
                    self.write_file(path, repl[path])
                    affected.append(path)
                elif base in repl:
                    self.write_file(path, repl[base])
                    affected.append(path)
            for key, payload in repl.items():
                norm = self._normalize_path(key) if "/" in key else f"compile-cache/{key}"
                if norm not in affected:
                    self.write_file(norm, payload)
                    affected.append(norm)

        return sorted(affected)

    def patch_file(
        self,
        archive_path: str,
        stock: bytes,
        patched: bytes,
        expected_count: int = 1,
        stock_regex: re.Pattern | None = None,
    ) -> int:
        """
        Applies a byte-level patch (zero-byte or length-changing) to an archive entry.
        Tracks disjoint stock/patched counts cleanly for multi-occurrence targets.
        Returns the number of newly patched occurrences.
        """
        raw = self.read_file(archive_path)
        if stock_regex is not None:
            updated, count = stock_regex.subn(lambda _m: patched, raw)
            if count != expected_count:
                raise ValueError(
                    f"Regex signature count mismatch in {archive_path!r}: "
                    f"expected {expected_count}, found {count}"
                )
            self.write_file(archive_path, updated)
            return count

        stock_cnt, patched_cnt = _count_disjoint(raw, stock, patched)

        if patched_cnt == expected_count and stock_cnt == 0:
            return 0
        if stock_cnt == 0 or stock_cnt + patched_cnt != expected_count:
            raise ValueError(
                f"Signature count mismatch in {archive_path!r}: "
                f"expected {expected_count}, found stock={stock_cnt}, patched={patched_cnt}"
            )

        updated = bytes(_replace_stock_only(raw, stock, patched))
        self.write_file(archive_path, updated)
        return stock_cnt

    def to_bytes(self, recompute_integrity: bool = True) -> bytes:
        """Serializes the archive into standard Electron ASAR binary format."""
        out_header = copy.deepcopy(self.header)
        chunks: list[bytes] = []
        offset = 0

        def _pack_walk(node: dict, prefix: str = "") -> None:
            nonlocal offset
            for name, entry in node.get("files", {}).items():
                rel = f"{prefix}/{name}" if prefix else name
                if "files" in entry:
                    _pack_walk(entry, rel)
                elif entry.get("unpacked") or "link" in entry:
                    continue
                else:
                    data = self.files.get(rel, b"")
                    entry["size"] = len(data)
                    entry["offset"] = str(offset)
                    if recompute_integrity:
                        entry["integrity"] = compute_asar_integrity(data)
                    chunks.append(data)
                    offset += len(data)

        _pack_walk(out_header)

        json_bytes = json.dumps(out_header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        json_len = len(json_bytes)
        pad_len = (4 - (json_len % 4)) % 4
        u2 = 4 + json_len + pad_len
        header_size = 4 + u2
        pickle_header = struct.pack("<IIII", 4, header_size, u2, json_len) + json_bytes + (b"\x00" * pad_len)
        return pickle_header + b"".join(chunks)

    def write_to(self, target_path: str, recompute_integrity: bool = True) -> None:
        """Serializes and atomically writes the ASAR archive to target_path."""
        _write_bytes_privileged(target_path, self.to_bytes(recompute_integrity=recompute_integrity))


def parse_asar(path_or_bytes: str | bytes | bytearray) -> AsarArchive:
    """Parses an ASAR archive from a file path or raw bytes."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        return AsarArchive.from_bytes(bytes(path_or_bytes))
    return AsarArchive.from_file(path_or_bytes)


def pack_asar(
    files: dict[str, bytes],
    recompute_integrity: bool = True,
    executable_paths: set[str] | None = None,
) -> bytes:
    """Packs a mapping of {archive_path: bytes} into a binary ASAR buffer."""
    archive = AsarArchive()
    exec_set = {AsarArchive._normalize_path(p) for p in (executable_paths or set())}
    for path in sorted(files):
        norm = AsarArchive._normalize_path(path)
        archive.write_file(norm, files[path], executable=(True if norm in exec_set else None))
    return archive.to_bytes(recompute_integrity=recompute_integrity)


def rebuild_asar(
    source_path: str,
    target_path: str | None = None,
    file_replacements: dict[str, bytes] | None = None,
    file_patches: list[dict] | None = None,
    compile_cache_mode: str | None = None,
    compile_cache_replacements: dict[str, bytes] | None = None,
    recompute_integrity: bool = True,
) -> bytes:
    """
    Rebuilds an ASAR archive with optional file replacements, length-changing patches,
    and V8 compile-cache (*.x64.jsc) removal/invalidation/replacement.
    """
    archive = AsarArchive.from_file(source_path)

    for path, content in (file_replacements or {}).items():
        archive.write_file(path, content)

    for patch in (file_patches or []):
        archive.patch_file(
            patch["archive_path"],
            patch["stock"],
            patch["patched"],
            expected_count=patch.get("expected_count", 1),
            stock_regex=patch.get("stock_regex"),
        )

    if compile_cache_mode:
        archive.handle_compile_cache(mode=compile_cache_mode, replacements=compile_cache_replacements)

    rebuilt = archive.to_bytes(recompute_integrity=recompute_integrity)
    if target_path:
        _write_bytes_privileged(target_path, rebuilt)
    return rebuilt


def _has_any_patch_markers(data: bytes, patches: list[dict]) -> bool:
    for p in patches:
        marker = p.get("check_marker") or p["patched"]
        if marker in data:
            return True
    return b"/*clp" in data or b"__clpWebReqInstalled" in data


def _extract_asar_version(data: bytes) -> str | None:
    try:
        archive = AsarArchive.from_bytes(data)
        if archive.has_file("package.json"):
            pkg = json.loads(archive.read_file("package.json").decode("utf-8"))
            return pkg.get("version")
    except Exception:
        pass
    return None


def _read_stock_meta(meta_path: str) -> dict:
    if not os.path.isfile(meta_path):
        return {}
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_stock_meta(meta_path: str, meta: dict) -> None:
    payload = (json.dumps(meta, indent=2) + "\n").encode("utf-8")
    try:
        _write_bytes_privileged(meta_path, payload)
    except Exception:
        pass


def _ensure_fresh_stock_backup(fpath: str, patches: list[dict]) -> tuple[bool, str]:
    """
    Ensures <fpath>.stock.bak exists and matches the current upstream stock version.
    Refreshes stale .stock.bak automatically when upstream updates overwrite fpath with
    a new unpatched ASAR.
    """
    bak_path = fpath + ".stock.bak"
    meta_path = fpath + ".stock.meta.json"

    if not os.path.exists(bak_path):
        _copy_file_privileged(fpath, bak_path)
        with open(fpath, "rb") as f:
            cur_data = f.read()
        _write_stock_meta(meta_path, {
            "stock_sha256": _sha256_bytes(cur_data),
            "app_version": _extract_asar_version(cur_data),
        })
        return True, "created"

    cur_sha = _sha256_file(fpath)
    bak_sha = _sha256_file(bak_path)
    if cur_sha == bak_sha:
        return False, "up_to_date"

    meta = _read_stock_meta(meta_path)
    if meta.get("patched_sha256") == cur_sha:
        return False, "up_to_date"

    with open(fpath, "rb") as f:
        cur_data = f.read()

    if not _has_any_patch_markers(cur_data, patches):
        _copy_file_privileged(fpath, bak_path)
        _write_stock_meta(meta_path, {
            "stock_sha256": cur_sha,
            "app_version": _extract_asar_version(cur_data),
        })
        return True, "refreshed"

    return False, "up_to_date"


def _restore_legacy_ion_if_needed() -> str | None:
    """Restores ion-dist.asar to stock if legacy claude-patcher patches are detected."""
    ion_path = PATHS.get("ion_asar_path")
    if not ion_path or not os.path.exists(ion_path):
        return None
    ion_bak = ion_path + ".stock.bak"
    with open(ion_path, "rb") as f:
        ion_bytes = f.read()
    has_legacy = any(patched in ion_bytes for patched, _ in _LEGACY_ION_PATCHES)
    if not has_legacy:
        return None
    if os.path.exists(ion_bak):
        _copy_file_privileged(ion_bak, ion_path)
        return "Restored ion-dist.asar to stock from backup"
    modified = bytearray(ion_bytes)
    for patched, stock in _LEGACY_ION_PATCHES:
        modified = _replace_stock_only(modified, patched, stock)
    _write_bytes_privileged(ion_path, bytes(modified))
    return "Reverted legacy ion-dist.asar patches to stock"


def check_asar_patch_status():
    """
    Audits app.asar (including V8 compile-cache status, session-created hook,
    artifactAppMayRequest preservation, and 1p MDM unlock) and ion-dist.asar stock status.
    """
    report = {
        "exists": False,
        "status": "NOT_FOUND",
        "backup_exists": False,
        "backup_stale": False,
        "compile_cache_status": "UNKNOWN",
        "compile_cache_count": None,
        "session_created_hook": False,
        "artifact_guard_preserved": False,
        "ion_status": "NOT_FOUND",
        "integrity_enforced": PATHS.get("asar_integrity_enforced"),
        "integrity_warning": PATHS.get("asar_integrity_warning"),
        "patches": {},
        "backups": {},
    }

    asar_path = PATHS.get("asar_path")
    ion_path = PATHS.get("ion_asar_path")

    if ion_path and os.path.exists(ion_path):
        report["backups"]["ion_asar_path"] = os.path.exists(ion_path + ".stock.bak")
        try:
            with open(ion_path, "rb") as f:
                ion_data = f.read()
            if any(patched in ion_data for patched, _ in _LEGACY_ION_PATCHES):
                report["ion_status"] = "PATCHED_LEGACY"
            else:
                report["ion_status"] = "STOCK"
        except Exception:
            report["ion_status"] = "UNKNOWN"

    if not asar_path or not os.path.exists(asar_path):
        report["backups"]["asar_path"] = False
        return report

    report["exists"] = True
    bak_path = asar_path + ".stock.bak"
    report["backups"]["asar_path"] = os.path.exists(bak_path)
    report["backup_exists"] = report["backups"]["asar_path"]

    try:
        with open(asar_path, "rb") as f:
            raw_bytes = f.read()
        archive = AsarArchive.from_bytes(raw_bytes)
    except Exception:
        report["status"] = "UNKNOWN"
        return report

    if report["backup_exists"] and _sha256_bytes(raw_bytes) != _sha256_file(bak_path):
        if not _has_any_patch_markers(raw_bytes, SURGICAL_PATCHES):
            report["backup_stale"] = True

    jsc_files = archive.list_compile_cache()
    report["compile_cache_count"] = len(jsc_files)
    report["compile_cache_status"] = "REMOVED" if len(jsc_files) == 0 else "PRESENT"

    chunk_path = ".vite/build/index.chunk-DqepnCaA.js"
    if archive.has_file(chunk_path):
        chunk_data = archive.read_file(chunk_path)
        report["session_created_hook"] = b"__clpWebReqInstalled" in chunk_data
        report["artifact_guard_preserved"] = b"artifactAppMayRequest" in chunk_data

    total = len(SURGICAL_PATCHES)
    neutralized_count = 0
    stock_count = 0
    has_partial = False

    for p in SURGICAL_PATCHES:
        pid = p["id"]
        apath = p.get("archive_path")
        if not apath or not archive.has_file(apath):
            report["patches"][pid] = {"status": "FILE_NOT_FOUND", "name": p["name"], "file": asar_path}
            continue

        data = archive.read_file(apath)
        exp_count = p.get("expected_count", 1)
        marker = p.get("check_marker") or p["patched"]
        stock_regex = p.get("stock_regex")

        if stock_regex is not None:
            stock_matches = len(stock_regex.findall(data))
            if stock_matches == 0 and marker in data:
                report["patches"][pid] = {"status": "NEUTRALIZED", "name": p["name"], "file": asar_path}
                neutralized_count += 1
            elif stock_matches >= exp_count:
                report["patches"][pid] = {"status": "STOCK", "name": p["name"], "file": asar_path}
                stock_count += 1
            else:
                report["patches"][pid] = {"status": "UNKNOWN", "name": p["name"], "file": asar_path}
            continue

        stock_cnt, patched_cnt = _count_disjoint(data, p["stock"], marker)
        if p.get("check_marker"):
            if patched_cnt >= exp_count:
                report["patches"][pid] = {"status": "NEUTRALIZED", "name": p["name"], "file": asar_path}
                neutralized_count += 1
            elif stock_cnt >= exp_count:
                report["patches"][pid] = {"status": "STOCK", "name": p["name"], "file": asar_path}
                stock_count += 1
            else:
                report["patches"][pid] = {"status": "UNKNOWN", "name": p["name"], "file": asar_path}
        elif patched_cnt >= exp_count and stock_cnt == 0:
            report["patches"][pid] = {"status": "NEUTRALIZED", "name": p["name"], "file": asar_path}
            neutralized_count += 1
        elif stock_cnt >= exp_count and patched_cnt == 0:
            report["patches"][pid] = {"status": "STOCK", "name": p["name"], "file": asar_path}
            stock_count += 1
        elif patched_cnt > 0:
            report["patches"][pid] = {"status": "PARTIAL", "name": p["name"], "file": asar_path}
            has_partial = True
        else:
            report["patches"][pid] = {"status": "UNKNOWN", "name": p["name"], "file": asar_path}

    if neutralized_count == total:
        report["status"] = "NEUTRALIZED"
    elif neutralized_count > 0 or has_partial:
        report["status"] = "PARTIALLY_PATCHED"
    elif stock_count == total:
        report["status"] = "STOCK"
    else:
        report["status"] = "UNKNOWN"

    return report


def apply_asar_patch(force: bool = False, strict_sift: bool = False):
    """
    Rebuilds app.asar from pristine stock backup with all Phase B telemetry/MDM/webRequest
    patches, removes compile-cache/*.x64.jsc, recomputes ASAR integrity blocks, and restores
    ion-dist.asar to stock if legacy patches were present.
    """
    if PATHS.get("asar_integrity_enforced") and not force:
        return False, (
            PATHS.get("asar_integrity_warning")
            or "Electron EnableEmbeddedAsarIntegrityValidation is enforced on this platform; aborting ASAR modification."
        )

    asar_path = PATHS.get("asar_path")
    if not asar_path or not os.path.exists(asar_path):
        return False, "Target app.asar not found on this system"

    notes = []

    # Heal legacy broken ion-dist.asar patches if present
    ion_msg = _restore_legacy_ion_if_needed()
    if ion_msg:
        notes.append(ion_msg)

    # Ensure pristine stock backup exists and is fresh across upstream updates
    changed, reason = _ensure_fresh_stock_backup(asar_path, SURGICAL_PATCHES)
    if changed and reason == "refreshed":
        notes.append("Refreshed stale backup for app.asar")

    bak_path = asar_path + ".stock.bak"
    source_path = bak_path if os.path.exists(bak_path) else asar_path

    try:
        archive = AsarArchive.from_file(source_path)
        for p in SURGICAL_PATCHES:
            apath = p["archive_path"]
            patched_bytes = (
                build_webrequest_iife(strict_sift=strict_sift) + b',u.app.on("session-created",(e=>aOe(e)))'
                if p["id"] == "electron_webrequest_firewall"
                else p["patched"]
            )
            archive.patch_file(
                apath,
                p["stock"],
                patched_bytes,
                expected_count=p.get("expected_count", 1),
                stock_regex=p.get("stock_regex"),
            )

        removed_jsc = archive.handle_compile_cache(mode="remove")
        if removed_jsc:
            notes.append(f"Removed {len(removed_jsc)} V8 compile-cache (.jsc) file(s)")

        out_bytes = archive.to_bytes(recompute_integrity=True)
        _write_bytes_privileged(asar_path, out_bytes)

        meta_path = asar_path + ".stock.meta.json"
        meta = _read_stock_meta(meta_path)
        meta["stock_sha256"] = _sha256_file(bak_path)
        meta["patched_sha256"] = _sha256_bytes(out_bytes)
        meta["app_version"] = meta.get("app_version") or _extract_asar_version(out_bytes)
        meta["strict_sift"] = strict_sift
        _write_stock_meta(meta_path, meta)
    except Exception as e:
        return False, f"ASAR rebuild failed: {e}"

    san_logs = sanitize_local_telemetry_artifacts()
    notes.extend(san_logs)
    suffix = (" " + "; ".join(notes) + ".") if notes else ""
    return True, f"Rebuilt app.asar with {len(SURGICAL_PATCHES)} verified patches & SHA-256 integrity.{suffix}"


def rollback_asar_patch():
    """Restores stock app.asar (and ion-dist.asar if modified) from pristine backups."""
    targets = [p for p in (PATHS.get("asar_path"), PATHS.get("ion_asar_path")) if p and os.path.exists(p)]
    if not targets:
        return False, "Target ASAR files not found on this system"

    restored = []
    for fpath in targets:
        bak_path = fpath + ".stock.bak"
        if os.path.exists(bak_path):
            with open(fpath, "rb") as f:
                cur_data = f.read()
            cur_sha = _sha256_bytes(cur_data)
            bak_sha = _sha256_file(bak_path)
            if cur_sha == bak_sha:
                restored.append(os.path.basename(fpath) + " (already stock)")
                continue
            if fpath == PATHS.get("asar_path") and not _has_any_patch_markers(cur_data, SURGICAL_PATCHES):
                restored.append(os.path.basename(fpath) + " (already stock)")
                continue
            try:
                shutil.copy2(bak_path, fpath)
                restored.append(os.path.basename(fpath))
            except PermissionError:
                subprocess.run(["sudo", "cp", "-p", bak_path, fpath], check=True)
                restored.append(os.path.basename(fpath) + " (sudo)")
        else:
            if fpath == PATHS.get("ion_asar_path"):
                with open(fpath, "rb") as f:
                    content = f.read()
                modified = bytearray(content)
                for patched, stock in _LEGACY_ION_PATCHES:
                    modified = _replace_stock_only(modified, patched, stock)
                if modified != content:
                    _write_bytes_privileged(fpath, bytes(modified))
                    restored.append(os.path.basename(fpath) + " (reverted)")
                else:
                    restored.append(os.path.basename(fpath) + " (already stock)")
            else:
                restored.append(os.path.basename(fpath) + " (no backup)")

    return True, f"Restored {', '.join(restored)} to factory stock state"
