"""Read-only historical origins resolved through the active migration receipt."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

try:
    from tools.migration_receipts import (read_active_receipt, read_bound_file,
        read_legacy_archive, pattern_archive_relative, receipt_lock)
    from tools.target_memory_schema import normalize_target_memory, TARGET_MEMORY_LIST_FIELDS
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from migration_receipts import (read_active_receipt, read_bound_file,
        read_legacy_archive, pattern_archive_relative, receipt_lock)
    from target_memory_schema import normalize_target_memory, TARGET_MEMORY_LIST_FIELDS
    from target_paths import canonical_target_value, target_storage_key

SOURCE_FIELDS = frozenset({"owner", "record_id", "version", "content_sha256"})


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def validate_source(source):
    if not isinstance(source, dict) or set(source) != SOURCE_FIELDS | {"purpose"}:
        raise ValueError("history source requires owner/record_id/version/content_sha256/purpose")
    if source["owner"] != "history" or source["purpose"] != "origin":
        raise ValueError("history sources are unverified origins, never basis or claim support")
    if (not isinstance(source["record_id"], str) or not source["record_id"].strip()
            or source["record_id"] != source["record_id"].strip() or "\x00" in source["record_id"]):
        raise ValueError("invalid history source record_id")
    for field in ("version", "content_sha256"):
        if not isinstance(source[field], str) or not re.fullmatch(r"[0-9a-f]{64}", source[field]):
            raise ValueError(f"history source {field} must be a SHA256 string")


def _stamp(path, *, directory=False):
    info = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("history source has a symlink or non-regular path component")
    identity = (info.st_dev, info.st_ino, info.st_mode)
    return identity if directory else (*identity, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def check_capture(capture):
    """Revalidate identities only; never parse or hash under the Store write lock."""
    for path, stamp in capture["directories"].items():
        if _stamp(path, directory=True) != stamp:
            raise ValueError("history source directory changed; reload and retry")
    for path, stamp in capture["files"].items():
        if _stamp(path) != stamp:
            raise ValueError("history source changed; reload and retry")


def _select_memory(payload, item, target):
    normalize_target_memory(payload, expected_target=target)
    field, position = item.get("field"), item.get("position")
    if field in TARGET_MEMORY_LIST_FIELDS:
        values = payload.get(field)
        if not isinstance(values, list) or type(position) is not int or not 0 <= position < len(values):
            raise ValueError("invalid historical memory list selector")
        record = values[position]
    elif field == "facts":
        if not isinstance(position, str) or position not in payload.get("facts", {}):
            raise ValueError("invalid historical memory fact selector")
        record = payload["facts"][position]
    elif field == "active_goal" and position == "value" and isinstance(payload.get(field), str):
        record = payload[field]
    else:
        raise ValueError("invalid historical memory selector")
    if isinstance(record, dict) and "target" in record:
        if not isinstance(record["target"], str) or canonical_target_value(record["target"]) != target:
            raise ValueError("historical memory record belongs to another target")
    return {"field": field, "position": position}, record, _digest(record)


def capture_source(repo_root, target, store_id, experience_id):
    """Capture only an explicitly mapped original; absence never searches live files."""
    result = {"status": "unavailable", "availability": "unavailable", "verification": "unverified",
              "files": {}, "directories": {}, "byte_digests": {}}
    try:
        root = Path(repo_root).absolute()
        with receipt_lock(root, target) as receipt_path:
            def read_bytes(path):
                path = Path(path).absolute()
                for parent in path.parents:
                    stamp = _stamp(parent, directory=True)
                    previous = result["directories"].setdefault(parent, stamp)
                    if previous != stamp:
                        raise ValueError("history directory changed during capture")
                before = _stamp(path)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as handle:
                    raw = handle.read()
                if _stamp(path) != before or result["files"].setdefault(path, before) != before:
                    raise ValueError("history source changed during capture")
                digest = hashlib.sha256(raw).hexdigest()
                if result["byte_digests"].setdefault(path, digest) != digest:
                    raise ValueError("history source bytes changed during capture")
                return raw

            receipt, manifest, manifest_hash = read_active_receipt(
                receipt_path, target=target, store_id=store_id, read_bytes=read_bytes)
            matches = []
            for kind in ("memory", "pattern"):
                backfill = receipt.get(f"{kind}_backfill")
                if backfill is None:
                    continue
                if isinstance(backfill, dict) and backfill.get("status") == "pending" and "experience_map" not in backfill:
                    continue
                if not isinstance(backfill, dict) or not isinstance(backfill.get("experience_map"), list):
                    raise ValueError("historical backfill has no valid experience map")
                for item in backfill["experience_map"]:
                    if not isinstance(item, dict):
                        raise ValueError("historical experience map contains a malformed entry")
                    if item.get("experience_id") == experience_id:
                        matches.append((kind, backfill, item))
            if len(matches) != 1:
                raise ValueError("historical experience must have exactly one active receipt mapping")
            kind, backfill, item = matches[0]
            if backfill.get("source_manifest_sha256") != manifest_hash:
                raise ValueError("historical map belongs to another source manifest")
            relative = item.get("source_path")
            if kind == "memory":
                if relative != f"memory/goals/targets/{target_storage_key(target)}.json":
                    raise ValueError("historical memory source path does not belong to target")
                files = [entry for entry in manifest["files"] if entry["path"] == relative]
                if len(files) != 1 or backfill.get("source_sha256") != files[0]["sha256"]:
                    raise ValueError("historical memory file binding mismatch")
                file = files[0]
                archive = read_legacy_archive(root, receipt, target=target, store_id=store_id, read_bytes=read_bytes)
                archived = [entry for entry in archive["files"] if entry.get("path") == relative]
                if len(archived) != 1 or any(archived[0].get(key) != file[key] for key in ("size", "sha256")):
                    raise ValueError("historical memory archive does not match the source manifest")
                raw = read_bound_file(root, archived[0]["archive_path"], size=file["size"],
                                      sha256=file["sha256"], read_bytes=read_bytes)
                selector, record, content_hash = _select_memory(json.loads(raw), item, target)
            else:
                files = backfill.get("source_files")
                expected_archive = pattern_archive_relative(target, files)
                if not backfill.get("archive_root"):
                    raise ValueError("PatternDB original is not archived; explicitly run target_migration.py "
                                     "--backfill-pattern-source SOURCE_ROOT with the same pinned original bytes")
                if backfill["archive_root"] != expected_archive or backfill.get("status") not in ("complete", "partial"):
                    raise ValueError("PatternDB archive locator or backfill status is invalid")
                selected = [entry for entry in files if entry["path"] == relative]
                if len(selected) != 1:
                    raise ValueError("PatternDB source file mapping is ambiguous or missing")
                file = selected[0]
                raw = read_bound_file(root, f"{expected_archive}/{relative}", size=file["size"],
                                      sha256=file["sha256"], read_bytes=read_bytes)
                line = item.get("line")
                lines = raw.split(b"\n")
                if type(line) is not int or not 1 <= line <= len(lines):
                    raise ValueError("invalid PatternDB line selector")
                raw_line = lines[line - 1]
                content_hash = hashlib.sha256(raw_line).hexdigest()
                if content_hash != item.get("source_line_sha256"):
                    raise ValueError("PatternDB source line digest mismatch")
                record = json.loads(raw_line)
                if not isinstance(record, dict) or record.get("target") != target:
                    raise ValueError("PatternDB record belongs to another target")
                selector = {"line": line}
            version = _digest({"target": target, "store_id": store_id, "source_manifest_sha256": manifest_hash,
                               "file": file, "source_kind": kind, "mapping": item, "selector": selector})
            binding = {"owner": "history", "record_id": experience_id, "version": version,
                       "content_sha256": content_hash}
            check_capture(result)
            result.update(status="available", availability="available", binding=binding,
                          detail={**binding, "source": {"target": target, "store_id": store_id,
                              "source_manifest_sha256": manifest_hash, "path": relative,
                              "sha256": file["sha256"], "size": file["size"]},
                              "source_kind": kind, "selector": selector, "record": record,
                              "availability": "available", "verification": "unverified"})
            if kind == "pattern":
                result["detail"]["raw_record"] = raw_line.decode("utf-8")
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        result.update(status="unavailable", availability="unavailable", reason=f"{type(exc).__name__}: {exc}"[:400])
    return result


def source_health(source, capture):
    status = capture["status"]
    if status == "available" and any(source.get(key) != value for key, value in capture["binding"].items()):
        return {"status": "version_changed", "availability": "available", "verification": "unverified",
                "reason": "historical mapping or original content binding changed"}
    return {"status": status, "availability": capture["availability"], "verification": "unverified",
            **({"reason": capture["reason"]} if "reason" in capture else {})}
