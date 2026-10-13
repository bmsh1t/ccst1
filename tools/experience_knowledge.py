"""Read-only, byte-bound knowledge sources for target experience provenance."""
from __future__ import annotations

import fcntl
import os
import re
import stat
from pathlib import Path
from contextlib import contextmanager

try:
    from tools.knowledge_registry import KnowledgeRegistryError, load_registry, parse_knowledge_document
    from tools.knowledge_review import knowledge_path, read_published_review, sha256
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_registry import KnowledgeRegistryError, load_registry, parse_knowledge_document
    from knowledge_review import knowledge_path, read_published_review, sha256


SOURCE_FIELDS = frozenset({"owner", "record_id", "version", "content_sha256"})


def validate_source(source: dict) -> None:
    if not isinstance(source, dict) or set(source) != SOURCE_FIELDS | {"purpose"}:
        raise ValueError("knowledge source requires owner/record_id/version/content_sha256/purpose")
    if source["owner"] != "knowledge" or source["purpose"] not in ("origin", "basis"):
        raise ValueError("knowledge source purpose must be origin or basis")
    if not isinstance(source["record_id"], str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", source["record_id"]):
        raise ValueError("invalid knowledge source record_id")
    for field in ("version", "content_sha256"):
        if not isinstance(source[field], str) or not re.fullmatch(r"[0-9a-f]{64}", source[field]):
            raise ValueError(f"knowledge source {field} must be a SHA256 string")


def _stamp(path: Path) -> tuple:
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlink knowledge source refused")
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("knowledge source must be a regular file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def check_capture(capture: dict) -> None:
    """Stat-only acceptance check; no hashing or parsing in a Store write transaction."""
    for path, (stamp, _) in capture["files"].items():
        if _stamp(path) != stamp:
            raise ValueError("knowledge source changed after acquisition; reload and retry")


@contextmanager
def publication_lock(repo_root: Path):
    """Hold the publisher's shared lock across acquisition or final acceptance."""
    directory = Path(repo_root).absolute() / "knowledge"
    if any(part.is_symlink() for part in (directory, *directory.parents)):
        raise ValueError("symlink knowledge directory refused")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        yield
    finally:
        os.close(descriptor)


def capture_source(repo_root: Path, knowledge_id: str) -> dict:
    """Acquire current owner bytes under the same directory lock as publication.

    Invalid external material is a per-source diagnostic, not an empty target view.
    The byte snapshot is private to the pending command and is never persisted.
    """
    result = {"status": "unavailable", "files": {}}
    try:
        if not isinstance(knowledge_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", knowledge_id):
            raise ValueError("invalid knowledge source record_id")
        root = Path(repo_root).absolute()
        with publication_lock(root):
            def read_bytes(path):
                stamp = _stamp(path)
                raw = path.read_bytes()
                if _stamp(path) != stamp:
                    raise ValueError("knowledge source changed during acquisition")
                previous = result["files"].get(path)
                if previous is not None and previous != (stamp, raw):
                    raise ValueError("knowledge source changed during acquisition")
                result["files"][path] = (stamp, raw)
                return raw

            registry_path = knowledge_path(root, "knowledge/capabilities.yaml")
            before = read_bytes(registry_path)
            registry = load_registry(root)
            if read_bytes(registry_path) != before:
                raise ValueError("knowledge registry changed during acquisition")
            entry = next((entry for entry in registry.method_entries() if entry["id"] == knowledge_id), None)
            if entry is None:
                result.update(status="unavailable", reason="knowledge method is no longer registered")
                return result
            if entry.get("status", "active") != "active":
                result.update(status="retired", reason="knowledge method is retired")
                return result
            ref = entry["file"]
            if not ref.startswith(("knowledge/cards/", "knowledge/playbooks/", "knowledge/payloads/")):
                raise ValueError("invalid registered knowledge method path")
            raw = read_bytes(knowledge_path(root, ref))
            parsed = parse_knowledge_document(raw.decode("utf-8"))
            metadata = parsed.metadata or {}
            if parsed.frontmatter_error or metadata.get("id") != knowledge_id:
                raise ValueError(parsed.frontmatter_error or "knowledge identity differs from registry")
            if metadata.get("status", "active") != "active":
                result.update(status="retired", reason="knowledge document is not active")
                return result
            if (metadata.get("maturity") not in ("tested", "proven")
                    or entry.get("maturity", metadata.get("maturity")) not in ("tested", "proven")):
                result.update(status="review-unverified", reason="knowledge method is not tested/proven")
                return result
            review = read_published_review(root, entry, raw, read_bytes=read_bytes)
            if review["status"] != "ready":
                result.update(status=review["status"], reason=review.get("reason", "knowledge review unavailable"))
                return result
            check_capture(result)
            result.update(status="available", binding={"owner": "knowledge", "record_id": knowledge_id,
                          "version": review["sha256"], "content_sha256": sha256(raw)})
    except (KnowledgeRegistryError, OSError, UnicodeError, ValueError) as exc:
        result.update(status="unavailable", reason=f"{type(exc).__name__}: {exc}"[:240])
    return result


def source_health(source: dict, capture: dict) -> dict:
    status = capture["status"]
    if status == "available" and any(source.get(key) != value for key, value in capture["binding"].items()):
        return {"status": "version_changed", "reason": "knowledge publication version or content changed"}
    return {"status": status, **({"reason": capture["reason"]} if "reason" in capture else {})}
