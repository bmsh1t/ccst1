"""Capture bounded GitHub Actions source bytes for native review.

Collection status describes retained files, never CI analysis or exploitability.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

try:
    from tools.artifact_io import publish_bytes_create_only, write_json_atomic
except ImportError:
    from artifact_io import publish_bytes_create_only, write_json_atomic

MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_WORKFLOW_FILES = 256


def _workflow_files(repo_path: str) -> list[Path]:
    root = Path(repo_path).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"repository path not found: {repo_path}")
    directory = root / ".github" / "workflows"
    if directory.resolve() != directory:
        raise ValueError("workflow directory must not traverse symlinks")
    if not directory.exists():
        return []
    if not directory.is_dir():
        raise ValueError("workflow location is not a directory")
    return sorted(p for p in directory.iterdir() if p.suffix.lower() in {".yml", ".yaml"})


def _snapshot(data: bytes, artifact_dir: Path) -> tuple[str, str]:
    digest = hashlib.sha256(data).hexdigest()
    directory = artifact_dir / "repo_workflows"
    if directory.resolve() != directory:
        raise ValueError("workflow artifact directory must not traverse symlinks")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{digest}.yaml"
    publish_bytes_create_only(path, data)
    return path.relative_to(artifact_dir).as_posix(), digest


def capture_repo_workflows(
    repo_path: str, *, artifact_dir: str | Path, repo_commit: str = ""
) -> dict:
    """Preserve workflow files without parsing jobs, selecting rules or running code."""
    root = Path(repo_path).resolve()
    output = Path(artifact_dir).absolute()
    if output.resolve() != output:
        raise ValueError("workflow output must not traverse symlinks")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    records = []
    try:
        files = _workflow_files(repo_path)
    except (OSError, ValueError) as exc:
        files = []
        records.append({"file_path": ".github/workflows", "status": "unavailable", "error": str(exc)})
    for path in files[:MAX_WORKFLOW_FILES]:
        relative = path.relative_to(root).as_posix()
        record = {"file_path": relative, "status": "ok"}
        records.append(record)
        if path.is_symlink() or path.resolve() != path or not path.is_file():
            record.update(status="unavailable", error="workflow must be a regular in-repository file")
            continue
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_WORKFLOW_BYTES + 1)
        except OSError as exc:
            record.update(status="unavailable", error=str(exc))
            continue
        if len(data) > MAX_WORKFLOW_BYTES:
            record.update(status="oversized", error=f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes")
            continue
        artifact, digest = _snapshot(data, output)
        record.update(size_bytes=len(data), sha256=digest, artifact=artifact)
    remaining = max(0, len(files) - MAX_WORKFLOW_FILES)
    payload = {
        "schema_version": 1,
        "inventory_kind": "source-capture",
        "analysis_status": "not_run",
        "status": "partial" if remaining or any(r["status"] != "ok" for r in records) else "complete",
        "repo_commit": repo_commit,
        "total_files": len(files),
        "remaining_files": remaining,
        "deferred_paths": [p.relative_to(root).as_posix() for p in files[MAX_WORKFLOW_FILES:]],
        "workflows": records,
    }
    write_json_atomic(output / "repo_workflows.json", payload)
    return payload
