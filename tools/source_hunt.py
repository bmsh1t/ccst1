from __future__ import annotations

import argparse
import hashlib
import json
import stat
from pathlib import Path

try:
    from tools.repo_scan_models import RepoSourceMeta
    from tools.repo_source import MAX_REPO_SIZE_BYTES, RepoConfirmationRequired, acquire_repo_source
    from tools.repo_workflows import capture_repo_workflows
except ImportError:
    from repo_scan_models import RepoSourceMeta
    from repo_source import MAX_REPO_SIZE_BYTES, RepoConfirmationRequired, acquire_repo_source
    from repo_workflows import capture_repo_workflows
try:
    from tools.artifact_io import publish_bytes_create_only, write_text_atomic as _write_text_atomic
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import publish_bytes_create_only, write_text_atomic as _write_text_atomic


try:
    from tools.target_paths import target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent


def _exposure_dir(target: str, repo_root: str | Path | None = None) -> Path:
    root = (Path(repo_root) if repo_root is not None else BASE_DIR).resolve()
    path = root / "findings" / target_storage_key(target) / "exposure"
    if path != path.resolve():
        raise ValueError("repo-source output must not traverse symlinks")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _write_json(path: Path, payload) -> None:
    _write_text_atomic(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def capture_source_files(repo_path: str, paths: list[str], exposure_dir: Path) -> dict:
    """Capture only explicitly selected UTF-8 files, not a repository audit."""
    root = Path(repo_path).resolve()
    rows = []
    selected = list(dict.fromkeys(paths))
    for name in selected[:32]:
        row = {"file_path": name, "status": "unavailable"}
        try:
            relative = Path(name)
            path = root / relative
            if not name or relative.is_absolute() or ".." in relative.parts or path.resolve() != path:
                raise ValueError("source path must be repository-relative without symlinks")
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError("source path is not a regular file")
            with path.open("rb") as handle:
                data = handle.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError("source exceeds 1 MiB; choose a smaller existing material")
            data.decode("utf-8")
        except (OSError, ValueError) as exc:
            row["reason"] = str(exc)
            rows.append(row)
            continue
        digest = hashlib.sha256(data).hexdigest()
        directory = exposure_dir / "repo_source_files"
        if directory.resolve() != directory:
            raise ValueError("source artifact directory must not traverse symlinks")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        artifact = directory / f"{digest}.txt"
        publish_bytes_create_only(artifact, data)
        row.update(status="ok", sha256=digest, size_bytes=len(data),
                   artifact=artifact.relative_to(exposure_dir).as_posix())
        rows.append(row)
    return {"status": "partial" if len(selected) > 32 or any(r["status"] != "ok" for r in rows)
            else "complete" if selected else "not_requested",
            "files": rows, "deferred_paths": selected[32:],
            "scope": "explicit files only; deployment correspondence unknown"}


def render_repo_summary(
    meta: RepoSourceMeta,
    source_capture: dict,
    workflow_capture: dict,
) -> str:
    lines = [
        "# Repository Source Capture",
        "",
        f"- Source kind: {meta.source_kind}",
        f"- Repo URL: {meta.repo_url or '(local only)'}",
        f"- Repo path: {meta.repo_path or '(temporary clone)'}",
        f"- Repo ref: {meta.repo_ref or '(n/a)'}",
        f"- Repo commit context: {meta.repo_commit or 'unknown/non-Git'} (working-tree bytes may differ)",
        f"- Size bytes: {meta.size_bytes}",
        f"- File count: {meta.file_count}",
        f"- Probe complete: {meta.probe_complete}",
        f"- Threshold exceeded: {meta.threshold_exceeded}",
        f"- Clone performed: {meta.clone_performed}",
    ]
    if meta.threshold_reasons:
        lines.append(f"- Threshold reasons: {', '.join(meta.threshold_reasons)}")
    lines.extend([
        f"- Capture status: {meta.status}",
        f"- Selected source capture: {source_capture['status']}",
        f"- Workflow capture: {workflow_capture['status']}; remaining files: {workflow_capture['remaining_files']}",
        "- Secret scan: not_run; CI analysis: not_run",
        "- Read the retained originals natively; collection is not an audit or a clean verdict.",
        "- Source references: repo_source_meta.json/source_capture; workflow references: repo_workflows.json",
    ])
    if meta.status == "confirmation_required":
        lines.append("- Acquisition: confirmation required before clone")
    return "\n".join(lines) + "\n"


def _write_result_bundle(
    target: str,
    meta: RepoSourceMeta,
    source_capture: dict,
    workflow_capture: dict,
    *,
    repo_root: str | Path | None = None,
) -> Path:
    exposure_dir = _exposure_dir(target, repo_root)
    payload = meta.to_dict()
    payload.update(
        execution_mode="source-capture",
        source_capture=source_capture,
        secret_scan="not_run",
        ci_scan="not_run",
    )
    _write_json(exposure_dir / "repo_source_meta.json", payload)
    _write_text_atomic(
        exposure_dir / "repo_summary.md",
        render_repo_summary(meta, source_capture, workflow_capture),
    )
    return exposure_dir


def run_source_hunt(
    *,
    target: str,
    repo_url: str = "",
    repo_path: str = "",
    allow_large_repo: bool = False,
    interactive: bool = False,
    repo_root: str | Path | None = None,
    source_files: list[str] | None = None,
) -> dict:
    try:
        source_meta, resolved_repo_path, temp_dir = acquire_repo_source(
            repo_url=repo_url,
            repo_path=repo_path,
            allow_large_repo=allow_large_repo,
            interactive=interactive,
        )
    except RepoConfirmationRequired as exc:
        exc.meta.status = "confirmation_required"
        source_capture = {"status": "not_requested", "files": [], "deferred_paths": []}
        workflow_capture = {
            "schema_version": 1, "status": "not_run", "total_files": None,
            "remaining_files": None, "workflows": [],
            "inventory_kind": "source-capture", "analysis_status": "not_run",
        }
        exposure_dir = _write_result_bundle(
            target, exc.meta, source_capture, workflow_capture, repo_root=repo_root
        )
        _write_json(exposure_dir / "repo_workflows.json", workflow_capture)
        return {
            "status": "confirmation_required",
            "exposure_dir": str(exposure_dir),
            "source_meta": exc.meta.to_dict(),
        }

    try:
        exposure_dir = _exposure_dir(target, repo_root)
        source_capture = capture_source_files(resolved_repo_path, source_files or [], exposure_dir)
        workflow_capture = capture_repo_workflows(
            resolved_repo_path, artifact_dir=exposure_dir, repo_commit=source_meta.repo_commit
        )
        if workflow_capture["status"] != "complete" or source_capture["status"] == "partial":
            source_meta.status = "partial"
        exposure_dir = _write_result_bundle(
            target,
            source_meta,
            source_capture,
            workflow_capture,
            repo_root=repo_root,
        )
        return {
            "status": source_meta.status,
            "exposure_dir": str(exposure_dir),
            "source_meta": source_meta.to_dict(),
            "execution_mode": "source-capture",
            "secret_scan": "not_run",
            "ci_scan": "not_run",
            "workflow_status": workflow_capture["status"],
            "source_capture": source_capture,
        }
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Acquire and capture repository originals for native review")
    parser.add_argument("--target", required=True, help="Target/program name used under findings/<target>/")
    parser.add_argument("--repo-url", default="", help="GitHub public repo URL or owner/repo reference")
    parser.add_argument("--repo-path", default="", help="Local repository path already available on disk")
    parser.add_argument("--source-file", action="append", default=[],
                        help="Capture one repository-relative UTF-8 file (repeatable; 32 files, 1 MiB each)")
    parser.add_argument("--repo-root", default="", help="Repository root for findings output")
    parser.add_argument(
        "--allow-large-repo",
        action="store_true",
        help=f"Allow clone when the repo exceeds {MAX_REPO_SIZE_BYTES} bytes or file-count thresholds",
    )
    args = parser.parse_args(argv)

    try:
        result = run_source_hunt(
            target=args.target,
            repo_url=args.repo_url,
            repo_path=args.repo_path,
            allow_large_repo=args.allow_large_repo,
            interactive=True,
            repo_root=args.repo_root or None,
            source_files=args.source_file,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    summary_path = Path(result["exposure_dir"]) / "repo_summary.md"
    print(summary_path.read_text(encoding="utf-8"))
    if result.get("source_capture"):
        print("Selected source capture: " + result["source_capture"]["status"]
              + "; details: repo_source_meta.json/source_capture")
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
