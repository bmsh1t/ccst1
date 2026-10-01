from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

import yaml

from artifact_io import write_json_atomic
from repo_scan_models import RepoFinding

UNTRUSTED_EVENTS = {"pull_request", "pull_request_target", "issue_comment"}
SHA_PIN_RE = re.compile(r"^[0-9a-f]{40}$")
UNSAFE_CONTEXT_RE = re.compile(
    r"\${{\s*github\.event\.(pull_request|issue|comment)\.(title|body|head\.ref|head\.label)\s*}}"
)
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


def _event_names(raw_on) -> set[str]:
    if isinstance(raw_on, str):
        return {raw_on}
    if raw_on is None:
        return set()
    if isinstance(raw_on, list) and all(isinstance(item, str) for item in raw_on):
        return set(raw_on)
    if isinstance(raw_on, dict) and all(isinstance(name, str) for name in raw_on):
        return set(raw_on)
    raise ValueError("workflow events must be names or a mapping of event names")


def _snapshot(data: bytes, artifact_dir: Path) -> tuple[str, str]:
    """Keep exact source bytes before parsing or temporary-clone cleanup."""
    digest = hashlib.sha256(data).hexdigest()
    directory = artifact_dir / "repo_workflows"
    if directory.resolve() != directory:
        raise ValueError("workflow artifact directory must not traverse symlinks")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest}.yaml"
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes() != data)):
        raise ValueError("existing workflow snapshot differs from its content identity")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=directory, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise ValueError("workflow snapshot changed during publication")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path.relative_to(artifact_dir).as_posix(), digest


def _job_candidates(text: str, relative_path: str, binding: dict) -> tuple[list[RepoFinding], list[str]]:
    loader = yaml.SafeLoader(text)
    try:
        node = loader.get_single_node()
        workflow = loader.construct_document(node) if node else {}
        if not isinstance(workflow, dict):
            raise ValueError("workflow must be a mapping")
        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            raise ValueError("workflow jobs must be a mapping")
        jobs_node = next((v for k, v in node.value if k.value == "jobs"), None) if node else None
        job_lines = {loader.construct_object(k): v.start_mark.line + 1 for k, v in jobs_node.value} if isinstance(jobs_node, yaml.MappingNode) else {}
    finally:
        loader.dispose()
    events = _event_names(workflow.get("on", workflow.get(True)))
    findings, errors = [], []
    for job_name, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("steps", []), list):
            errors.append(f"invalid job/steps structure: {job_name}")
            continue
        steps = job.get("steps", [])
        if any(not isinstance(step, dict) for step in steps):
            errors.append(f"workflow steps must be mappings: {job_name}")
            continue
        if any(step.get(key) is not None and not isinstance(step[key], str)
               for step in steps for key in ("uses", "run")):
            errors.append(f"uses/run must be strings: {job_name}")
            continue
        uses = [step.get("uses") or "" for step in steps]
        runs = [step.get("run") or "" for step in steps]
        labels = job.get("runs-on", [])
        labels = labels if isinstance(labels, list) else [labels]
        unpinned = [value for value in uses if value and not value.startswith(("actions/", "docker://", "./"))
                    and "@" in value and not SHA_PIN_RE.fullmatch(value.split("@", 1)[1])]
        observations = [
            ("pull-request-target-checkout", "pull_request_target and checkout occur in this workflow/job",
             "pull_request_target" in events and any(v.startswith("actions/checkout@") for v in uses)),
            ("self-hosted-untrusted-trigger", "Self-hosted runner label and externally triggered event occur together",
             "self-hosted" in labels and bool(events & UNTRUSTED_EVENTS)),
            ("unsafe-user-input-in-run", "Event context expression appears directly in a run step",
             any(UNSAFE_CONTEXT_RE.search(value) for value in runs)),
            ("unpinned-third-party-action", "Action references without full commit SHA pinning are present", bool(unpinned)),
        ]
        for rule, title, present in observations:
            if present:
                findings.append(RepoFinding(
                    rule_id=rule, category="ci", severity="unknown", confidence="unknown", source="builtin",
                    file_path=relative_path, line_number=job_lines.get(job_name), match_type="workflow-signal",
                    title=title, evidence_snippet=f"{relative_path} (job {job_name})",
                    metadata={"status": "candidate", "job": str(job_name), "events": sorted(events),
                              **binding, **({"uses": unpinned} if rule == "unpinned-third-party-action" else {})},
                ))
    return findings, errors


def scan_repo_ci(repo_path: str, *, artifact_dir: str | Path | None = None, repo_commit: str = "") -> list[RepoFinding]:
    """Collect review signals, not vulnerability verdicts; preserve every bounded workflow."""
    root = Path(repo_path).resolve()
    output = Path(artifact_dir).absolute() if artifact_dir is not None else None
    if output is not None and output.resolve() != output:
        raise ValueError("CI output must not traverse symlinks")
    records, findings = [], []
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
            record.update(status="oversized", error=f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes; not copied or scanned")
            continue
        record.update(size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        if output is not None:
            record["artifact"], _ = _snapshot(data, output)
        try:
            candidates, errors = _job_candidates(data.decode("utf-8"), relative, {
                "workflow_sha256": record["sha256"],
                **({"workflow_artifact": record["artifact"]} if output is not None else {}),
            })
            findings.extend(candidates)
            if errors:
                record.update(status="invalid", error="; ".join(errors)[:240])
        except (ValueError, yaml.YAMLError, RecursionError) as exc:
            record.update(status="invalid", error=str(exc)[:240])
    remaining = max(0, len(files) - MAX_WORKFLOW_FILES)
    partial = bool(remaining or any(row["status"] != "ok" for row in records))
    if output is not None:
        write_json_atomic(output / "repo_workflows.json", {
            "schema_version": 1, "status": "partial" if partial else "complete",
            "repo_commit": repo_commit,
            "total_files": len(files), "remaining_files": remaining,
            "deferred_paths": [p.relative_to(root).as_posix() for p in files[MAX_WORKFLOW_FILES:]],
            "workflows": records,
        })
    elif partial:
        raise ValueError("CI scan incomplete; use artifact_dir to retain per-file diagnostics and available candidates")
    return findings
