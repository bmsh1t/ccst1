#!/usr/bin/env python3
"""Run an AI-selected, bounded DNS permutation and resolution lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.runtime_state import RuntimePhaseBusy, runtime_phase_lock
    from tools.target_paths import canonical_target_value, classify_target, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from runtime_state import RuntimePhaseBusy, runtime_phase_lock  # type: ignore
    from target_paths import canonical_target_value, classify_target, target_storage_key  # type: ignore


BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = 1
DEFAULT_MAX_SEEDS = 200
DEFAULT_MAX_CANDIDATES = 5_000
DEFAULT_RATE_LIMIT = 500
DEFAULT_TIMEOUT_SECONDS = 300
MAX_MAX_SEEDS = 1_000
MAX_MAX_CANDIDATES = 50_000
MAX_RATE_LIMIT = 5_000
MAX_TIMEOUT_SECONDS = 1_800


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_text(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _safe_env() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "XDG_CONFIG_HOME")
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _valid_host(value: str) -> str:
    host = value.strip().split(maxsplit=1)[0].lower().strip(".") if value.strip() else ""
    if host.startswith("*."):
        host = host[2:]
    if not host or len(host) > 253:
        return ""
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label)
        for label in labels
    ):
        return ""
    return host


def _in_scope(host: str, target: str) -> bool:
    return host == target or host.endswith(f".{target}")


def _read_scoped_hosts(path: Path, target: str, *, limit: int | None = None) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            host = _valid_host(raw)
            if not host or not _in_scope(host, target) or host in seen:
                continue
            seen.add(host)
            values.append(host)
            if limit is not None and len(values) >= limit:
                break
    return values


def _write_lines(path: Path, values: Iterable[str]) -> None:
    rows = list(values)
    _atomic_text(path, "".join(f"{value}\n" for value in rows))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _run_command(
    command: list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    timeout: float,
) -> dict[str, Any]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                command,
                stdout=stdout,
                stderr=stderr,
                env=_safe_env(),
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=max(0.1, timeout))
            except subprocess.TimeoutExpired:
                _stop_process(process)
                return {
                    "status": "timeout",
                    "returncode": 124,
                    "duration_seconds": round(time.monotonic() - started, 3),
                }
            except BaseException:
                _stop_process(process)
                raise
    except OSError as exc:
        return {
            "status": "error",
            "returncode": 127,
            "duration_seconds": round(time.monotonic() - started, 3),
            "error": str(exc),
        }
    return {
        "status": "ok" if returncode == 0 else "error",
        "returncode": returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def _wordlist_candidates(path: Path, target: str) -> Iterable[str]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = raw.strip().lower()
            if not value or value.startswith("#"):
                continue
            host = _valid_host(value if _in_scope(value, target) else f"{value}.{target}")
            if host and _in_scope(host, target):
                yield host


def _collect_candidates(
    target: str,
    seeds: set[str],
    sources: list[tuple[str, Iterable[str]]],
    *,
    limit: int,
) -> tuple[list[str], dict[str, int]]:
    candidates: list[str] = []
    seen = set(seeds)
    source_counts: dict[str, int] = {}
    for source, values in sources:
        source_counts[source] = 0
        for raw in values:
            host = _valid_host(raw)
            if not host or not _in_scope(host, target) or host in seen:
                continue
            seen.add(host)
            candidates.append(host)
            source_counts[source] += 1
            if len(candidates) >= limit:
                return candidates, source_counts
    return candidates, source_counts


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _merge_hosts(path: Path, additions: Iterable[str], target: str) -> int:
    existing = _read_scoped_hosts(path, target) if path.is_file() else []
    merged = sorted(set(existing).union(additions))
    _write_lines(path, merged)
    return len(set(merged).difference(existing))


def _base_result(
    *,
    repo: Path,
    target: str,
    reason: str,
    output_dir: Path,
    seed_path: Path,
    wordlist: Path | None,
    max_seeds: int,
    max_candidates: int,
    rate_limit: int,
    timeout: int,
) -> dict[str, Any]:
    def relative(path: Path) -> str:
        return str(path.relative_to(repo))

    return {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "status": "error",
        "trigger_reason": reason,
        "started_at": _now_utc(),
        "completed_at": "",
        "failure_summary": "",
        "limits": {
            "max_seeds": max_seeds,
            "max_candidates": max_candidates,
            "rate_limit": rate_limit,
            "timeout_seconds": timeout,
        },
        "inputs": {
            "seed_artifact": relative(seed_path),
            "wordlist": str(wordlist) if wordlist else "",
            "wordlist_sha256": _sha256(wordlist) if wordlist else "",
        },
        "counts": {
            "available_seeds": 0,
            "selected_seeds": 0,
            "candidates": 0,
            "resolved": 0,
            "wildcards": 0,
            "new_all_hosts": 0,
            "new_resolved_hosts": 0,
        },
        "source_counts": {},
        "tools": {},
        "warnings": [],
        "artifacts": {
            "manifest": relative(output_dir / "manifest.json"),
            "seeds": relative(output_dir / "seeds.txt"),
            "candidates": relative(output_dir / "candidates.txt"),
            "resolved": relative(output_dir / "resolved.txt"),
            "wildcards": relative(output_dir / "wildcards.txt"),
        },
    }


def _execute(
    *,
    repo: Path,
    target: str,
    reason: str,
    wordlist: Path | None,
    max_seeds: int,
    max_candidates: int,
    rate_limit: int,
    timeout: int,
) -> dict[str, Any]:
    recon_dir = repo / "recon" / target_storage_key(target)
    seed_path = recon_dir / "subdomains" / "all.txt"
    if not seed_path.is_file():
        raise ValueError(f"passive recon seed artifact is missing: {seed_path}")
    output_dir = recon_dir / "subdomains" / "dns-expansion"
    output_dir.mkdir(parents=True, exist_ok=True)
    result = _base_result(
        repo=repo,
        target=target,
        reason=reason,
        output_dir=output_dir,
        seed_path=seed_path,
        wordlist=wordlist,
        max_seeds=max_seeds,
        max_candidates=max_candidates,
        rate_limit=rate_limit,
        timeout=timeout,
    )
    (output_dir / "resolved.txt").unlink(missing_ok=True)
    (output_dir / "wildcards.txt").unlink(missing_ok=True)
    deadline = time.monotonic() + timeout
    selected_seeds = _read_scoped_hosts(seed_path, target, limit=max_seeds)
    available_seeds = _read_scoped_hosts(seed_path, target)
    if not selected_seeds:
        raise ValueError(f"passive recon seed artifact has no scoped hosts: {seed_path}")
    seed_snapshot = output_dir / "seeds.txt"
    _write_lines(seed_snapshot, selected_seeds)
    result["counts"]["available_seeds"] = len(available_seeds)
    result["counts"]["selected_seeds"] = len(selected_seeds)
    result["inputs"]["seed_sha256"] = _sha256(seed_snapshot)

    logs_dir = output_dir / "logs"
    source_iterables: list[tuple[str, Iterable[str]]] = []
    if wordlist:
        source_iterables.append(("wordlist", _wordlist_candidates(wordlist, target)))

    generator_specs = (
        (
            "alterx",
            ["-l", str(seed_snapshot), "-silent", "-duc", "-limit", str(max_candidates)],
        ),
        ("dnsgen", ["--fast", str(seed_snapshot)]),
    )
    for name, arguments in generator_specs:
        raw_path = output_dir / f"{name}.raw.txt"
        log_path = logs_dir / f"{name}.log"
        raw_path.unlink(missing_ok=True)
        log_path.unlink(missing_ok=True)
        executable = shutil.which(name)
        if not executable:
            result["tools"][name] = {"status": "missing"}
            continue
        remaining = _remaining(deadline)
        if remaining <= 0:
            result["tools"][name] = {"status": "timeout", "returncode": 124}
            continue
        tool_result = _run_command(
            [executable, *arguments],
            stdout_path=raw_path,
            stderr_path=log_path,
            timeout=remaining,
        )
        result["tools"][name] = tool_result
        if tool_result["status"] == "ok":
            source_iterables.append((name, raw_path.open(encoding="utf-8", errors="replace")))
        else:
            result["warnings"].append(f"{name} {tool_result['status']}")

    candidates, source_counts = _collect_candidates(
        target,
        set(selected_seeds),
        source_iterables,
        limit=max_candidates,
    )
    for _name, values in source_iterables:
        close = getattr(values, "close", None)
        if callable(close):
            close()
    candidates_path = output_dir / "candidates.txt"
    _write_lines(candidates_path, candidates)
    result["source_counts"] = source_counts
    result["counts"]["candidates"] = len(candidates)

    if not candidates:
        attempted = [item.get("status") for item in result["tools"].values()]
        if wordlist or "ok" in attempted:
            result["status"] = "ok"
        elif attempted and all(status == "missing" for status in attempted):
            result["status"] = "unavailable"
            result["failure_summary"] = "alterx/dnsgen are unavailable and no wordlist was supplied"
        else:
            result["status"] = "error"
            result["failure_summary"] = "DNS candidate generation failed"
        return result

    puredns = shutil.which("puredns")
    if not puredns:
        result["tools"]["puredns"] = {"status": "missing"}
        result["status"] = "unavailable"
        result["failure_summary"] = "puredns is unavailable; candidates were preserved"
        return result

    raw_resolved = output_dir / ".resolved.tmp"
    raw_wildcards = output_dir / ".wildcards.tmp"
    raw_resolved.unlink(missing_ok=True)
    raw_wildcards.unlink(missing_ok=True)
    remaining = _remaining(deadline)
    if remaining <= 0:
        result["tools"]["puredns"] = {"status": "timeout", "returncode": 124}
        result["status"] = "error"
        result["failure_summary"] = f"DNS expansion timed out after {timeout}s"
        return result
    puredns_result = _run_command(
        [
            puredns,
            "resolve",
            str(candidates_path),
            "--rate-limit",
            str(rate_limit),
            "--quiet",
            "--write",
            str(raw_resolved),
            "--write-wildcards",
            str(raw_wildcards),
        ],
        stdout_path=logs_dir / "puredns.stdout.log",
        stderr_path=logs_dir / "puredns.stderr.log",
        timeout=remaining,
    )
    result["tools"]["puredns"] = puredns_result
    if puredns_result["status"] != "ok":
        raw_resolved.unlink(missing_ok=True)
        raw_wildcards.unlink(missing_ok=True)
        result["status"] = "error"
        result["failure_summary"] = (
            f"puredns {puredns_result['status']}; no hosts were merged"
        )
        return result

    candidate_set = set(candidates)
    resolved = (
        [
            host
            for host in _read_scoped_hosts(raw_resolved, target)
            if host in candidate_set
        ]
        if raw_resolved.is_file()
        else []
    )
    wildcards = _read_scoped_hosts(raw_wildcards, target) if raw_wildcards.is_file() else []
    _write_lines(output_dir / "resolved.txt", resolved)
    _write_lines(output_dir / "wildcards.txt", wildcards)
    raw_resolved.unlink(missing_ok=True)
    raw_wildcards.unlink(missing_ok=True)
    result["counts"]["resolved"] = len(resolved)
    result["counts"]["wildcards"] = len(wildcards)
    result["counts"]["new_resolved_hosts"] = _merge_hosts(
        recon_dir / "subdomains" / "resolved.txt", resolved, target
    )
    result["counts"]["new_all_hosts"] = _merge_hosts(seed_path, resolved, target)
    result["status"] = "ok"
    return result


def run_dns_expansion(
    target: str,
    *,
    reason: str,
    wordlist: str = "",
    max_seeds: int = DEFAULT_MAX_SEEDS,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    rate_limit: int = DEFAULT_RATE_LIMIT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    repo_root: str | Path = BASE_DIR,
) -> dict[str, Any]:
    target_info = classify_target(canonical_target_value(target))
    resolved_target = str(target_info["target"]).lower().strip(".")
    if target_info["kind"] != "domain" or ":" in resolved_target or "." not in resolved_target:
        raise ValueError("DNS expansion requires one domain target without a port")
    if not reason.strip():
        raise ValueError("AI trigger reason is required")
    if not 1 <= max_seeds <= MAX_MAX_SEEDS:
        raise ValueError(f"max_seeds must be between 1 and {MAX_MAX_SEEDS}")
    if not 1 <= max_candidates <= MAX_MAX_CANDIDATES:
        raise ValueError(f"max_candidates must be between 1 and {MAX_MAX_CANDIDATES}")
    if not 1 <= rate_limit <= MAX_RATE_LIMIT:
        raise ValueError(f"rate_limit must be between 1 and {MAX_RATE_LIMIT}")
    if not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS}")
    resolved_wordlist = Path(wordlist).expanduser().resolve() if wordlist else None
    if resolved_wordlist and not resolved_wordlist.is_file():
        raise ValueError(f"wordlist is missing: {resolved_wordlist}")

    repo = Path(repo_root).resolve()
    output_dir = repo / "recon" / target_storage_key(resolved_target) / "subdomains" / "dns-expansion"
    manifest_path = output_dir / "manifest.json"
    started = time.monotonic()
    try:
        with runtime_phase_lock(repo, resolved_target, "recon"):
            try:
                result = _execute(
                    repo=repo,
                    target=resolved_target,
                    reason=reason.strip()[:500],
                    wordlist=resolved_wordlist,
                    max_seeds=max_seeds,
                    max_candidates=max_candidates,
                    rate_limit=rate_limit,
                    timeout=timeout,
                )
            except ValueError:
                raise
            except Exception as exc:
                output_dir.mkdir(parents=True, exist_ok=True)
                result = {
                    "schema_version": SCHEMA_VERSION,
                    "target": resolved_target,
                    "status": "error",
                    "trigger_reason": reason.strip()[:500],
                    "started_at": _now_utc(),
                    "completed_at": "",
                    "failure_summary": str(exc),
                }
            result["completed_at"] = _now_utc()
            result["duration_seconds"] = round(time.monotonic() - started, 3)
            _atomic_json(manifest_path, result)
    except (RuntimePhaseBusy, ValueError):
        raise
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-selected bounded DNS expansion lane")
    parser.add_argument("--target", required=True, help="Domain with passive Recon artifacts")
    parser.add_argument("--reason", required=True, help="Evidence-based AI trigger reason")
    parser.add_argument("--wordlist", default="", help="Optional reviewed DNS label wordlist")
    parser.add_argument("--max-seeds", type=int, default=DEFAULT_MAX_SEEDS)
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument("--rate-limit", type=int, default=DEFAULT_RATE_LIMIT)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--repo-root", default=str(BASE_DIR), help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_dns_expansion(
            args.target,
            reason=args.reason,
            wordlist=args.wordlist,
            max_seeds=args.max_seeds,
            max_candidates=args.max_candidates,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            repo_root=args.repo_root,
        )
    except RuntimePhaseBusy as exc:
        print(f"runtime phase busy: {exc}", file=sys.stderr)
        return 75
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
        print(
            f"{result['status']}: {counts.get('resolved', 0)} resolved, "
            f"{counts.get('new_all_hosts', 0)} new host(s)"
        )
        if result.get("failure_summary"):
            print(str(result["failure_summary"]), file=sys.stderr)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
