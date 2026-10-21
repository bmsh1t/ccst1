#!/usr/bin/env python3
"""Evidence-gated Exchange interface checks using the external EBurst tool.

EBurst is an old Python 2 script kept outside this repository.  This module
owns discovery, target scoping, bounded execution, and structured evidence;
it does not import or copy EBurst and does not expose its credential-brute
force mode to Autopilot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

if __package__ in {None, ""}:  # direct script execution from another directory
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from tools.artifact_io import publish_bytes_create_only, write_json_atomic
    from tools.autopilot_continuation import reject_unsupported_continuation
    from tools.scope_context import ScopeContext
    from tools.scope_source import load_scope_context
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import publish_bytes_create_only, write_json_atomic
    from autopilot_continuation import reject_unsupported_continuation
    from scope_context import ScopeContext
    from scope_source import load_scope_context


try:
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.scope_context import url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore
    from scope_context import url_belongs_to_target  # type: ignore


SCHEMA_VERSION = 1
MAX_HOSTS = 5
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 900
EXCHANGE_PATH_RE = re.compile(
    r"/(?:owa(?:/|$)|ews(?:/|$)|autodiscover(?:/|$)|ecp(?:/|$)|oab(?:/|$)|"
    r"mapi(?:/|$)|rpc(?:/|$)|powershell(?:/|$)|microsoft-server-activesync(?:/|$))",
    re.IGNORECASE,
)
EXCHANGE_TEXT_RE = re.compile(
    r"\b(?:microsoft\s+exchange|outlook\s+web\s+access|autodiscover|"
    r"microsoft-server-activesync|exchange\s+(?:web|mail)|owa|ews)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SENSITIVE_ENV_KEYS = {
    "BBHUNT_AUTH_HEADERS",
    "BBHUNT_AUTH_HEADER",
    "BBHUNT_COOKIE",
    "BBHUNT_BEARER",
    "BBHUNT_API_KEY",
    "H1_API_TOKEN",
    "CHAOS_API_KEY",
    "RESIN_PROXY_TOKEN",
}
Which = Callable[[str], str | None]
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _shared_tools_dir(env: dict[str, str]) -> Path:
    value = env.get("BBHUNT_TOOLS_DIR") or env.get("OSMEDEUS_TOOLS_DIR")
    return Path(value).expanduser() if value else Path(env.get("HOME") or str(Path.home())) / "Tools"


def _candidate_homes(env: dict[str, str]) -> list[Path]:
    values = []
    explicit = env.get("EBURST_HOME")
    if explicit:
        return [Path(explicit).expanduser()]
    values.extend(
        [
            _shared_tools_dir(env) / "EBurst",
            Path(env.get("HOME") or str(Path.home())) / "Tools" / "EBurst",
        ]
    )
    seen: set[str] = set()
    result = []
    for value in values:
        key = str(value.resolve())
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def resolve_eburst(*, env: dict[str, str] | None = None, which: Which | None = None) -> dict:
    """Resolve EBurst without importing it or installing dependencies."""
    env = dict(os.environ if env is None else env)
    resolver = which or (lambda name: shutil.which(name, path=env.get("PATH", os.defpath)))
    command = resolver("eburst") or resolver("EBurst")
    if command:
        return {
            "status": "ready",
            "home": str(Path(command).expanduser().resolve().parent),
            "script": "",
            "interpreter": str(Path(command).expanduser().resolve()),
            "mode": "binary",
        }
    missing_runtime = None
    for home in _candidate_homes(env):
        script = home / "EBurst.py"
        if not script.is_file():
            continue
        candidates = []
        configured = str(env.get("EBURST_PYTHON") or "").strip()
        if configured:
            candidates.append(configured)
        candidates.extend(("python2", "python2.7"))
        interpreter = None
        for item in candidates:
            if os.path.isfile(item) and os.access(item, os.X_OK):
                interpreter = item
                break
            interpreter = resolver(item)
            if interpreter:
                break
        if interpreter:
            return {
                "status": "ready",
                "home": str(home.resolve()),
                "script": str(script.resolve()),
                "interpreter": str(Path(interpreter).expanduser().resolve()),
                "mode": "python2-script",
            }
        missing_runtime = {
            "status": "missing_interpreter",
            "home": str(home.resolve()),
            "script": str(script.resolve()),
            "interpreter": "",
            "reason": "python2-required",
        }
    return missing_runtime or {"status": "missing_script", "home": "", "script": "", "interpreter": ""}


def _read_text(path: Path, *, limit: int = 1_000_000) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _host_url(value: str, target: str) -> tuple[str, str] | None:
    raw = str(value or "").strip().rstrip(".,;)")
    if not raw or any(ord(character) < 32 or ord(character) == 127 for character in raw):
        return None
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        netloc = parsed.netloc
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not host or not netloc:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    try:
        parsed.port
    except ValueError:
        return None
    if not url_belongs_to_target(candidate, target):
        return None
    return candidate, netloc


def _evidence_candidates(recon_dir: Path) -> list[tuple[str, str]]:
    paths = [
        recon_dir / "live" / "technology_inventory.json",
        recon_dir / "live" / "httpx_full.jsonl",
        recon_dir / "live" / "httpx_full.txt",
        recon_dir / "live" / "urls.txt",
        recon_dir / "urls" / "all.txt",
    ]
    evidence = []
    for path in paths:
        content = _read_text(path)
        if content:
            evidence.append((str(path), content))
    return evidence


def detect_exchange_hosts(repo_root: str | Path, target: str, *, max_hosts: int = MAX_HOSTS) -> list[dict]:
    """Find target-owned hosts with Exchange path/product evidence."""
    if max_hosts <= 0:
        return []
    resolved_target = canonical_target_value(target)
    recon_dir = Path(repo_root) / "recon" / target_storage_key(resolved_target)
    found: dict[str, dict] = {}
    for source, content in _evidence_candidates(recon_dir):
        if source.endswith("technology_inventory.json"):
            try:
                payload = json.loads(content)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            records = []
            for host in payload.get("hosts") or []:
                if isinstance(host, dict):
                    records.append(host)
            for item in payload.get("components") or []:
                if isinstance(item, dict):
                    records.append(item)
            for item in records:
                blob = json.dumps(item, ensure_ascii=False)
                if not EXCHANGE_TEXT_RE.search(blob):
                    continue
                value = str(item.get("url") or item.get("host") or "")
                parsed = _host_url(value, resolved_target)
                if parsed:
                    url, netloc = parsed
                    found.setdefault(netloc.lower(), {"url": url, "host": netloc, "evidence": []})[
                        "evidence"
                    ].append(source)
            continue

        for line in content.splitlines():
            if not EXCHANGE_TEXT_RE.search(line) and not EXCHANGE_PATH_RE.search(line):
                continue
            urls = URL_RE.findall(line)
            for value in urls:
                parsed = _host_url(value, resolved_target)
                if not parsed:
                    continue
                url, netloc = parsed
                found.setdefault(netloc.lower(), {"url": url, "host": netloc, "evidence": []})[
                    "evidence"
                ].append(source)
    return list(found.values())[: min(int(max_hosts), MAX_HOSTS)]


def build_probe_command(resolution: dict, host: str) -> list[str]:
    """Build the read-only EBurst interface availability command."""
    if resolution.get("status") != "ready":
        raise ValueError("EBurst is not runnable")
    if (not host or "://" in host or "/" in host or host.startswith("-")
            or any(character.isspace() for character in host) or "@" in host):
        raise ValueError("EBurst host must be a scoped host[:port], not a URL/path")
    command = [str(resolution["interpreter"])]
    if resolution.get("script"):
        command.append(str(resolution["script"]))
    return command + ["-C", "-d", host]


def _write_json_atomic(path: Path, payload: dict) -> None:
    write_json_atomic(path, payload, sort_keys=True)


def run_exchange_lane(
    repo_root: str | Path,
    target: str,
    *,
    hosts: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_hosts: int = MAX_HOSTS,
    env: dict[str, str] | None = None,
    which: Which | None = None,
    runner: Runner | None = None,
    context_file: str | Path | None = None,
) -> dict:
    """Run bounded Exchange interface checks and publish a target-owned summary."""
    if type(timeout) is not int or timeout < 1 or timeout > MAX_TIMEOUT:
        raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT} seconds")
    if type(max_hosts) is not int or max_hosts < 1 or max_hosts > MAX_HOSTS:
        raise ValueError(f"max_hosts must be between 1 and {MAX_HOSTS}")
    repo = Path(repo_root).expanduser().resolve()
    resolved_target = canonical_target_value(target)
    reject_unsupported_continuation(repo, target, context_file, executor="EBurst")
    scope = load_scope_context(repo, resolved_target)
    supplied_scope = ScopeContext(root_target=target)
    candidates = []
    if hosts:
        for raw in hosts:
            parsed = _host_url(raw, target)
            if not parsed:
                raise ValueError(f"EBurst host is outside target scope or invalid: {raw}")
            url, netloc = parsed
            # The retained upstream -C interface uses HTTPS and checks the origin's
            # predefined Exchange paths. Do not silently broaden an HTTP-only input.
            if urlparse(url).scheme.lower() != "https":
                raise ValueError("EBurst -C uses HTTPS; select an HTTPS origin or a native HTTP executor")
            origin = f"https://{netloc}/"
            if not supplied_scope.allows_active(origin) or not scope.allows_active(origin):
                raise ValueError("EBurst origin is excluded by the current Scope")
            candidates.append({"url": url, "host": netloc, "evidence": ["explicit-host"]})
    else:
        candidates = detect_exchange_hosts(repo, resolved_target, max_hosts=max_hosts)
        candidates = [candidate for candidate in candidates
                      if urlparse(candidate["url"]).scheme.lower() == "https"
                      and supplied_scope.allows_active(f"https://{candidate['host']}/")
                      and scope.allows_active(f"https://{candidate['host']}/")]
    candidate_inventory = list({str(item["host"]).lower(): item for item in candidates}.values())
    candidates = candidate_inventory[:max_hosts]

    output_root = repo / "recon" / target_storage_key(resolved_target) / "exchange" / "eburst"
    if any(parent.is_symlink() for parent in (output_root / "runs", output_root, *output_root.parents)):
        raise ValueError("EBurst output must not traverse symlinks")
    summary_path = output_root / "summary.json"
    if summary_path.is_symlink() or (summary_path.exists() and not summary_path.is_file()):
        raise ValueError("EBurst summary destination must be a regular file")
    for directory in (output_root, output_root / "runs"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run.", dir=output_root / "runs"))

    summary = {
        "schema_version": SCHEMA_VERSION,
        "target": resolved_target,
        "lane": "exchange-interface-check",
        "status": "not_applicable" if not candidates else "pending",
        "tool": "eburst",
        "hosts": candidates,
        "results": [],
        "scope_hash": scope.fingerprint,
        "run_dir": str(run_dir.relative_to(repo)),
        "ts": datetime.now(timezone.utc).isoformat(),
        "analysis_status": "not_run",
        "credential_attempts": 0,
        "requested_inputs": len(hosts) if hosts is not None else None,
        "input_total": len(candidate_inventory) if hosts else None,
        "selected": len(candidates),
        "remaining": len(candidate_inventory) if hosts else None,
        "deferred_hosts": candidate_inventory[max_hosts:],
    }
    _write_json_atomic(run_dir / "summary.json", summary)
    resolution = resolve_eburst(env=env, which=which)
    summary["tool_status"] = resolution["status"]
    if not candidates:
        summary["reason"] = "no-scoped-https-exchange-input"
    elif resolution.get("status") != "ready":
        summary["status"] = "unavailable"
        summary["reason"] = resolution.get("reason") or resolution["status"]
    else:
        child_env = dict(os.environ if env is None else env)
        for key in SENSITIVE_ENV_KEYS:
            child_env.pop(key, None)
        execute = runner or subprocess.run
        for index, candidate in enumerate(candidates):
            host = str(candidate["host"])
            current_scope = load_scope_context(repo, resolved_target)
            if not current_scope.allows_active(f"https://{host}/"):
                raise ValueError("EBurst Scope changed before execution")
            result = {"host": host, "url": candidate["url"]}
            host_dir = run_dir / f"host-{index + 1}"
            host_dir.mkdir(mode=0o700)
            command = build_probe_command(resolution, host)
            _write_json_atomic(host_dir / "command.json", {"argv": command, "tool": resolution})
            summary["status"] = "running"
            _write_json_atomic(run_dir / "summary.json", summary)
            try:
                completed = execute(
                    command,
                    cwd=str(host_dir),
                    env=child_env,
                    capture_output=True,
                    text=False,
                    timeout=timeout,
                    check=False,
                )
                result["returncode"] = int(completed.returncode)
                result["status"] = "ok" if completed.returncode == 0 else "failed"
                stdout, stderr = completed.stdout, completed.stderr
            except subprocess.TimeoutExpired as exc:
                result.update({"status": "timeout", "returncode": None})
                stdout, stderr = exc.stdout, exc.stderr
            except OSError as exc:
                result.update({"status": "unavailable", "returncode": None, "error": str(exc)})
                stdout, stderr = b"", str(exc).encode("utf-8")
            as_bytes = lambda part: part if isinstance(part, bytes) else str(part or "").encode("utf-8")
            stdout, stderr = as_bytes(stdout), as_bytes(stderr)
            publish_bytes_create_only(host_dir / "stdout.raw", stdout)
            publish_bytes_create_only(host_dir / "stderr.raw", stderr)
            raw_path = host_dir / "combined.raw"
            publish_bytes_create_only(raw_path, stdout + stderr)
            result["raw_evidence"] = str(raw_path.relative_to(repo))
            result["stdout_path"] = str((host_dir / "stdout.raw").relative_to(repo))
            result["stderr_path"] = str((host_dir / "stderr.raw").relative_to(repo))
            result["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
            result["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
            summary["results"].append(result)
            _write_json_atomic(run_dir / "summary.json", summary)
        statuses = {item["status"] for item in summary["results"]}
        summary["status"] = "ok" if statuses == {"ok"} else "partial" if "ok" in statuses else "failed"
    summary["completed"] = sum(item.get("status") == "ok" for item in summary["results"])
    if summary["input_total"] is not None:
        summary["remaining"] = summary["input_total"] - summary["completed"]

    summary["summary_path"] = str(summary_path.relative_to(repo))
    if summary_path.is_symlink() or (summary_path.exists() and not summary_path.is_file()):
        raise ValueError("EBurst summary destination must be a regular file")
    if summary_path.exists():
        publish_bytes_create_only(run_dir / "previous_summary.json", summary_path.read_bytes())
    _write_json_atomic(run_dir / "summary.json", summary)
    _write_json_atomic(summary_path, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence-gated Exchange interface check via external EBurst")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--host", action="append", default=[], help="Explicit target-owned host[:port] or URL")
    parser.add_argument("--max-hosts", type=int, default=MAX_HOSTS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true", help="Emit the structured summary (default)")
    parser.add_argument("--context-file", default=None, help="Parent Scope continuation; rejected by this subprocess adapter")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_exchange_lane(
            args.repo_root,
            args.target,
            hosts=args.host,
            timeout=args.timeout,
            max_hosts=args.max_hosts,
            context_file=args.context_file,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["status"] in {"ok", "not_applicable"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
