#!/usr/bin/env python3
"""role_diff.py — multi-role endpoint comparison for IDOR / authz testing.

Given two or more auth sessions (e.g. user_a, user_b, admin, no_auth) and a
list of endpoints, replay each endpoint under each role and surface the
high-signal differences:

  - status_diff     : roles return different HTTP status classes (2xx/3xx/4xx/5xx)
  - size_diff       : same status but response bodies differ >N% by size
  - hash_match      : two different roles return byte-identical bodies
                      (strong IDOR signal — user A getting user B's data)
  - leak_to_unauth  : no_auth role gets 2xx with non-trivial body

Sessions are supplied explicitly via repeated `--session ROLE=PATH` flags. The
tool does NOT scan disk for sessions — keep auth handling deliberate.

The use case this tool solves: IDOR detection is currently manual in this
repo. Scanner tools probe parameters and content, but they do not compare the
same endpoint across roles. This tool fills that gap and feeds back into
`findings/<target>/role_diff/result.json` for the validator/report pipeline.

Usage:
  python3 tools/role_diff.py \\
      --target target.com \\
      --endpoints recon/target.com/urls/api_endpoints.txt \\
      --session user_a=.private/auth_a.json \\
      --session user_b=.private/auth_b.json \\
      --session admin=.private/auth_admin.json \\
      --session no_auth=NONE

Outputs:
  findings/<target>/role_diff/result.json   structured diff matrix
  stdout: summary table + ## CLAUDE_HINT block
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

# ─── Logging (ANSI, sent to stderr so stdout stays parseable) ───────────────
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_YELLOW = "\033[1;33m"
_CYAN = "\033[0;36m"
_NC = "\033[0m"


def _log_info(msg: str) -> None:
    print(f"{_CYAN}[*]{_NC} {msg}", file=sys.stderr)


def _log_ok(msg: str) -> None:
    print(f"{_GREEN}[+]{_NC} {msg}", file=sys.stderr)


def _log_warn(msg: str) -> None:
    print(f"{_YELLOW}[!]{_NC} {msg}", file=sys.stderr)


def _log_err(msg: str) -> None:
    print(f"{_RED}[-]{_NC} {msg}", file=sys.stderr)


# ─── Constants ──────────────────────────────────────────────────────────────
NO_AUTH_SENTINEL = "NONE"
DEFAULT_METHOD = "GET"
DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 5
DEFAULT_DIFF_SIZE_PCT = 30
MIN_INTER_REQUEST_MS = 50
LEAK_UNAUTH_MIN_BYTES = 200
HASH_PREFIX_LEN = 16
RESPONSE_READ_CAP = 1024 * 1024  # 1 MB body cap for hashing/sizing


def status_class(status: int) -> str:
    """Bucket HTTP status into rough classes for diff detection."""
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


# ─── Session parsing ────────────────────────────────────────────────────────
def parse_session_arg(raw: str) -> tuple[str, dict]:
    """Parse a --session ROLE=PATH argument into (role_name, session_dict).

    session_dict is the merged effective auth state: {"headers": {...}}.

    Special cases:
      - PATH == "NONE": no-auth role (empty headers).
      - PATH points to JSON with {"cookie", "headers", "bearer", "api_key"}
        which are normalized into a single headers dict.
    """
    if "=" not in raw:
        raise ValueError(
            f"--session expects ROLE=PATH, got {raw!r} (use NONE for unauthenticated)"
        )
    role, _, path = raw.partition("=")
    role = role.strip()
    path = path.strip()
    if not role:
        raise ValueError(f"--session role name is empty in {raw!r}")
    if path == NO_AUTH_SENTINEL:
        return role, {"headers": {}}
    session_path = Path(path)
    if not session_path.is_file():
        raise FileNotFoundError(f"session file not found: {path}")
    try:
        payload = json.loads(session_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"session file {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"session file {path} must contain a JSON object")
    headers: dict[str, str] = {}
    for key, value in (payload.get("headers") or {}).items():
        if isinstance(value, str):
            headers[str(key)] = value
    cookie = payload.get("cookie")
    if isinstance(cookie, str) and cookie.strip():
        headers["Cookie"] = cookie.strip()
    bearer = payload.get("bearer")
    if isinstance(bearer, str) and bearer.strip():
        headers["Authorization"] = f"Bearer {bearer.strip()}"
    api_key = payload.get("api_key")
    if isinstance(api_key, str) and api_key.strip():
        headers.setdefault("X-API-Key", api_key.strip())
    return role, {"headers": headers}


def parse_sessions(session_args: list[str]) -> dict[str, dict]:
    sessions: dict[str, dict] = {}
    for raw in session_args:
        role, session = parse_session_arg(raw)
        if role in sessions:
            raise ValueError(f"role {role!r} given twice")
        sessions[role] = session
    if not sessions:
        raise ValueError("at least one --session is required")
    return sessions


# ─── Endpoint parsing ───────────────────────────────────────────────────────
def parse_endpoints_file(path: Path, method_allow: set[str]) -> list[tuple[str, str]]:
    """Parse the endpoints file. Each line is `[METHOD] URL`.

    Bare URLs are replayed with GET because no captured request body is
    available.

    Lines starting with `#` or empty are skipped. Methods not in method_allow
    raise immediately because this URL-only replay tool has no request body or
    cleanup model. This is a request-shape guard, not a red-line rule: add
    observed POST/PUT/PATCH/DELETE deliberately when the replay is read-only,
    preview/validate-only, or uses test-owned reversible resources.
    """
    if not path.is_file():
        raise FileNotFoundError(f"endpoints file not found: {path}")
    parsed: list[tuple[str, str]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 1:
            method = DEFAULT_METHOD
            url = parts[0]
        else:
            head, tail = parts[0], parts[1]
            if head.upper() == head and head.isalpha():
                method = head.upper()
                url = tail.strip()
            else:
                method = DEFAULT_METHOD
                url = line
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"line {line_no}: URL must be absolute, got {url!r}")
        if method not in method_allow:
            raise ValueError(
                f"line {line_no}: method {method!r} not in --method-allow ({sorted(method_allow)})"
            )
        parsed.append((method, url))
    return parsed


# ─── Request execution ──────────────────────────────────────────────────────
def _do_request(
    method: str,
    url: str,
    headers: dict,
    timeout: int,
) -> dict:
    req = Request(url, method=method, headers=headers or {})
    opener = build_opener()  # no automatic cookie handling — sessions are explicit
    start = time.perf_counter()
    status: Optional[int] = None
    body = b""
    error_kind: Optional[str] = None
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(RESPONSE_READ_CAP)
    except HTTPError as exc:
        status = exc.code
        try:
            body = exc.read(RESPONSE_READ_CAP) if hasattr(exc, "read") else b""
        except Exception:  # noqa: BLE001
            body = b""
    except URLError as exc:
        error_kind = f"urlerror:{exc.reason}"
    except (TimeoutError, OSError) as exc:
        error_kind = f"oserror:{type(exc).__name__}"
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    size = len(body)
    body_hash = hashlib.sha256(body).hexdigest()[:HASH_PREFIX_LEN] if body else ""
    return {
        "status": status if status is not None else 0,
        "size": size,
        "hash": body_hash,
        "latency_ms": elapsed_ms,
        "error": error_kind,
    }


def replay_endpoint(
    method: str,
    url: str,
    sessions: dict[str, dict],
    timeout: int,
) -> dict[str, dict]:
    """Replay one endpoint across every role. Sequential to keep target pacing sane."""
    by_role: dict[str, dict] = {}
    for role, session in sessions.items():
        result = _do_request(method, url, session.get("headers", {}), timeout)
        by_role[role] = result
        time.sleep(MIN_INTER_REQUEST_MS / 1000)
    return by_role


# ─── Signal detection ───────────────────────────────────────────────────────
def detect_signals(by_role: dict[str, dict], diff_size_pct: int) -> list[str]:
    """Return the list of high-signal labels for this endpoint across roles."""
    signals: list[str] = []
    statuses = {role: r["status"] for role, r in by_role.items() if not r.get("error")}
    classes = {status_class(s) for s in statuses.values()}
    if len(classes) >= 2:
        signals.append("status_diff")

    # Group by class to compare sizes/hashes inside the same class.
    by_class: dict[str, list[str]] = {}
    for role, status in statuses.items():
        by_class.setdefault(status_class(status), []).append(role)

    for _cls, roles in by_class.items():
        if len(roles) < 2:
            continue
        sizes = [by_role[r]["size"] for r in roles]
        hashes = [by_role[r]["hash"] for r in roles]
        # hash_match: two distinct roles returning byte-identical body
        if any(hashes.count(h) > 1 for h in hashes if h):
            signals.append("hash_match")
        # size_diff: at least one pair differs by more than diff_size_pct
        if sizes and max(sizes) > 0:
            ratio = (max(sizes) - min(sizes)) / max(sizes) * 100
            if ratio >= diff_size_pct:
                signals.append("size_diff")

    if "no_auth" in by_role:
        no_auth_result = by_role["no_auth"]
        if (
            not no_auth_result.get("error")
            and 200 <= no_auth_result["status"] < 300
            and no_auth_result["size"] >= LEAK_UNAUTH_MIN_BYTES
        ):
            signals.append("leak_to_unauth")

    # Dedupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for sig in signals:
        if sig not in seen:
            seen.add(sig)
            out.append(sig)
    return out


# ─── Output ─────────────────────────────────────────────────────────────────
def render_terminal_summary(result: dict) -> str:
    """Render a compact stdout summary. Sessions/auth never appear here."""
    lines: list[str] = []
    lines.append("Role Diff Summary")
    lines.append("=================")
    lines.append(f"Target:       {result['target']}")
    lines.append(f"Roles:        {', '.join(result['roles'])}")
    lines.append(f"Endpoints:    {len(result['endpoints'])}")
    lines.append(f"High-signal:  {result['summary']['high_signal_count']}")
    lines.append("")
    high = [e for e in result["endpoints"] if e["signals"]]
    if high:
        lines.append("Findings:")
        for entry in high[:25]:
            label = ",".join(entry["signals"]).upper()
            lines.append(f"  [{label}]  {entry['method']} {entry['url']}")
        if len(high) > 25:
            lines.append(f"  ... and {len(high) - 25} more")
    else:
        lines.append("No high-signal differences detected across roles.")
    lines.append("")
    return "\n".join(lines)


def emit_claude_hint(result: dict, out_path: Path) -> str:
    summary = result["summary"]
    next_action = "review high-signal entries; for hash_match feed candidate to validator"
    if summary["high_signal_count"] == 0:
        next_action = "no role diffs found — consider expanding endpoint list or sessions"
    return (
        "\n## CLAUDE_HINT\n"
        "phase: role_diff\n"
        f"target: {result['target']}\n"
        f"roles: {','.join(result['roles'])}\n"
        f"endpoints_total: {len(result['endpoints'])}\n"
        f"high_signal_count: {summary['high_signal_count']}\n"
        f"hash_match_count: {summary['hash_match_count']}\n"
        f"status_diff_count: {summary['status_diff_count']}\n"
        f"size_diff_count: {summary['size_diff_count']}\n"
        f"leak_to_unauth_count: {summary['leak_to_unauth_count']}\n"
        f"artifacts:\n  result: {out_path}\n"
        f"next_priority_action: {next_action}\n"
    )


# ─── Orchestration ──────────────────────────────────────────────────────────
def run_role_diff(
    target: str,
    endpoints: list[tuple[str, str]],
    sessions: dict[str, dict],
    out_dir: Path,
    timeout: int = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    diff_size_pct: int = DEFAULT_DIFF_SIZE_PCT,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    endpoint_records: list[dict] = []

    summary = {
        "high_signal_count": 0,
        "hash_match_count": 0,
        "status_diff_count": 0,
        "size_diff_count": 0,
        "leak_to_unauth_count": 0,
    }

    def _work(ep: tuple[str, str]) -> dict:
        method, url = ep
        by_role = replay_endpoint(method, url, sessions, timeout)
        signals = detect_signals(by_role, diff_size_pct)
        return {"method": method, "url": url, "by_role": by_role, "signals": signals}

    max_workers = max(1, min(concurrency, len(endpoints) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for record in pool.map(_work, endpoints):
            endpoint_records.append(record)
            if record["signals"]:
                summary["high_signal_count"] += 1
            for sig in record["signals"]:
                key = f"{sig}_count"
                if key in summary:
                    summary[key] += 1

    result = {
        "target": target,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "roles": list(sessions.keys()),
        "endpoints": endpoint_records,
        "summary": summary,
    }

    out_path = out_dir / "result.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _default_out_dir(target: str) -> Path:
    base = Path(__file__).resolve().parent.parent
    safe = target.replace("/", "_").strip()
    return base / "findings" / safe / "role_diff"


# ─── CLI entrypoint ─────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="role_diff.py",
        description="Compare a list of endpoints across multiple auth roles (IDOR detection).",
    )
    p.add_argument("--target", required=True, help="Target name (used for output directory).")
    p.add_argument("--endpoints", required=True, help="Path to endpoints file (one URL per line).")
    p.add_argument(
        "--session",
        action="append",
        default=[],
        metavar="ROLE=PATH",
        help="Auth session as ROLE=PATH. Use PATH=NONE for unauthenticated. Repeatable.",
    )
    p.add_argument(
        "--method-allow",
        default="GET",
        help=(
            "Comma-separated allowed methods for this URL-only replay tool "
            "(bare URLs use GET). Add observed POST/PUT/PATCH/DELETE deliberately "
            "when the request has no destructive side effect or uses test-owned resources."
        ),
    )
    p.add_argument("--out-dir", default="", help="Override output directory.")
    p.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Per-request timeout sec (default {DEFAULT_TIMEOUT})."
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Endpoint parallelism (default {DEFAULT_CONCURRENCY}).",
    )
    p.add_argument(
        "--diff-size-pct",
        type=int,
        default=DEFAULT_DIFF_SIZE_PCT,
        help=f"Size diff threshold percent (default {DEFAULT_DIFF_SIZE_PCT}).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        sessions = parse_sessions(args.session)
    except (ValueError, FileNotFoundError) as exc:
        _log_err(str(exc))
        return 2

    method_allow = {m.strip().upper() for m in args.method_allow.split(",") if m.strip()}
    if not method_allow:
        _log_err("--method-allow cannot be empty")
        return 2

    try:
        endpoints = parse_endpoints_file(Path(args.endpoints), method_allow)
    except (ValueError, FileNotFoundError) as exc:
        _log_err(str(exc))
        return 2

    if not endpoints:
        _log_warn("endpoints file produced 0 entries — nothing to do")
        return 0

    out_dir = Path(args.out_dir) if args.out_dir else _default_out_dir(args.target)
    _log_info(
        f"role_diff: target={args.target} endpoints={len(endpoints)} roles={list(sessions.keys())}"
    )

    result = run_role_diff(
        target=args.target,
        endpoints=endpoints,
        sessions=sessions,
        out_dir=out_dir,
        timeout=args.timeout,
        concurrency=args.concurrency,
        diff_size_pct=args.diff_size_pct,
    )

    sys.stdout.write(render_terminal_summary(result))
    sys.stdout.write(emit_claude_hint(result, out_dir / "result.json"))
    _log_ok(f"result written to {out_dir / 'result.json'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
