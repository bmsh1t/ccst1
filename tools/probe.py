#!/usr/bin/env python3
"""probe.py — 对目标发请求的默认姿势：透传请求语义 + 透明记账（批次 B1）。

Task: 09-11-ai-capability-roadmap, batch B1.

它是“记账的 curl”，不是扫描器：一次请求、无重试、无并发、无 payload 生成。
每次调用按序做四件事——

1. scope 检查：URL 必须属于 target（复用 ``target_paths.url_belongs_to_target``，
   另加 localhost/127.0.0.1 等环回等价）；不匹配则拒绝且不发出任何请求。
2. 发请求：stdlib ``urllib.request``（method/headers/body/timeout 透传，
   不跟随重定向——与 curl 默认语义一致，3xx 原样返回）。
3. 原始请求/响应全文落盘 ``evidence/<target>/probe/<ts>-<hash8>.json``
   （同一毫秒内的重复请求加 ``-N`` 后缀——两次请求必须是两个事件、两个文件，
   不静默去重、不覆盖旧证据）。
4. 自动追加 Evidence Ledger（``source="probe"``，``result`` 默认 ``lead``——
   探针只产生线索，不产生结论）。

状态标志（核心安全设计，与 ``validation_runner.py`` 的
"state-changing validation requires --redline-checked before any request"
纪律同构，不发明新安全语义）：

- ``state_changing`` / ``redline_checked`` 默认 False，不可静默置 True；
- ``--state-changing`` 必须伴随 ``--redline-checked``（表示已按
  ``rules/red-lines.md`` 评估副作用），否则在发任何请求之前拒绝；
- 输出末尾显式回显落账内容（``LEDGER: ...`` 行），AI 必须看见；
- ``--no-ledger`` 是纯只读浏览的逃生口：跳过 ledger 写入并显式提示未落账。

本工具的机械闸门全部属于桶纪律内的类别：scope/red-line（危险操作桶）、
timeout/max_body_bytes（失控边界）、参数格式（显式格式类）；没有任何
“该测什么”的内容级闸门。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.evidence_ledger import (
        RESULTS,
        normalize_actor,
        normalize_ledger_vuln_class,
        normalize_result,
        normalize_variant,
        record_entry,
    )
    from tools.target_paths import (
        canonical_target_value,
        target_storage_key,
        url_belongs_to_target,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from evidence_ledger import (  # type: ignore
        RESULTS,
        normalize_actor,
        normalize_ledger_vuln_class,
        normalize_result,
        normalize_variant,
        record_entry,
    )
    from target_paths import (  # type: ignore
        canonical_target_value,
        target_storage_key,
        url_belongs_to_target,
    )

DISPLAY_BODY_LIMIT = 4096
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
# Literal hosts that all name the local loopback interface. A lab target typed
# as `localhost:3000` must accept a probe URL on `127.0.0.1:3000` (and vice
# versa); the strict literal-host matcher in target_paths treats them as
# different hosts, so probe adds this equivalence layer on top.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


class ProbeError(ValueError):
    """Pre-request rejection: bad arguments, scope mismatch, or flag discipline."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """curl-style pass-through: 3xx responses are returned, not followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _parse_authority(value: str) -> tuple[str, int | None, str]:
    """Mirror target_paths._scope_endpoint: (host, effective port, scheme)."""
    raw = str(value or "").strip()
    if not raw:
        return "", None, ""
    candidate = raw if "://" in raw or raw.startswith("//") else f"//{raw}"
    try:
        parsed = urlparse(candidate)
        port = parsed.port
    except ValueError:
        return "", None, ""
    scheme = (parsed.scheme or "").lower()
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    host = (parsed.hostname or "").lower()
    return host, port, scheme


def url_matches_target_scope(url: str, target: str) -> bool:
    """Scope gate: the shared target matcher plus loopback host equivalence."""
    if url_belongs_to_target(url, target):
        return True
    t_host, t_port, t_scheme = _parse_authority(target)
    u_host, u_port, u_scheme = _parse_authority(url)
    if not t_host or not u_host:
        return False
    if t_host not in LOOPBACK_HOSTS or u_host not in LOOPBACK_HOSTS:
        return False
    if t_scheme and u_scheme and t_scheme != u_scheme:
        return False
    if t_port is not None and u_port != t_port:
        return False
    return True


def _read_bounded(response: object, limit: int) -> tuple[bytes, int]:
    """Retain up to ``limit`` bytes; report the observed size separately."""
    raw = response.read(limit + 1)  # type: ignore[attr-defined]
    observed = len(raw)
    content_length = str(response.headers.get("Content-Length") or "").strip()  # type: ignore[attr-defined]
    if content_length.isdigit():
        observed = max(observed, int(content_length))
    return raw[:limit], observed


def run_probe(
    *,
    target: str,
    url: str,
    method: str = "GET",
    data: str = "",
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    state_changing: bool = False,
    redline_checked: bool = False,
    no_ledger: bool = False,
    vuln_class: str = "IDOR",
    actor: str = "owner",
    variant: str = "baseline",
    result: str = "lead",
    note: str = "",
    repo_root: Path | str = BASE_DIR,
) -> dict:
    """Send one request and record it.

    Raises ``ProbeError`` before any network I/O when arguments, scope, or the
    state-changing/red-line flag discipline are rejected. Network failures
    propagate as ``urllib.error.URLError``/``OSError``; ledger failures after a
    successful request are captured in the returned ``ledger`` sub-dict so the
    on-disk probe evidence is never lost silently.
    """
    # Flag discipline first: mirrors validation_runner's pre-request gate.
    if state_changing and not redline_checked:
        raise ProbeError(
            "state-changing probe requires --redline-checked before any request"
        )
    if timeout <= 0:
        raise ProbeError("timeout must be positive")
    if max_body_bytes < 1:
        raise ProbeError("max_body_bytes must be positive")
    if not str(target or "").strip():
        raise ProbeError("target is required")
    parsed = urlparse(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProbeError("probe URL must be an absolute http(s) URL")
    if not url_matches_target_scope(url, target):
        u_host, u_port, _ = _parse_authority(url)
        t_host, t_port, _ = _parse_authority(target)
        u_authority = f"{u_host}:{u_port}" if u_port is not None else u_host
        t_authority = f"{t_host}:{t_port}" if t_port is not None else t_host
        raise ProbeError(
            "probe URL is outside target scope: "
            f"{u_authority or '(no host)'} does not belong to target "
            f"{t_authority or target}"
        )
    # Ledger-side enums are validated with the exact normalizers record_entry
    # uses, but before the request: a typo must fail here rather than after a
    # request has fired and orphaned an unledgered probe file. Empty strings
    # fall back exactly the way record_entry's own normalizers do — probe does
    # not add gates the ledger owner does not have.
    try:
        normalize_ledger_vuln_class(vuln_class)
        normalize_actor(actor or "owner")
        normalize_variant(variant or "baseline")
        normalize_result(result or "lead")
    except ValueError as exc:
        raise ProbeError(str(exc)) from exc

    repo = Path(repo_root)
    method_u = str(method or "GET").strip().upper()
    request_headers = {str(k): str(v) for k, v in (headers or {}).items()}
    data_text = str(data or "")
    data_bytes = data_text.encode("utf-8") if data_text else None

    request = urllib.request.Request(
        url,
        data=data_bytes,
        headers=request_headers,
        method=method_u,
    )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw, observed_bytes = _read_bounded(response, max_body_bytes)
            status = int(response.status)
            reason = str(response.reason or "")
            response_headers = {str(k): str(v) for k, v in response.headers.items()}
            final_url = str(response.geturl() or url)
    except urllib.error.HTTPError as exc:
        raw, observed_bytes = _read_bounded(exc, max_body_bytes)
        status = int(exc.code)
        reason = str(exc.reason or "")
        response_headers = {str(k): str(v) for k, v in exc.headers.items()}
        final_url = str(exc.geturl() or url)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    body_sha256 = hashlib.sha256(raw).hexdigest()
    body_text = raw.decode("utf-8", errors="replace")
    body_truncated = observed_bytes > len(raw)
    ts = datetime.now(timezone.utc)
    ts_compact = ts.strftime("%Y%m%dT%H%M%S") + f"{ts.microsecond // 1000:03d}Z"
    stem = f"{ts_compact}-{body_sha256[:8]}"

    resolved_target = canonical_target_value(target)
    probe_dir = repo / "evidence" / target_storage_key(resolved_target) / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_payload = {
        "kind": "probe",
        "schema_version": 1,
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": resolved_target,
        "request": {
            "method": method_u,
            "url": url,
            "headers": request_headers,
            "body": data_text,
            "timeout_seconds": timeout,
        },
        "response": {
            "status": status,
            "reason": reason,
            "headers": response_headers,
            "body": body_text,
            "body_sha256": body_sha256,
            "body_retained_bytes": len(raw),
            "body_observed_bytes": observed_bytes,
            "body_truncated": body_truncated,
            "final_url": final_url,
        },
        "elapsed_ms": elapsed_ms,
        "flags": {
            "state_changing": bool(state_changing),
            "redline_checked": bool(redline_checked),
        },
    }
    encoded_payload = (
        json.dumps(probe_payload, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    # Two probes in the same millisecond with identical bodies would otherwise
    # collide on `<ts>-<hash8>.json`: the second write would overwrite the
    # first, and record_entry would silently dedupe the shared event_id.
    # Exclusive-create plus a -N suffix keeps every probe its own file and
    # its own ledger event; the retry is unbounded so evidence is never
    # dropped after a request has already fired.
    probe_path: Path | None = None
    unique_stem = stem
    attempt = 0
    while probe_path is None:
        attempt += 1
        suffix = "" if attempt == 1 else f"-{attempt}"
        candidate = probe_dir / f"{stem}{suffix}.json"
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded_payload)
        probe_path = candidate
        unique_stem = f"{stem}{suffix}"
    try:
        evidence_ref = str(probe_path.relative_to(repo))
    except ValueError:  # probe dir outside repo root: keep the absolute path
        evidence_ref = str(probe_path)

    ledger: dict = {
        "recorded": False,
        "state_changing": bool(state_changing),
        "redline_checked": bool(redline_checked),
        "source": "probe",
        "result": str(result or "lead"),
    }
    if no_ledger:
        ledger["skipped"] = "--no-ledger"
    else:
        try:
            entry = record_entry(
                repo,
                target=target,
                endpoint=url,
                method=method_u,
                vuln_class=vuln_class,
                actor=actor,
                variant=variant,
                source="probe",
                result=result,
                state_changing=bool(state_changing),
                redline_checked=bool(redline_checked),
                evidence_ref=evidence_ref,
                notes=note,
                event_id=f"probe-{unique_stem}",
            )
            ledger.update(
                recorded=True,
                event_id=str(entry.get("event_id") or ""),
                write_status=str(entry.get("write_status") or ""),
                evidence_ref=str(entry.get("evidence_ref") or evidence_ref),
                result=str(entry.get("result") or ""),
            )
        except (ValueError, OSError) as exc:
            # The request already happened: keep the on-disk probe evidence and
            # surface the ledger failure loudly instead of dropping it.
            ledger["error"] = str(exc)

    outcome = {
        "target": resolved_target,
        "url": url,
        "final_url": final_url,
        "method": method_u,
        "status": status,
        "reason": reason,
        "elapsed_ms": elapsed_ms,
        "request_headers": request_headers,
        "response_headers": response_headers,
        "body_bytes": len(raw),
        "body_observed_bytes": observed_bytes,
        "body_truncated": body_truncated,
        "body_sha256": body_sha256,
        "body_sha256_16": body_sha256[:16],
        "body_display": body_text[:DISPLAY_BODY_LIMIT],
        "body_display_truncated": len(body_text) > DISPLAY_BODY_LIMIT,
        "probe_file": evidence_ref,
        "ledger": ledger,
    }
    outcome["ledger_echo"] = _ledger_echo(ledger, evidence_ref)
    return outcome


def _ledger_echo(ledger: dict, evidence_ref: str) -> str:
    """Explicit end-of-output echo so the AI must see what was recorded."""
    if ledger.get("skipped") == "--no-ledger":
        return "LEDGER: NOT RECORDED (--no-ledger)"
    if not ledger.get("recorded"):
        return f"LEDGER: NOT RECORDED (ledger error: {ledger.get('error', 'unknown')})"
    return (
        "LEDGER: state_changing={state_changing} redline_checked={redline_checked} "
        "event={event} ref={ref} result={result} source=probe"
    ).format(
        state_changing=ledger["state_changing"],
        redline_checked=ledger["redline_checked"],
        event=ledger.get("event_id") or "-",
        ref=ledger.get("evidence_ref") or evidence_ref,
        result=ledger.get("result") or "-",
    )


def format_outcome(outcome: dict) -> str:
    lines = [
        f"PROBE {outcome['method']} {outcome['url']}",
        f"TARGET {outcome['target']}",
        f"STATUS {outcome['status']} {outcome['reason']} ({outcome['elapsed_ms']} ms)",
    ]
    if 300 <= int(outcome.get("status") or 0) <= 399:
        lines.append(
            "REDIRECT NOT FOLLOWED — probe the Location URL explicitly "
            "(it was NOT auto-requested; check it against target scope first)"
        )
    if outcome.get("final_url") and outcome["final_url"] != outcome["url"]:
        lines.append(f"FINAL URL {outcome['final_url']} (redirect not followed)")
    request_headers = outcome.get("request_headers") or {}
    if request_headers:
        lines.append("REQUEST HEADERS")
        lines.extend(f"  {k}: {v}" for k, v in request_headers.items())
    lines.append("RESPONSE HEADERS")
    lines.extend(f"  {k}: {v}" for k, v in (outcome.get("response_headers") or {}).items())
    lines.append(
        "BODY {retained} bytes retained of {total} observed, sha256={sha} (first 16)".format(
            retained=outcome.get("body_bytes", 0),
            total=outcome.get("body_observed_bytes") or outcome.get("body_bytes") or 0,
            sha=outcome.get("body_sha256_16", ""),
        )
    )
    display = outcome.get("body_display") or ""
    if display:
        lines.append(display)
    if outcome.get("body_display_truncated") or outcome.get("body_truncated"):
        lines.append("...[body display truncated; full retained body in probe file]")
    lines.append(f"PROBE FILE {outcome.get('probe_file', '')}")
    lines.append(outcome.get("ledger_echo", ""))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probe",
        description=(
            "Transparently-ledgered single request: scope check, pass-through "
            "request, on-disk evidence, automatic evidence ledger append. "
            "Redirects are NOT followed (curl default semantics, not curl -L): "
            "a 3xx is returned as-is with its Location header."
        ),
        epilog=(
            "examples:\n"
            '  python3 tools/probe.py --target 127.0.0.1:3001 --url http://127.0.0.1:3001/rest/basket/7\n'
            '  python3 tools/probe.py --target example.com --url https://example.com/api --method POST --data \'{"q":1}\'\n'
            "\n"
            "A 302 to another origin does not auto-follow: probe the Location "
            "URL yourself after checking it against the target's scope."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="canonical target (host[:port] or URL)")
    parser.add_argument("--url", required=True, help="absolute http(s) URL to request")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--data", default="", help="request body text (sent as-is)")
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'K: V'",
        help="request header, repeatable",
    )
    parser.add_argument(
        "--vuln-class",
        default="IDOR",
        help=(
            "ledger evidence family tag (archival label, not a judgment; default "
            "matches evidence_ledger record's own default). Accepts the ledger "
            "families: IDOR, SSRF, XSS, Race, Authz, GraphQL, OAuth, Upload, "
            "Webhook, JWT, SQLi, XXE, RCE, Path, CSRF, NoSQLi, "
            "PrototypePollution, OpenRedirect, BusinessLogic, Workflow."
        ),
    )
    parser.add_argument("--actor", default="owner", help="ledger actor (anonymous/owner/peer/low_role/admin/cross_tenant)")
    parser.add_argument("--variant", default="baseline", help="ledger variant (baseline/id_swap/role_diff/...)")
    parser.add_argument(
        "--result",
        default="lead",
        choices=list(RESULTS),
        help="ledger result; default lead — a probe produces a lead, never a conclusion",
    )
    parser.add_argument("--note", default="", help="free-text note recorded with the ledger entry")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="request timeout seconds (default 10)")
    parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=DEFAULT_MAX_BODY_BYTES,
        help="bounded-retention cap for response bodies (default 10 MiB); larger bodies are retained truncated and flagged",
    )
    parser.add_argument(
        "--state-changing",
        action="store_true",
        help="record this request as state-changing; requires --redline-checked",
    )
    parser.add_argument(
        "--redline-checked",
        action="store_true",
        help="asserts the effect was evaluated against rules/red-lines.md",
    )
    parser.add_argument(
        "--no-ledger",
        action="store_true",
        help="skip the evidence ledger append (probe JSON still written); output marks NOT RECORDED",
    )
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    headers: dict[str, str] = {}
    for raw in args.header:
        name, separator, value = raw.partition(":")
        if not separator or not name.strip():
            parser.error(f"--header expects 'K: V' form, got: {raw!r}")
        headers[name.strip()] = value.strip()
    try:
        outcome = run_probe(
            target=args.target,
            url=args.url,
            method=args.method,
            data=args.data,
            headers=headers,
            timeout=args.timeout,
            max_body_bytes=args.max_body_bytes,
            state_changing=args.state_changing,
            redline_checked=args.redline_checked,
            no_ledger=args.no_ledger,
            vuln_class=args.vuln_class,
            actor=args.actor,
            variant=args.variant,
            result=args.result,
            note=args.note,
            repo_root=args.repo_root,
        )
    except ProbeError as exc:
        print(f"probe error: {exc}", file=sys.stderr)
        return 2
    except (urllib.error.URLError, OSError) as exc:
        print(f"probe request failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(outcome, ensure_ascii=False, indent=2))
    else:
        print(format_outcome(outcome))

    if args.no_ledger:
        return 0
    if not outcome["ledger"].get("recorded"):
        print(
            f"probe ledger error: {outcome['ledger'].get('error', 'unknown')}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
