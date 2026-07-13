#!/usr/bin/env python3
"""
sibling_worker.py — single-process sibling-probe execution worker.

Spawned by parallel_workers.spawn_sibling_worker. Tests one seed
finding by expanding it through sibling_generator and HTTP-probing
each sibling endpoint until budget or timeout is reached.

Writes:
    <scratch_dir>/attempts.jsonl
    <scratch_dir>/findings.json
    <scratch_dir>/done.flag         (touched at termination)

Worker is intentionally lightweight — no Ollama, no LLM. The parent
agent reads findings.json + attempts.jsonl after join.

Sibling-probe outcome rules (B6 R6):
    Confirmed sibling finding ⇐ HTTP 200 with non-empty body AND a
    ID-bearing path that returns object-shaped data (heuristic — JSON
    starts with `{` or `[`). Anything else is recorded as an attempt
    only.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tools.sibling_generator import extract_template, find_siblings, _load_all_urls  # noqa: E402

USER_AGENT = "claude-bug-bounty/sibling-worker"
HTTP_TIMEOUT_SECS = 10
DEFAULT_LIMITER_TEST_RPS = 1.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _record_attempt(scratch: Path, payload: dict) -> None:
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    with open(scratch / "attempts.jsonl", "a", encoding="utf-8") as fh:
        fh.write(line)


def _write_findings(scratch: Path, findings: list[dict]) -> None:
    (scratch / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")


def _touch_done(scratch: Path, summary: dict) -> None:
    (scratch / "done.flag").write_text(
        json.dumps(summary, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _http_probe(url: str) -> dict:
    """Lightweight GET; returns {status, snippet, error?}."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECS) as resp:
            body = resp.read(4096)
            text = body.decode("utf-8", errors="ignore")
            return {
                "status": resp.status,
                "snippet": text[:512],
                "content_type": resp.headers.get("Content-Type", ""),
            }
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "snippet": "", "error": "http_error"}
    except urllib.error.URLError as exc:
        return {"status": None, "snippet": "", "error": f"url_error:{exc.reason}"}
    except (TimeoutError, socket.timeout):
        return {"status": None, "snippet": "", "error": "timeout"}
    except Exception as exc:  # pragma: no cover
        return {"status": None, "snippet": "", "error": f"exception:{exc}"}


def _looks_like_object_response(probe: dict) -> bool:
    if probe.get("status") != 200:
        return False
    snippet = (probe.get("snippet") or "").lstrip()
    if not snippet:
        return False
    return snippet.startswith("{") or snippet.startswith("[")


def _build_target_url(target: str, path: str) -> str:
    """Compose a probe URL for a path under the target host.

    Scheme selection:
      - if target already includes a scheme, honour it
      - if target is loopback/private (127.x, localhost, 10.x, 192.168.x,
        172.16-31.x), default to http://
      - otherwise default to https://
    """
    if "://" in target:
        base = target.rstrip("/")
    else:
        host = target.split(":", 1)[0]
        is_local = (
            host in {"localhost", "127.0.0.1", "0.0.0.0"}
            or host.startswith("127.")
            or host.startswith("10.")
            or host.startswith("192.168.")
            or any(host.startswith(f"172.{n}.") for n in range(16, 32))
        )
        scheme = "http" if is_local else "https"
        base = f"{scheme}://{target}".rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _select_global_limiter(scratch: Path):
    """Return a GlobalRateLimiter or None (only when state file is reachable)."""
    try:
        from tools.parallel_workers import GlobalRateLimiter      # noqa: WPS433
        return GlobalRateLimiter(test_rps=DEFAULT_LIMITER_TEST_RPS)
    except Exception:
        return None


def _install_timeout_alarm(timeout_secs: int) -> None:
    """SIGALRM trips after timeout_secs (POSIX only)."""
    def _on_alarm(signum, frame):  # pragma: no cover - exit path
        sys.stderr.write(f"sibling_worker: timeout after {timeout_secs}s\n")
        os._exit(2)
    try:
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(int(max(1, timeout_secs)))
    except (AttributeError, ValueError):
        pass


def _cancel_timeout_alarm() -> None:
    """正常完成后清除 SIGALRM，避免 worker 定时器影响宿主进程。"""
    try:
        signal.alarm(0)
    except (AttributeError, ValueError):
        pass


def run_worker(seed_path: Path, scratch: Path, target: str, budget_tools: int) -> dict:
    """Main worker loop. Returns summary dict."""
    seed = json.loads(Path(seed_path).read_text(encoding="utf-8"))
    seed_finding = seed.get("seed_finding") or {}
    endpoint = str(seed_finding.get("endpoint") or seed_finding.get("url") or "")

    summary = {
        "kind": "sibling",
        "worker_id": seed.get("worker_id"),
        "target": target,
        "started_at": _utc_now(),
        "seed_endpoint": endpoint,
        "probes_attempted": 0,
        "probes_confirmed": 0,
        "budget_tools": budget_tools,
        "exit_reason": "completed",
        "parent_session": seed.get("parent_session"),
    }

    if not endpoint:
        summary["exit_reason"] = "no_endpoint_in_seed"
        summary["finished_at"] = _utc_now()
        return summary

    template = extract_template(endpoint)
    all_urls = _load_all_urls(target, BASE_DIR)
    siblings = find_siblings(template, all_urls, max_count=budget_tools)

    findings: list[dict] = []
    limiter = _select_global_limiter(scratch)

    for sib in siblings:
        if summary["probes_attempted"] >= budget_tools:
            summary["exit_reason"] = "budget_exhausted"
            break
        path = sib.get("endpoint", "")
        url = _build_target_url(target, path)
        host = urlparse(url).netloc or target
        if limiter is not None:
            try:
                limiter.wait(host, is_recon=False)
            except Exception:
                pass
        probe = _http_probe(url)
        attempt = {
            "ts": _utc_now(),
            "url": url,
            "method": "GET",
            "result": probe,
            "rationale": sib.get("rationale", ""),
            "worker_id": seed.get("worker_id"),
            "parent_session": seed.get("parent_session"),
        }
        _record_attempt(scratch, attempt)
        summary["probes_attempted"] += 1
        if _looks_like_object_response(probe):
            findings.append({
                "id": f"{seed.get('worker_id')}-{summary['probes_attempted']}",
                "endpoint": path,
                "url": url,
                "vuln_class": str(seed_finding.get("vuln_class") or "IDOR"),
                "severity": str(seed_finding.get("severity") or "medium"),
                "method": "GET",
                "evidence_status": probe.get("status"),
                "evidence_snippet": probe.get("snippet", "")[:240],
                "discovered_at": _utc_now(),
                "source": "sibling_worker",
                "seed_finding_id": seed_finding.get("id"),
                "worker_id": seed.get("worker_id"),
            })
            summary["probes_confirmed"] += 1
            _write_findings(scratch, findings)

    if not findings:
        _write_findings(scratch, findings)

    summary["finished_at"] = _utc_now()
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="sibling-probe worker")
    parser.add_argument("--target", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--scratch-dir", required=True)
    parser.add_argument("--budget-tools", type=int, default=12)
    parser.add_argument("--timeout-secs", type=int, default=300)
    parser.add_argument("--parent-session", default=None)
    args = parser.parse_args(argv)

    scratch = Path(args.scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)

    _install_timeout_alarm(args.timeout_secs)

    try:
        summary = run_worker(
            seed_path=Path(args.seed),
            scratch=scratch,
            target=args.target,
            budget_tools=args.budget_tools,
        )
    except Exception as exc:  # pragma: no cover
        summary = {
            "kind": "sibling",
            "target": args.target,
            "exit_reason": f"worker_exception:{exc}",
            "finished_at": _utc_now(),
        }
    finally:
        _touch_done(scratch, summary)
        _cancel_timeout_alarm()

    return 0


if __name__ == "__main__":
    sys.exit(main())
