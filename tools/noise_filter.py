#!/usr/bin/env python3
"""SPA-fallback fingerprinting and gau-noise dedup helpers.

Three subcommands:

  fingerprint --hosts FILE --out FILE
      For each host (one URL per line), GET a guaranteed-bogus path and record
      {status, body_sha, body_size, content_type}. Used by `filter`.

  filter --findings FILE --fingerprints FILE [--keep FILE] [--drop FILE]
      Re-fetch each URL listed in --findings (one URL token per line, or the
      raw line if it looks URL-shaped); compare its body sha against the host
      fingerprint. Matches → suppressed; mismatches → kept.

  dedup --in FILE --out FILE [--no-live] [--http-timeout 5]
      Run p1radup (param-key dedup) then httpx (-mc 200,301,302,401,403)
      liveness check. Writes deduped + live URLs. Fail-open: on any subprocess
      error returns the original file content.

Design goals:
  * Fail open. Any subprocess failure or parse error degrades back to the
    original input so the scanner pipeline never regresses.
  * No new third-party Python deps; uses urllib + subprocess for p1radup/httpx.
  * Output formats stable (JSON / one-URL-per-line) so downstream consumers
    don't change.
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
import time
import urllib.parse
import urllib.request
from pathlib import Path

# ---- HTTP helpers ----------------------------------------------------------

USER_AGENT = "claude-bug-bounty/noise_filter"
DEFAULT_TIMEOUT = 6.0
BODY_HASH_CAP = 16 * 1024  # hash first 16KB for stability
SPA_HASH_THRESHOLD = 0.97  # body_size relative diff < 3% AND sha match -> SPA


def _bogus_path(seed: int) -> str:
    return f"/__noise_filter_{seed}_{int(time.time())}__"


def _http_get(url: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, bytes, str]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(BODY_HASH_CAP * 2)
            ct = resp.headers.get("Content-Type", "")
            return status, body, ct
    except urllib.error.HTTPError as e:
        try:
            body = e.read(BODY_HASH_CAP * 2)
        except Exception:
            body = b""
        return e.code, body, e.headers.get("Content-Type", "") if e.headers else ""
    except Exception:
        return 0, b"", ""


def _body_sha(body: bytes) -> str:
    return hashlib.sha256(body[:BODY_HASH_CAP]).hexdigest()


def _host_root(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


# ---- fingerprint subcommand ------------------------------------------------


def cmd_fingerprint(args: argparse.Namespace) -> int:
    hosts_path = Path(args.hosts).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not hosts_path.is_file():
        # fail open — empty fingerprints
        out_path.write_text(json.dumps({"fingerprints": {}, "note": "no hosts input"}, indent=2))
        return 0

    seen_roots: dict[str, dict] = {}
    seed = 0
    timeout = float(args.timeout or DEFAULT_TIMEOUT)
    for line in hosts_path.read_text(encoding="utf-8", errors="replace").splitlines():
        root = _host_root(line)
        if not root or root in seen_roots:
            continue
        seed += 1
        bogus_url = root + _bogus_path(seed)
        status, body, ct = _http_get(bogus_url, timeout=timeout)
        seen_roots[root] = {
            "status": status,
            "body_sha": _body_sha(body),
            "body_size": len(body),
            "content_type": ct,
        }

    payload = {
        "generated_at": int(time.time()),
        "host_count": len(seen_roots),
        "fingerprints": seen_roots,
        "threshold": SPA_HASH_THRESHOLD,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[noise_filter] fingerprint hosts={len(seen_roots)} -> {out_path}")
    return 0


# ---- filter subcommand -----------------------------------------------------


URL_TOKEN_RE = re.compile(r"https?://[^\s\"'`<>]+")


def _extract_url(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    if line.startswith(("http://", "https://")):
        return line.split()[0]
    m = URL_TOKEN_RE.search(line)
    return m.group(0) if m else ""


def _is_spa_fallback(url: str, fp: dict, timeout: float) -> bool:
    status, body, _ = _http_get(url, timeout=timeout)
    if status == 0:
        return False
    if status != fp["status"]:
        return False
    if _body_sha(body) == fp["body_sha"]:
        return True
    expected = fp.get("body_size", 0)
    actual = len(body)
    if expected and actual:
        ratio = min(expected, actual) / max(expected, actual)
        if ratio >= SPA_HASH_THRESHOLD and abs(actual - expected) < 256:
            return True
    return False


def cmd_filter(args: argparse.Namespace) -> int:
    findings = Path(args.findings).expanduser().resolve()
    fp_path = Path(args.fingerprints).expanduser().resolve()
    keep_path = Path(args.keep).expanduser().resolve() if args.keep else None
    drop_path = Path(args.drop).expanduser().resolve() if args.drop else None
    timeout = float(args.timeout or DEFAULT_TIMEOUT)

    if not findings.is_file():
        return 0
    if not fp_path.is_file():
        # fail open — keep everything
        if keep_path:
            keep_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(findings, keep_path)
        return 0

    try:
        fp_data = json.loads(fp_path.read_text(encoding="utf-8"))
    except Exception:
        if keep_path:
            keep_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(findings, keep_path)
        return 0

    fps = fp_data.get("fingerprints", {})
    kept: list[str] = []
    dropped: list[str] = []
    for line in findings.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        url = _extract_url(line)
        if not url:
            kept.append(line)
            continue
        root = _host_root(url)
        fp = fps.get(root)
        if not fp:
            kept.append(line)
            continue
        if _is_spa_fallback(url, fp, timeout=timeout):
            dropped.append(line)
        else:
            kept.append(line)

    if keep_path:
        keep_path.parent.mkdir(parents=True, exist_ok=True)
        keep_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    if drop_path:
        drop_path.parent.mkdir(parents=True, exist_ok=True)
        drop_path.write_text("\n".join(dropped) + ("\n" if dropped else ""), encoding="utf-8")
    # If --keep was not provided, rewrite the findings file in place with kept-only
    # content (drops go to drop_path if provided, otherwise are discarded). This
    # matches the common scanner-pipeline use case of post-processing existing
    # findings files in place.
    if not keep_path:
        findings.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    print(f"[noise_filter] filter kept={len(kept)} dropped={len(dropped)} ({findings.name})")
    return 0


# ---- dedup subcommand ------------------------------------------------------


def _resolve_bin(name: str) -> str:
    """Locate executables that may sit outside the default PATH for CI/dev envs."""
    for candidate in (
        name,
        os.path.expanduser(f"~/.local/bin/{name}"),
        f"/usr/local/bin/{name}",
        os.path.expanduser(f"~/go/bin/{name}"),
    ):
        path = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if path:
            return path
    return ""


def _run_p1radup(in_path: Path, out_path: Path, timeout: int = 120) -> tuple[bool, str]:
    """Return (success, reason). Distinguishes missing binary from empty output."""
    bin_path = _resolve_bin("p1radup")
    if not bin_path:
        return False, "binary_missing"
    try:
        proc = subprocess.run(
            [bin_path, "-i", str(in_path), "-o", str(out_path), "-s"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except Exception as exc:
        return False, f"subprocess_error:{type(exc).__name__}"
    if proc.returncode != 0:
        return False, f"exit_{proc.returncode}"
    if not out_path.is_file() or out_path.stat().st_size == 0:
        return False, "empty_output"  # e.g. validators rejected all URLs (localhost/IP)
    return True, "ok"


def _builtin_dedup(in_path: Path, out_path: Path) -> int:
    """Fail-open Python dedup by (scheme, host, path, sorted param keys).

    Mirrors p1radup default behaviour (one URL per unique param-key signature
    per host+path) without going through the `validators` package, so it works
    for loopback / private-range hosts that p1radup rejects.
    """
    seen: set[tuple] = set()
    kept: list[str] = []
    for raw in in_path.read_text(encoding="utf-8", errors="replace").splitlines():
        url = _extract_url(raw)
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        param_keys = tuple(sorted({k for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}))
        sig = (parsed.scheme, parsed.netloc, parsed.path, param_keys)
        if sig in seen:
            continue
        seen.add(sig)
        kept.append(url)
    out_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    return len(kept)


def _run_httpx_live(in_path: Path, out_path: Path, timeout: int = 180) -> tuple[bool, str]:
    """Return (success, reason). 0-match is success (yields empty output)."""
    bin_path = _resolve_bin("httpx")
    if not bin_path:
        return False, "binary_missing"
    try:
        proc = subprocess.run(
            [
                bin_path,
                "-l", str(in_path),
                "-mc", "200,301,302,307,401,403",
                "-silent",
                "-t", "30",
                "-rl", "150",
                "-timeout", "5",
                "-o", str(out_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except Exception as exc:
        return False, f"subprocess_error:{type(exc).__name__}"
    if proc.returncode != 0:
        return False, f"exit_{proc.returncode}"
    # 0-match is valid output — httpx may not create the file, materialize empty.
    if not out_path.is_file():
        out_path.write_text("", encoding="utf-8")
    return True, "ok"


def cmd_dedup(args: argparse.Namespace) -> int:
    in_path = Path(args.input).expanduser().resolve()
    out_path = Path(args.output).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not in_path.is_file() or in_path.stat().st_size == 0:
        out_path.write_text("", encoding="utf-8")
        return 0

    original_count = sum(1 for _ in in_path.read_text(encoding="utf-8", errors="replace").splitlines() if _.strip())
    print(f"[noise_filter] dedup begin in={original_count} URLs ...", file=sys.stderr, flush=True)
    t_start = time.time()

    with tempfile.TemporaryDirectory(prefix="noise_filter_") as tmpdir:
        dedup_path = Path(tmpdir) / "dedup.txt"
        live_path = Path(tmpdir) / "live.txt"

        # Step 1: p1radup, fall back to built-in dedup on rejection (loopback/IP hosts)
        ok, reason = _run_p1radup(in_path, dedup_path)
        if ok:
            stage1 = dedup_path
            dedup_engine = "p1radup"
        else:
            _builtin_dedup(in_path, dedup_path)
            stage1 = dedup_path
            dedup_engine = f"builtin_fallback({reason})"

        dedup_count = sum(1 for _ in stage1.read_text(encoding="utf-8", errors="replace").splitlines() if _.strip())
        print(f"[noise_filter]   dedup stage: {original_count} -> {dedup_count} via {dedup_engine} ({time.time()-t_start:.1f}s)", file=sys.stderr, flush=True)

        # Step 2: httpx liveness (optional)
        if args.no_live:
            shutil.copyfile(stage1, out_path)
            live_count = dedup_count
            live_engine = "skip"
        else:
            print(f"[noise_filter]   liveness probe: testing {dedup_count} URLs with httpx ...", file=sys.stderr, flush=True)
            t_httpx = time.time()
            ok2, reason2 = _run_httpx_live(stage1, live_path)
            if ok2:
                shutil.copyfile(live_path, out_path)
                live_count = sum(1 for _ in live_path.read_text(encoding="utf-8", errors="replace").splitlines() if _.strip())
                live_engine = "httpx"
                print(f"[noise_filter]   liveness stage: {dedup_count} -> {live_count} via httpx ({time.time()-t_httpx:.1f}s)", file=sys.stderr, flush=True)
            else:
                shutil.copyfile(stage1, out_path)
                live_count = dedup_count
                live_engine = f"skip({reason2})"
                print(f"[noise_filter]   liveness stage: skipped ({reason2})", file=sys.stderr, flush=True)

    print(f"[noise_filter] dedup orig={original_count} dedup={dedup_count}/{dedup_engine} live={live_count}/{live_engine} -> {out_path}")
    return 0


# ---- entry point -----------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SPA-fallback fingerprint + gau-noise dedup helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    fp = sub.add_parser("fingerprint", help="Compute SPA-fallback body fingerprints for hosts")
    fp.add_argument("--hosts", required=True, help="File with one URL per line (host roots will be extracted)")
    fp.add_argument("--out", required=True, help="Output JSON path")
    fp.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    fp.set_defaults(func=cmd_fingerprint)

    flt = sub.add_parser("filter", help="Drop findings whose URLs return the host's SPA-fallback body")
    flt.add_argument("--findings", required=True, help="Findings file (URLs, optionally prefixed)")
    flt.add_argument("--fingerprints", required=True, help="JSON produced by `fingerprint`")
    flt.add_argument("--keep", default="", help="Output path for kept lines (if empty, rewrites findings in place)")
    flt.add_argument("--drop", default="", help="Optional output path for dropped lines")
    flt.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    flt.set_defaults(func=cmd_filter)

    dd = sub.add_parser("dedup", help="p1radup + httpx liveness for a URL list")
    dd.add_argument("--input", required=True, help="Input URL list")
    dd.add_argument("--output", required=True, help="Output filtered URL list")
    dd.add_argument("--no-live", action="store_true", help="Skip httpx liveness")
    dd.set_defaults(func=cmd_dedup)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
