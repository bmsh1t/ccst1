#!/bin/bash
# Bounded upstream Nuclei execution over live/explicit-priority inputs.
# Scope/Auth and the existing phase lock admit execution; native review owns
# hypotheses and findings. Per-run raw artifacts survive retries and failures.
# Usage: vuln_scanner.sh RECON_DIR [--quick|--full] [--skip CSV]
set -euo pipefail
umask 077

RECON_DIR=""
SCAN_MODE=standard
SKIP_CHECKS=""
PHASE_ARGS=("$@")
while [ "$#" -gt 0 ]; do
    case "$1" in
        --quick) SCAN_MODE=quick ;;
        --full) SCAN_MODE=full ;;
        --skip)
            shift
            [ "$#" -gt 0 ] || { echo '--skip requires a value' >&2; exit 2; }
            SKIP_CHECKS="${SKIP_CHECKS}${SKIP_CHECKS:+,}$1" ;;
        --skip=*) SKIP_CHECKS="${SKIP_CHECKS}${SKIP_CHECKS:+,}${1#--skip=}" ;;
        -*) echo "Unknown option: $1" >&2; exit 2 ;;
        *)
            [ -z "$RECON_DIR" ] || { echo "Unexpected argument: $1" >&2; exit 2; }
            RECON_DIR="$1" ;;
    esac
    shift
done
SKIP_CHECKS="$(python3 - "$SKIP_CHECKS" <<'PY'
import sys
print(",".join(dict.fromkeys(value.strip().lower() for value in sys.argv[1].split(",") if value.strip())))
PY
)"
[ -n "$RECON_DIR" ] && [ -d "$RECON_DIR" ] || {
    echo 'Usage: vuln_scanner.sh RECON_DIR [--quick|--full] [--skip CSV]' >&2
    exit 2
}
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RECON_DIR="$(cd "$RECON_DIR" && pwd)"
export PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

SESSION_ID=""
if [ "$(basename "$(dirname "$RECON_DIR")")" = sessions ]; then
    SESSION_ID="$(basename "$RECON_DIR")"
    TARGET_HINT="$(basename "$(dirname "$(dirname "$RECON_DIR")")")"
else
    TARGET_HINT="$(basename "$RECON_DIR")"
fi
SCANNER_AUTH_TARGET="$(python3 - "$RECON_DIR/recon_manifest.jsonl" "$TARGET_HINT" <<'PY'
import json
import sys
from pathlib import Path
from tools.target_paths import canonical_target_value

path, fallback = sys.argv[1:]
target = fallback
if Path(path).is_file():
    with Path(path).open(encoding="utf-8") as handle:
        for raw in handle:
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("target"):
                target = str(row["target"])
                break
canonical_target_value(target)
print(target)
PY
)"
TARGET="$(python3 - "$SCANNER_AUTH_TARGET" <<'PY'
import sys
from tools.target_paths import canonical_target_value
print(canonical_target_value(sys.argv[1]))
PY
)"
if [ "${BBHUNT_RUNTIME_PHASE_LOCKED:-}" != scan ] || [ "${BBHUNT_RUNTIME_LOCK_TARGET:-}" != "$TARGET" ]; then
    exec python3 "$BASE_DIR/tools/runtime_phase_exec.py" \
        --repo-root "$BASE_DIR" --target "$TARGET" --phase scan -- \
        bash "$BASE_DIR/tools/vuln_scanner.sh" "${PHASE_ARGS[@]}"
fi
SCANNER_AUTH_SOURCE_TARGET="${BBHUNT_AUTH_TARGET:-}"
. "$BASE_DIR/tools/_auth_helper.sh"
bb_auth_bind_target "$SCANNER_AUTH_TARGET"
# The shell helper clears cross-target credentials, but its same-target rebind
# replaces URL scheme/port with the invocation target. Keep the original binding
# for AuthSession to intersect/narrow before selecting upstream origins.
if bb_auth_active && [ -n "$SCANNER_AUTH_SOURCE_TARGET" ]; then
    export BBHUNT_AUTH_TARGET="$SCANNER_AUTH_SOURCE_TARGET"
fi

# No artifact writes before the existing Store admission succeeds.
python3 - "$BASE_DIR" "$TARGET" <<'PY'
import sys
from tools.target_store import runtime_store
runtime_store(sys.argv[1], sys.argv[2])
PY
TARGET_KEY="$(python3 - "$TARGET" <<'PY'
import sys
from tools.target_paths import target_storage_key
print(target_storage_key(sys.argv[1]))
PY
)"
DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET_KEY"
[ -z "$SESSION_ID" ] || DEFAULT_FINDINGS_DIR="$DEFAULT_FINDINGS_DIR/sessions/$SESSION_ID"
FINDINGS_DIR="${FINDINGS_OUT_DIR:-$DEFAULT_FINDINGS_DIR}"
FINDINGS_DIR="$(python3 - "$BASE_DIR" "$TARGET_KEY" "$FINDINGS_DIR" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1]) / "findings" / sys.argv[2]
output = Path(sys.argv[3]).absolute()
if output.resolve() != output or (output / "nuclei_runs").resolve() != output / "nuclei_runs" or not output.is_relative_to(root):
    raise ValueError("scanner output must stay in the target findings directory without symlinks")
for name in ("summary.json", "summary.txt"):
    path = output / name
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("scanner summaries must be regular files without symlinks")
print(output)
PY
)"
case "$SCAN_MODE" in quick) DEFAULT_LIMIT=50; DEFAULT_TIMEOUT=180 ;; full) DEFAULT_LIMIT=200; DEFAULT_TIMEOUT=600 ;; *) DEFAULT_LIMIT=100; DEFAULT_TIMEOUT=600 ;; esac
TARGET_LIMIT="${BB_NUCLEI_MAX_TARGETS:-$DEFAULT_LIMIT}"
SCAN_TIMEOUT="${BB_CVE_TIMEOUT:-$DEFAULT_TIMEOUT}"
THREADS="${BB_SCAN_THREADS:-10}"
RATE_LIMIT="${BB_SCAN_RATE_LIMIT:-20}"
for value in "$TARGET_LIMIT" "$SCAN_TIMEOUT" "$THREADS" "$RATE_LIMIT"; do
    case "$value" in ''|*[!0-9]*) echo 'Scanner bounds must be positive integers' >&2; exit 2 ;; esac
    [[ "$value" =~ [1-9] ]] || { echo 'Scanner bounds must be positive integers' >&2; exit 2; }
done
mkdir -p "$FINDINGS_DIR/nuclei_runs"
RUN_DIR="$(mktemp -d "$FINDINGS_DIR/nuclei_runs/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
STATUS=incomplete
NUCLEI_RC=""
: > "$RUN_DIR/raw.jsonl"
: > "$RUN_DIR/stdout.log"
: > "$RUN_DIR/stderr.log"

publish_summary() {
    python3 - "$BASE_DIR" "$TARGET" "$SESSION_ID" "$SCAN_MODE" "$RECON_DIR" "$FINDINGS_DIR" "$RUN_DIR" \
        "$STATUS" "$NUCLEI_RC" "$TARGET_LIMIT" "$SKIP_CHECKS" "$1" <<'PY'
import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from tools.artifact_io import write_json_atomic, write_text_atomic

(repo, target, session, mode, recon, findings, run, status, rc, limit, skips, wrapper_rc) = sys.argv[1:]
root, run_dir, recon_dir = Path(findings), Path(run), Path(recon)
inputs = json.loads((run_dir / "input.json").read_text()) if (run_dir / "input.json").is_file() else {}

def count_lines(path):
    if not path.is_file():
        return 0
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return sum(bool(line.strip()) for line in handle)

records = malformed = 0
with (run_dir / "raw.jsonl").open("rb") as handle:
    for raw in handle:
        if not raw.strip():
            continue
        try:
            row = json.loads(raw.decode("utf-8"))
            if not isinstance(row, dict):
                raise ValueError("result is not an object")
            records += 1
        except (ValueError, UnicodeError):
            malformed += 1
if malformed or (int(wrapper_rc) and status in {"complete", "sampled", "running"}):
    status = "incomplete"
if malformed and not int(wrapper_rc):
    wrapper_rc = "2"
total = int(inputs.get("origin_count", 0))
attempted = int(inputs.get("selected_count", 0)) if rc else 0
completed = attempted if status in {"complete", "sampled"} and rc == "0" else 0
remaining = total - completed
relative = run_dir.relative_to(root).as_posix()
raw_path = recon_dir / "urls/raw/all.txt"
if not raw_path.is_file():
    raw_path = raw_path.with_suffix(".txt.gz")
artifacts = {name: f"{relative}/{name}" for name in (
    "raw.jsonl", "stdout.log", "stderr.log", "exit_code.rc", "version.txt",
    "input.json", "command.json", "input_candidates.txt", "ordered_scan_targets.txt",
    "previous_summary.json", "previous_summary.txt",
    "nuclei_targets_all.txt", "nuclei_targets.txt", "excluded_urls.txt",
) if (run_dir / name).is_file()}
review = (
    f"Nuclei execution: {status}; exit={rc or ('unknown' if (run_dir / 'command.json').is_file() else 'not_run')}; completed origins={completed}/{total}.\n"
    f"Raw tool records={records}; malformed records={malformed}; no finding assessment performed.\n"
    f"Artifacts: {relative}/summary.json; {relative}/raw.jsonl; {relative}/stderr.log.\n"
)
write_text_atomic(run_dir / "review.txt", review)
payload = {
    "schema_version": 1, "execution_mode": "upstream-nuclei", "status": status,
    "generated_at": datetime.now(timezone.utc).isoformat(), "target": target,
    "session_id": session or None, "mode": mode, "recon_dir": recon,
    "findings_dir": findings, "input_contract": "live-priority-origins",
    "raw_url_count": count_lines(raw_path),
    "active_url_count": count_lines(recon_dir / "urls/all.txt"),
    "parameter_url_count": count_lines(recon_dir / "urls/with_params.txt"),
    "live_count": inputs.get("live_count", 0),
    "ordered_scan_count": inputs.get("ordered_count", 0),
    "ordered_scan_file": str(run_dir / "ordered_scan_targets.txt"),
    "nuclei_target_available_count": total, "nuclei_target_count": inputs.get("selected_count", 0),
    "nuclei_target_limit": int(limit), "nuclei_targets_truncated": total > inputs.get("selected_count", 0),
    "nuclei_cve": {"status": status, "input": "origin-bounded", "exit_code": int(rc) if rc else None,
                   "attempted": attempted, "raw_record_count": records, "malformed_record_count": malformed},
    "lane_coverage": {"nuclei_default": {
        "lane": "nuclei_default", "execution_kind": "active_scanner", "status": status,
        "input_total": total, "selected": completed, "remaining": remaining,
        "continuation": f"review {relative}/summary.json and retained inputs before choosing follow-up",
        "closure_blocking": False,
    }},
    "artifacts": artifacts, "run_summary": f"{relative}/summary.json",
    "requested_skips": [value.strip() for value in skips.split(",") if value.strip()],
    "skipped_checks": ["nuclei"] if status == "skipped" else [],
    "categories": {},
    "manual_review": [{"path": f"{relative}/review.txt", "count": 3}],
    "assessment_status": "not_run", "wrapper_exit_code": int(wrapper_rc),
}
# Per-run receipt precedes the disposable latest projection. Neither is a completion marker by existence.
write_json_atomic(run_dir / "summary.json", payload)
write_text_atomic(root / "summary.txt", review)
write_json_atomic(root / "summary.json", payload)
raise SystemExit(2 if malformed else 0)
PY
}
finalize_run() {
    local wrapper_rc="$?" publish_rc=0
    trap - EXIT
    publish_summary "$wrapper_rc" || publish_rc=$?
    if [ "$publish_rc" -ne 0 ]; then
        echo "Scanner summary incomplete or publication failed; artifacts: $RUN_DIR" >&2
        [ "$wrapper_rc" -ne 0 ] || wrapper_rc=2
    fi
    exit "$wrapper_rc"
}
trap finalize_run EXIT
trap 'STATUS=incomplete; exit 130' INT
trap 'STATUS=incomplete; exit 143' TERM
# Retain the previous projection as history before clearing a stale completion claim.
python3 - "$FINDINGS_DIR" "$RUN_DIR" <<'PY'
import sys
from pathlib import Path
from tools.artifact_io import publish_bytes_create_only
root, run = map(Path, sys.argv[1:])
for name in ("summary.json", "summary.txt"):
    old = root / name
    if old.is_symlink():
        raise ValueError("scanner summary must not be a symlink")
    if old.is_file():
        publish_bytes_create_only(run / ("previous_" + name), old.read_bytes())
        old.unlink()
PY
publish_summary 0

python3 - "$BASE_DIR" "$SCANNER_AUTH_TARGET" "$RECON_DIR" "$RUN_DIR" "$TARGET_LIMIT" 2> "$RUN_DIR/stderr.log" <<'PY'
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from tools.artifact_io import write_json_atomic, write_text_atomic
from tools.auth_session import AuthSession
from tools.scope_context import url_belongs_to_target
from tools.scope_source import load_scope_context

repo, target, recon, run, limit = sys.argv[1:]
recon, run = Path(recon), Path(run)
scope = load_scope_context(repo, target)
session = AuthSession.from_env(os.environ).bind_target(target).bind_scope(scope)
live = recon / "live/urls.txt"
if not live.is_file() or not live.stat().st_size:
    live = recon / "live/httpx_full.txt"
if not live.is_file() or not live.stat().st_size:
    raise ValueError("No live input; select live target URLs before scanning")
sources = [recon / "priority" / name for name in ("critical_hosts.txt", "high_hosts.txt", "prioritized_hosts.txt")]
sources.append(live)
ordered, origins, excluded, candidates = [], [], [], []
seen, seen_origins = set(), set()
for source in sources:
    if not source.is_file():
        continue
    with source.open(encoding="utf-8") as handle:
        for raw in handle:
            value = raw.strip().split()[0] if raw.strip() else ""
            if not value:
                continue
            candidates.append(value)
            try:
                parsed = urlsplit(value)
                parsed.port
            except ValueError:
                excluded.append(value)
                continue
            origin = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), "", "", ""))
            allowed = (
                parsed.scheme.lower() in {"http", "https"} and parsed.hostname
                and parsed.username is None and parsed.password is None
                and url_belongs_to_target(value, target) and scope.allows_active(value)
                and scope.allows_active(origin)
                and (session.is_empty() or (session.allows_url(value) and session.allows_url(origin)))
            )
            if not allowed:
                excluded.append(value)
                continue
            if value not in seen:
                seen.add(value)
                ordered.append(value)
            if origin not in seen_origins:
                seen_origins.add(origin)
                origins.append(origin)
selected = origins[:int(limit)]
for name, rows in (("input_candidates.txt", candidates), ("ordered_scan_targets.txt", ordered),
                   ("nuclei_targets_all.txt", origins), ("nuclei_targets.txt", selected), ("excluded_urls.txt", excluded)):
    write_text_atomic(run / name, "".join(value + "\n" for value in rows))
write_json_atomic(run / "input.json", {"source_paths": [str(path) for path in sources if path.is_file()],
    "live_count": sum(bool(line.strip()) for line in live.read_text(encoding="utf-8").splitlines()),
    "ordered_count": len(ordered), "origin_count": len(origins), "selected_count": len(selected),
    "excluded_count": len(excluded), "auth_applied": (not session.is_empty())})
if not selected:
    raise ValueError("No target/Scope/Auth-owned service origins available")
PY

case ",$SKIP_CHECKS," in
    *,all,*|*,nuclei,*|*,cves,*) STATUS=skipped; exit 0 ;;
esac
case "${BBHUNT_DISABLE_NUCLEI_CVES:-0}" in
    1|true|TRUE|yes|YES|on|ON) STATUS=skipped; exit 0 ;;
esac
if ! command -v nuclei >/dev/null 2>&1; then
    STATUS=unavailable
    printf '%s\n' 'nuclei is not available; no scan was run' > "$RUN_DIR/stderr.log"
    exit 2
fi
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
if [ -z "$TIMEOUT_BIN" ]; then
    STATUS=unavailable
    printf '%s\n' 'timeout/gtimeout is required for bounded execution; no scan was run' > "$RUN_DIR/stderr.log"
    exit 2
fi
"$TIMEOUT_BIN" --kill-after=5s 10 nuclei -version > "$RUN_DIR/version.txt" 2>&1 || printf 'version query failed: %s\n' "$?" >> "$RUN_DIR/version.txt"
NUCLEI_ARGS=(
    -l "$RUN_DIR/nuclei_targets.txt" -tags cve -severity medium,high,critical
    -etags dos,bruteforce,fuzz -ept code,headless -dr -duc -ni -jsonl -silent
    -rate-limit "$RATE_LIMIT" -concurrency "$THREADS" -o "$RUN_DIR/raw.jsonl"
)
python3 - "$RUN_DIR" "$SCAN_TIMEOUT" "${NUCLEI_ARGS[@]}" <<'PY'
import os
import shutil
import sys
from pathlib import Path
from tools.artifact_io import write_json_atomic
from tools.auth_session import AuthSession
run, timeout, *args = sys.argv[1:]
write_json_atomic(Path(run) / "command.json", {
    "executable": shutil.which("nuclei"), "timeout_seconds": int(timeout), "args": args,
    "auth_header_names": [header.split(":", 1)[0] for header in AuthSession.from_env(os.environ).headers_list()],
    "auth_session_id": os.environ.get("BBHUNT_SESSION_ID", ""),
    "template_revision": "unknown; uses installed cve-tag templates",
})
PY
STATUS=running
publish_summary 0
# Upstream restrictions are mechanical, without side-effect inference from arbitrary templates.
if "$TIMEOUT_BIN" --kill-after=5s "$SCAN_TIMEOUT" nuclei \
    "${NUCLEI_ARGS[@]}" "${BB_AUTH_ARGS[@]}" \
    > "$RUN_DIR/stdout.log" 2> "$RUN_DIR/stderr.log"; then
    NUCLEI_RC=0
else
    NUCLEI_RC=$?
fi
printf '%s\n' "$NUCLEI_RC" > "$RUN_DIR/exit_code.rc"
if [ "$NUCLEI_RC" -ne 0 ]; then
    STATUS=incomplete
    echo "Nuclei did not complete (exit=$NUCLEI_RC); raw artifacts: $RUN_DIR" >&2
    exit 2
fi
STATUS="$(python3 - "$RUN_DIR/input.json" <<'PY'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text())
print("sampled" if payload["selected_count"] < payload["origin_count"] else "complete")
PY
)"
echo "Nuclei exited 0; artifacts: $RUN_DIR. Inspect summary status and raw records for review."
