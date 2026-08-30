#!/bin/bash
# =============================================================================
# GraphQL Security Audit — GraphQL 专项安全检查
#
# 默认只执行低风险探测：连通性、introspection、GET 绕过、字段建议泄露、引擎指纹。
# 需要更主动的枚举/注入/复杂度测试时，必须显式传入 --active 或 --dos-tests。
#
# Usage:
#   ./tools/graphql_audit.sh <graphql-endpoint-url>
#   ./tools/graphql_audit.sh <url> --cookie "session=abc"
#   ./tools/graphql_audit.sh <url> --header "Authorization: Bearer TOKEN"
#   ./tools/graphql_audit.sh <url> --proxy http://127.0.0.1:8080
#   ./tools/graphql_audit.sh <url> --active
#   ./tools/graphql_audit.sh <url> --dos-tests --batch-size 100 --alias-count 500 --depth 15
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="${BBHUNT_BASE_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
. "$SCRIPT_DIR/external_arsenal.sh"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAG='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}[HIT]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }
skip() { echo -e "${YELLOW}[~]${NC} $1"; }

usage() {
  sed -n '2,14p' "$0"
}

URL=""
COOKIE=""
PROXY=""
OUT_DIR=""
ACTIVE=0
DOS_TESTS=0
BATCH_SIZE=20
ALIAS_COUNT=50
DEPTH=8
EXTRA_HEADERS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cookie)     shift; COOKIE="${1:-}" ;;
    --header)     shift; EXTRA_HEADERS+=("${1:-}") ;;
    --proxy)      shift; PROXY="${1:-}" ;;
    --output-dir) shift; OUT_DIR="${1:-}" ;;
    --active)     ACTIVE=1 ;;
    --dos-tests)  DOS_TESTS=1 ;;
    --full)       ACTIVE=1; DOS_TESTS=1 ;;
    --batch-size) shift; BATCH_SIZE="${1:-20}" ;;
    --alias-count) shift; ALIAS_COUNT="${1:-50}" ;;
    --depth)      shift; DEPTH="${1:-8}" ;;
    -h|--help)    usage; exit 0 ;;
    http*)        URL="$1" ;;
    *)            err "Unknown argument: $1"; usage; exit 2 ;;
  esac
  shift
done

[ -z "$URL" ] && { err "GraphQL endpoint URL required"; usage; exit 2; }

case "$BATCH_SIZE$ALIAS_COUNT$DEPTH" in
  *[!0-9]*|"") err "--batch-size/--alias-count/--depth must be positive integers"; exit 2 ;;
esac

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if ! TARGET_INFO=$(python3 - "$URL" "$SCRIPT_DIR/.." <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[2]).resolve()))
from tools.target_paths import canonical_target_value, target_storage_key

target = canonical_target_value(sys.argv[1])
print(target, target_storage_key(target), sep="\t")
PY
); then
  err "Unable to derive the canonical target identity"
  exit 2
fi
IFS=$'\t' read -r TARGET TARGET_KEY <<< "$TARGET_INFO"
[ -n "$TARGET" ] && [ -n "$TARGET_KEY" ] || { err "Invalid target identity"; exit 2; }

FINDINGS_DIR="$BASE_DIR/findings/$TARGET_KEY"
GRAPHQL_DIR="$FINDINGS_DIR/graphql"
OUT_DIR="${OUT_DIR:-$GRAPHQL_DIR/$TIMESTAMP}"
if ! python3 - "$OUT_DIR" "$GRAPHQL_DIR" <<'PY'
import sys
from pathlib import Path

output = Path(sys.argv[1]).expanduser().resolve()
root = Path(sys.argv[2]).expanduser().resolve()
try:
    output.relative_to(root)
except ValueError:
    raise SystemExit(f"output directory must stay under the target GraphQL root: {root}")
PY
then
  exit 2
fi
mkdir -p "$OUT_DIR"

SUMMARY="$OUT_DIR/summary.txt"
{
  echo "GraphQL Audit -- $URL"
  echo "Date: $(date)"
  echo "Mode: active=$ACTIVE dos_tests=$DOS_TESTS"
  echo "---"
} > "$SUMMARY"

CURL_ARGS=(-s --max-time "${GQL_CURL_TIMEOUT:-30}")
[ -n "$COOKIE" ] && CURL_ARGS+=(-H "Cookie: $COOKIE")
[ -n "$PROXY" ] && CURL_ARGS+=(--proxy "$PROXY")
for hdr in "${EXTRA_HEADERS[@]}"; do
  [ -n "$hdr" ] && CURL_ARGS+=(-H "$hdr")
done

INTROSPECTION_ENABLED=0
GET_BYPASS=0
FIELD_SUGGESTIONS=0
SQLI_SIGNAL=0
ARRAY_BATCHING=0
ALIAS_ACCEPTED=0
DEPTH_LIMIT_SIGNAL=0

_summary() {
  printf '%s\n' "$1" >> "$SUMMARY"
}

_gql_post() {
  curl "${CURL_ARGS[@]}" -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "$1"
}

_pretty_json() {
  local src="$1" dst="$2"
  if _have python3; then
    python3 -m json.tool < "$src" > "$dst" 2>/dev/null || cp "$src" "$dst"
  else
    cp "$src" "$dst"
  fi
}

# shellcheck source=banner.sh
. "$SCRIPT_DIR/banner.sh"
AUTH_STATE="none"
[ -n "$COOKIE" ] && AUTH_STATE="cookie"
[ "${#EXTRA_HEADERS[@]}" -gt 0 ] && AUTH_STATE="${AUTH_STATE}+header"
print_banner "GraphQL Security Audit" "$URL" \
    "Safe default|connectivity . introspection . GET bypass . suggestions . fingerprint" \
    "Active opt-in|--active for field discovery/gqlmap/graphql-cop" \
    "DoS opt-in|--dos-tests for batching/alias/depth probes" \
    "Output|$OUT_DIR" \
    "Auth|$AUTH_STATE"

# ---------------------------------------------------------------------------
# Phase 0: Connectivity check
# ---------------------------------------------------------------------------
log "Phase 0 -- connectivity check"
HTTP_CODE=$(curl "${CURL_ARGS[@]}" -o /dev/null -w '%{http_code}' -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __typename }"}' 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "000" ]; then
  err "Cannot reach $URL -- aborting"
  exit 1
fi

ok "Endpoint responded: HTTP $HTTP_CODE"
_summary "connectivity: HTTP $HTTP_CODE"

# ---------------------------------------------------------------------------
# Phase 1: Introspection
# ---------------------------------------------------------------------------
log "Phase 1 -- introspection probe"
INTROSPECT_QUERY='{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: true) { name isDeprecated } } } }"}'
INTROSPECT_RAW="$OUT_DIR/introspection.raw.json"
INTROSPECT_OUT="$OUT_DIR/introspection.json"
_gql_post "$INTROSPECT_QUERY" > "$INTROSPECT_RAW" 2>/dev/null || true

if grep -q '"__schema"' "$INTROSPECT_RAW" 2>/dev/null; then
  INTROSPECTION_ENABLED=1
  hit "Introspection ENABLED -- schema dumped to introspection.json"
  _pretty_json "$INTROSPECT_RAW" "$INTROSPECT_OUT"
  _summary "introspection: ENABLED"

  if _have python3; then
    python3 - "$INTROSPECT_RAW" "$OUT_DIR/interesting_fields.txt" <<'PY' 2>/dev/null || true
import json
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
keywords = re.compile(r"admin|internal|secret|token|password|role|debug|legacy|private|key|flag", re.I)
hits = []
try:
    data = json.loads(src.read_text(encoding="utf-8", errors="ignore"))
    types = data.get("data", {}).get("__schema", {}).get("types", [])
    for t in types:
        name = t.get("name", "")
        if keywords.search(name):
            hits.append(f"TYPE: {name}")
        for f in (t.get("fields") or []):
            fname = f.get("name", "")
            if keywords.search(fname):
                hits.append(f"FIELD: {name}.{fname}")
except Exception as exc:
    hits.append(f"parse error: {exc}")
dst.write_text(("\n".join(hits) + "\n") if hits else "no obvious sensitive names found\n", encoding="utf-8")
PY
    log "Interesting schema names saved to $OUT_DIR/interesting_fields.txt"
  fi
else
  warn "Introspection appears disabled or blocked"
  cp "$INTROSPECT_RAW" "$INTROSPECT_OUT" 2>/dev/null || true
  _summary "introspection: DISABLED"

  log "Trying introspection via GET..."
  GET_RESP="$OUT_DIR/introspection_get.raw"
  curl "${CURL_ARGS[@]}" -X GET \
    "$URL?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D" > "$GET_RESP" 2>/dev/null || true
  if grep -q '"__schema"' "$GET_RESP" 2>/dev/null; then
    GET_BYPASS=1
    hit "Introspection reachable via GET -- possible method/WAF bypass"
    _summary "introspection_get_bypass: YES"
  else
    _summary "introspection_get_bypass: no"
  fi
fi

log "Checking field suggestions..."
SUGGEST_OUT="$OUT_DIR/field_suggestions.raw.json"
_gql_post '{"query":"{ usr { id } }"}' > "$SUGGEST_OUT" 2>/dev/null || true
if grep -qi "did you mean\|suggestions" "$SUGGEST_OUT" 2>/dev/null; then
  FIELD_SUGGESTIONS=1
  hit "Field suggestions ENABLED -- schema may be leakable via typo-based enumeration"
  _summary "field_suggestions: ENABLED"
else
  _summary "field_suggestions: disabled or no hints"
fi

# ---------------------------------------------------------------------------
# Phase 2: Engine fingerprinting
# ---------------------------------------------------------------------------
log "Phase 2 -- engine fingerprinting"
FINGER_OUT="$OUT_DIR/fingerprint.txt"
if _have graphw00f; then
  graphw00f -d -t "$URL" \
    ${PROXY:+--proxy "$PROXY"} 2>&1 | tee "$FINGER_OUT"
  _summary "fingerprint: see fingerprint.txt"
elif python3 -c "import graphw00f" 2>/dev/null; then
  python3 -m graphw00f.main -d -t "$URL" \
    ${PROXY:+--proxy "$PROXY"} 2>&1 | tee "$FINGER_OUT"
  _summary "fingerprint: see fingerprint.txt"
else
  skip "graphw00f not installed -- fingerprint skipped"
  echo "(install: pipx install graphw00f)" > "$FINGER_OUT"
  _summary "fingerprint: skipped"
fi

# ---------------------------------------------------------------------------
# Phase 3: Active field discovery / injection checklist
# ---------------------------------------------------------------------------
if [ "$ACTIVE" -eq 1 ]; then
  log "Phase 3 -- active field discovery (clairvoyance)"
  CLAIRVOYANCE_OUT="$OUT_DIR/field_suggestions.json"
  if _have clairvoyance || python3 -c "import clairvoyance" 2>/dev/null; then
    CLAIRVOYANCE_ARGS=(-u "$URL" -o "$CLAIRVOYANCE_OUT")
    for hdr in "${EXTRA_HEADERS[@]}"; do
      [ -n "$hdr" ] && CLAIRVOYANCE_ARGS+=(-H "$hdr")
    done
    [ -n "$PROXY" ] && CLAIRVOYANCE_ARGS+=(--proxy "$PROXY")
    if _have clairvoyance; then
      clairvoyance "${CLAIRVOYANCE_ARGS[@]}" 2>&1 | tail -20
    else
      python3 -m clairvoyance "${CLAIRVOYANCE_ARGS[@]}" 2>&1 | tail -20
    fi
    ok "Clairvoyance output: $CLAIRVOYANCE_OUT"
    _summary "clairvoyance: completed"
  else
    skip "clairvoyance not installed -- field discovery skipped"
    echo "(install: pipx install clairvoyance)" > "$CLAIRVOYANCE_OUT"
    _summary "clairvoyance: skipped"
  fi

  log "Phase 4 -- injection scan"
  GQLMAP_OUT="$OUT_DIR/gqlmap.txt"
  if _have gqlmap; then
    GQLMAP_ARGS=(--target "$URL" --query '{ users(search: GQLMAP) { id } }')
    [ -n "$PROXY" ] && GQLMAP_ARGS+=(--proxy "$PROXY")
    gqlmap "${GQLMAP_ARGS[@]}" 2>&1 | tee "$GQLMAP_OUT" || true
    _summary "injection_scan: completed (see gqlmap.txt)"
  else
    skip "gqlmap not installed -- built-in SQLi error probe only"
    SQLI_RESP="$OUT_DIR/sqli_quick_probe.raw.json"
    _gql_post '{"query":"{ users(search: \"1'\''--\") { id } }"}' > "$SQLI_RESP" 2>/dev/null || true
    if grep -qi "syntax\|mysql\|pgsql\|sqlite\|ORA-\|error in your SQL" "$SQLI_RESP" 2>/dev/null; then
      SQLI_SIGNAL=1
      hit "SQL error in response -- possible SQLi in GraphQL argument"
      _summary "sqli_quick_probe: POSSIBLE HIT"
    else
      _summary "sqli_quick_probe: no obvious errors"
    fi
  fi

  log "Phase 5 -- graphql-cop checklist"
  COP_OUT="$OUT_DIR/cop_report.txt"
  if _have graphql-cop; then
    COP_ARGS=(-t "$URL")
    for hdr in "${EXTRA_HEADERS[@]}"; do
      [ -n "$hdr" ] && COP_ARGS+=(-H "$hdr")
    done
    graphql-cop "${COP_ARGS[@]}" 2>&1 | tee "$COP_OUT"
    _summary "graphql_cop: completed"
  else
    skip "graphql-cop not installed -- checklist skipped"
    echo "(install: pipx install graphql-cop)" > "$COP_OUT"
    _summary "graphql_cop: skipped"
  fi
else
  skip "Active enumeration/injection phases skipped -- rerun with --active"
  _summary "active_phases: skipped"
fi

# ---------------------------------------------------------------------------
# Phase 6: Explicit DoS / complexity opt-in
# ---------------------------------------------------------------------------
if [ "$DOS_TESTS" -eq 1 ]; then
  log "Phase 6 -- batching / alias / depth limit probes (explicit opt-in)"
  DOS_OUT="$OUT_DIR/dos_complexity.txt"

  T_SINGLE=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ __typename }"}' \
    -o /dev/null -w '%{time_total}' 2>/dev/null || echo "0")

  BATCH_PAYLOAD=$(python3 -c "import json; print(json.dumps([{'query':'{ __typename }'}]*${BATCH_SIZE}))")
  BATCH_STATUS=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "$BATCH_PAYLOAD" \
    -o "$OUT_DIR/batching.raw" -w '%{http_code}' 2>/dev/null || echo "000")
  T_BATCH=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "$BATCH_PAYLOAD" \
    -o /dev/null -w '%{time_total}' 2>/dev/null || echo "0")

  {
    echo "single query time: ${T_SINGLE}s"
    echo "${BATCH_SIZE}-query batch time: ${T_BATCH}s HTTP: $BATCH_STATUS"
  } | tee "$DOS_OUT"

  if grep -q '^\[' "$OUT_DIR/batching.raw" 2>/dev/null; then
    ARRAY_BATCHING=1
    hit "Array batching ACCEPTED -- potential brute-force/rate-limit amplifier"
    _summary "array_batching: ENABLED (${BATCH_SIZE})"
  else
    _summary "array_batching: likely disabled (HTTP $BATCH_STATUS)"
  fi

  ALIAS_PAYLOAD=$(python3 -c "
import json
aliases = ' '.join(f'q{i}: __typename' for i in range(${ALIAS_COUNT}))
print(json.dumps({'query': '{ ' + aliases + ' }'}))
")
  ALIAS_OUT="$OUT_DIR/alias_bomb.raw"
  curl "${CURL_ARGS[@]}" -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "$ALIAS_PAYLOAD" \
    -o "$ALIAS_OUT" -w "alias-${ALIAS_COUNT} query: HTTP %{http_code} time: %{time_total}s\n" 2>/dev/null \
    | tee -a "$DOS_OUT"
  if grep -q 'q0' "$ALIAS_OUT" 2>/dev/null; then
    ALIAS_ACCEPTED=1
    hit "Alias query accepted -- check rate-limit / resolver cost controls"
    _summary "alias_query: accepted (${ALIAS_COUNT})"
  else
    _summary "alias_query: blocked or limited"
  fi

  DEPTH_QUERY=$(python3 -c "
import json
inner = 'id'
for _ in range(${DEPTH}):
    inner = f'edges {{ node {{ {inner} }} }}'
print(json.dumps({'query': '{ viewer { ' + inner + ' } }'}))
")
  DEPTH_OUT="$OUT_DIR/depth_probe.raw"
  DEPTH_HTTP=$(curl "${CURL_ARGS[@]}" -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "$DEPTH_QUERY" \
    -o "$DEPTH_OUT" -w '%{http_code}' 2>/dev/null || echo "000")
  echo "depth-${DEPTH} query: HTTP $DEPTH_HTTP" | tee -a "$DOS_OUT"
  if [ "$DEPTH_HTTP" = "200" ] && ! grep -qi "max.*depth\|query.*depth\|complexity" "$DEPTH_OUT" 2>/dev/null; then
    DEPTH_LIMIT_SIGNAL=1
    hit "Deep query accepted -- no obvious depth/complexity limit signal"
    _summary "depth_limit: none detected at depth ${DEPTH}"
  else
    _summary "depth_limit: enforced or query rejected"
  fi
else
  skip "DoS/complexity probes skipped -- rerun with --dos-tests"
  _summary "dos_complexity_phases: skipped"
fi

RUN_SUMMARY="$OUT_DIR/run-summary.json"
_summary "canonical_run_summary: $RUN_SUMMARY"
if ! PUBLISH_RESULT=$(python3 - \
  "$BASE_DIR" "$SCRIPT_DIR/.." "$FINDINGS_DIR" "$OUT_DIR" "$RUN_SUMMARY" \
  "$TARGET" "$TARGET_KEY" "$URL" "$ACTIVE" "$DOS_TESTS" \
  "$INTROSPECTION_ENABLED" "$GET_BYPASS" "$FIELD_SUGGESTIONS" \
  "$SQLI_SIGNAL" "$ARRAY_BATCHING" "$ALIAS_ACCEPTED" "$DEPTH_LIMIT_SIGNAL" <<'PY'
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
source_root = Path(sys.argv[2]).resolve()
findings_dir = Path(sys.argv[3]).resolve()
out_dir = Path(sys.argv[4]).resolve()
summary_path = Path(sys.argv[5]).resolve()
target, target_key, endpoint = sys.argv[6:9]
active, dos_tests = (value == "1" for value in sys.argv[9:11])
signal_names = (
    "introspection_enabled",
    "introspection_get_bypass",
    "field_suggestions",
    "sqli_error_signal",
    "array_batching",
    "alias_query_accepted",
    "depth_limit_signal",
)
signals = [name for name, value in zip(signal_names, sys.argv[11:18]) if value == "1"]

sys.path.insert(0, str(source_root))
from tools.finding_index import upsert_finding


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


artifacts = []
for path in sorted(out_dir.iterdir(), key=lambda item: item.name)[:24]:
    if not path.is_file() or path == summary_path or path.stat().st_size <= 0:
        continue
    artifacts.append({
        "ref": str(path.relative_to(repo_root)),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    })

run_id = out_dir.name
operation_seed = "|".join((target, endpoint, run_id, *signals))
operation_id = "graphql_" + hashlib.sha256(operation_seed.encode()).hexdigest()[:20]
finding_id = "graphql_" + hashlib.sha1(f"{target}|{endpoint}|audit-signal".encode()).hexdigest()[:12]
generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
payload = {
    "schema_version": 1,
    "kind": "graphql_audit_run",
    "generated_at": generated_at,
    "operation_id": operation_id,
    "run_id": run_id,
    "target": target,
    "target_key": target_key,
    "endpoint": endpoint,
    "mode": {"active": active, "dos_tests": dos_tests},
    "status": "completed",
    "signals": signals,
    "artifact_count": len(artifacts),
    "artifacts": artifacts,
    "candidate_finding_id": finding_id if signals else "",
}
summary_path.parent.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(
    "w", encoding="utf-8", dir=summary_path.parent,
    prefix=f".{summary_path.name}.", suffix=".tmp", delete=False,
) as handle:
    temp_path = Path(handle.name)
    json.dump(payload, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
temp_path.replace(summary_path)

if signals:
    relative_summary = str(summary_path.relative_to(repo_root))
    upsert_finding(
        findings_dir,
        {
            "id": finding_id,
            "type": "graphql",
            "category": "graphql",
            "vuln_class": "GraphQL",
            "title": f"GraphQL audit signal on {endpoint}",
            "summary": "GraphQL audit signals require protocol replay: " + ", ".join(signals),
            "url": endpoint,
            "severity": "low",
            "confidence": "needs_review",
            "source_file": relative_summary,
            "raw": f"graphql_audit:{operation_id}",
            "validation_status": "candidate",
            "report_status": "not_generated",
            "rubric": {
                "rubric_id": "graphql",
                "status": "needs-evidence",
                "ready": False,
                "score": 0,
                "satisfied_count": 0,
                "total": 3,
                "missing": [
                    {"id": "exact_replay", "label": "exact GraphQL request/response replay"},
                    {"id": "actor_diff", "label": "actor or role boundary comparison"},
                    {"id": "impact", "label": "target-owned business impact"},
                ],
                "missing_labels": [
                    "exact GraphQL request/response replay",
                    "actor or role boundary comparison",
                    "target-owned business impact",
                ],
                "next_actions": [
                    "Replay one exact GraphQL operation through validation_runner.py protocol-replay."
                ],
                "summary": "graphql:needs-evidence satisfied=0/3",
            },
        },
        target=target,
    )

print(json.dumps({
    "summary": str(summary_path.relative_to(repo_root)),
    "candidate_finding_id": finding_id if signals else "",
}, sort_keys=True))
PY
); then
  err "Failed to publish the canonical GraphQL run summary"
  exit 1
fi
_summary "canonical_publish: $PUBLISH_RESULT"

echo ""
echo -e "${BOLD}====== AUDIT SUMMARY ======${NC}"
cat "$SUMMARY"
echo ""
ok "All output saved to: $OUT_DIR"
