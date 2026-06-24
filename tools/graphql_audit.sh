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
HOST=$(echo "$URL" | awk -F/ '{print $3}' | tr -d '[:space:]')
OUT_DIR="${OUT_DIR:-$(pwd)/findings/graphql/${HOST}/${TIMESTAMP}}"
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
    hit "Deep query accepted -- no obvious depth/complexity limit signal"
    _summary "depth_limit: none detected at depth ${DEPTH}"
  else
    _summary "depth_limit: enforced or query rejected"
  fi
else
  skip "DoS/complexity probes skipped -- rerun with --dos-tests"
  _summary "dos_complexity_phases: skipped"
fi

echo ""
echo -e "${BOLD}====== AUDIT SUMMARY ======${NC}"
cat "$SUMMARY"
echo ""
ok "All output saved to: $OUT_DIR"
