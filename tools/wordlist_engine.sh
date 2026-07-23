#!/bin/bash
# 目标词候选池：网站原词 + Hashcat 批量变异 + 品牌词 pydictor 定向变异。

set -euo pipefail

DEPTH=2
MIN_LEN=5
MAX_LEN=14
MODE="balanced"
FILTER="strict"
RATE=5
USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Bug-Bounty-Research"
TARGET=""

_need_value() { [ "$#" -ge 2 ] && [ -n "${2:-}" ] || { echo "Missing value for $1" >&2; exit 1; }; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --depth)   _need_value "$@"; DEPTH="$2"; shift 2 ;;
        --min-len) _need_value "$@"; MIN_LEN="$2"; shift 2 ;;
        --max-len) _need_value "$@"; MAX_LEN="$2"; shift 2 ;;
        --mode)    _need_value "$@"; MODE="$2"; shift 2 ;;
        --filter)  _need_value "$@"; FILTER="$2"; shift 2 ;;
        --rate)    _need_value "$@"; RATE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 <target> [--depth N] [--mode minimal|balanced|aggressive] [--filter strict|loose]"
            exit 0
            ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *) [ -z "$TARGET" ] && TARGET="$1" || { echo "Unexpected arg: $1" >&2; exit 1; }; shift ;;
    esac
done

[ -n "$TARGET" ] || { echo "Target required" >&2; exit 1; }
[[ "$DEPTH" =~ ^[0-9]+$ && "$MIN_LEN" =~ ^[0-9]+$ && "$MAX_LEN" =~ ^[0-9]+$ && "$RATE" =~ ^[0-9]+$ ]] \
    || { echo "depth/min-len/max-len/rate must be non-negative integers" >&2; exit 1; }
[ "$MIN_LEN" -le "$MAX_LEN" ] || { echo "min-len must be <= max-len" >&2; exit 1; }
case "$FILTER" in strict|loose) ;; *) echo "Unknown filter: $FILTER" >&2; exit 1 ;; esac
case "$MODE" in minimal|balanced|aggressive) ;; *) echo "Unknown mode: $MODE" >&2; exit 1 ;; esac

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log_ok() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err() { echo -e "${RED}[-]${NC} $1" >&2; }

_resolve_exec() {
    local explicit="$1" command_name="$2" fallback="$3"
    if [ -n "$explicit" ] && [ -x "$explicit" ]; then printf '%s\n' "$explicit"
    elif command -v "$command_name" >/dev/null 2>&1; then command -v "$command_name"
    elif [ -x "$fallback" ]; then printf '%s\n' "$fallback"
    fi
}
_resolve_file() {
    local explicit="$1" fallback="$2"
    if [ -n "$explicit" ] && [ -f "$explicit" ]; then printf '%s\n' "$explicit"
    elif [ -f "$fallback" ]; then printf '%s\n' "$fallback"
    fi
}

CEWLER_BIN="$(_resolve_exec "${CEWLER_BIN:-}" cewler "$HOME/.local/bin/cewler")"
HASHCAT_BIN="$(_resolve_exec "${HASHCAT_BIN:-}" hashcat "$HOME/Tools/hashcat/hashcat.bin")"
PYDICTOR_BIN="$(_resolve_file "${PYDICTOR_BIN:-}" "$HOME/Tools/pydictor/pydictor.py")"

if [ -n "${HASHCAT_RULES_DIR:-}" ]; then
    RULES_DIR="$HASHCAT_RULES_DIR"
elif [ -n "$HASHCAT_BIN" ] && [ -d "$(dirname "$HASHCAT_BIN")/rules" ]; then
    RULES_DIR="$(dirname "$HASHCAT_BIN")/rules"
elif [ -d /usr/share/hashcat/rules ]; then
    RULES_DIR=/usr/share/hashcat/rules
else
    RULES_DIR=""
fi
case "$MODE" in
    minimal) RULE_NAME="top10_2025.rule" ;;
    balanced) RULE_NAME="best66.rule" ;;
    aggressive) RULE_NAME="OneRuleToRuleThemStill.rule" ;;
esac
RULE_FILE="${RULES_DIR:+$RULES_DIR/$RULE_NAME}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_KEY="$(PYTHONPATH="$(dirname "$SCRIPT_DIR")" python3 - "$TARGET" <<'PY'
import sys
from tools.target_paths import target_storage_key
print(target_storage_key(sys.argv[1]))
PY
)"
TARGET_HOST="$(python3 - "$TARGET" <<'PY'
import sys
from urllib.parse import urlparse
value=sys.argv[1]
parsed=urlparse(value if '://' in value else '//' + value)
print(parsed.hostname or value)
PY
)"
BRAND="${TARGET_HOST#www.}"
BRAND="${BRAND%%.*}"
BRAND="$(printf '%s' "$BRAND" | tr -cd '[:alnum:]_-')"

OUT_DIR="recon/${TARGET_KEY}/wordlists"
mkdir -p "$OUT_DIR"
RAW="$OUT_DIR/from-website.txt"
CLEAN="$OUT_DIR/cleaned.txt"
BRAND_OUT="$OUT_DIR/brand-pydictor.txt"
HASHCAT_OUT="$OUT_DIR/website-hashcat.txt"
POOL="$OUT_DIR/candidate-pool.txt"
RANKED="$OUT_DIR/ranked.txt"
: > "$RAW"; : > "$CLEAN"; : > "$BRAND_OUT"; : > "$HASHCAT_OUT"

if [ -n "$CEWLER_BIN" ]; then
    log_ok "Crawling https://${TARGET_HOST}"
    if ! "$CEWLER_BIN" "https://${TARGET_HOST}" -d "$DEPTH" -m "$MIN_LEN" -l -r "$RATE" -u "$USER_AGENT" -o "$RAW"; then
        log_warn "cewler exited non-zero; preserving any partial output"
    fi
else
    log_warn "cewler unavailable; continuing with brand sources"
fi

if [ -s "$RAW" ]; then
    if [ "$FILTER" = strict ]; then
        awk -v min="$MIN_LEN" -v max="$MAX_LEN" '
            length($0) >= min && length($0) <= max && /^[a-z][a-z0-9]*$/ \
            && !(length($0) >= 10 && /[0-9]/ && /[a-z]/) && !seen[$0]++
        ' "$RAW" > "$CLEAN"
    else
        awk -v min="$MIN_LEN" -v max="$MAX_LEN" '
            length($0) >= min && length($0) <= max && /^[[:print:]]+$/ && !seen[$0]++
        ' "$RAW" > "$CLEAN"
    fi
fi

if [ -n "$PYDICTOR_BIN" ] && [ -n "$BRAND" ]; then
    PYDICTOR_TMP="$(mktemp -d "$OUT_DIR/.pydictor.XXXXXX")"
    trap 'rm -rf "$PYDICTOR_TMP"' EXIT
    if python3 "$PYDICTOR_BIN" -extend "$BRAND" --leet 0 1 2 11 21 \
            --len "$MIN_LEN" "$MAX_LEN" -o "$PYDICTOR_TMP" >/dev/null 2>&1; then
        find "$PYDICTOR_TMP" -type f -exec cat {} \; 2>/dev/null \
            | awk -v min="$MIN_LEN" -v max="$MAX_LEN" \
                'length($0) >= min && length($0) <= max && !seen[$0]++' > "$BRAND_OUT"
    else
        log_warn "pydictor brand expansion failed"
    fi
fi
if [ ! -s "$BRAND_OUT" ] && [ "${#BRAND}" -ge "$MIN_LEN" ] && [ "${#BRAND}" -le "$MAX_LEN" ]; then
    printf '%s\n' "$BRAND" > "$BRAND_OUT"
fi

if [ -s "$CLEAN" ] && [ -n "$HASHCAT_BIN" ] && [ -f "$RULE_FILE" ]; then
    log_ok "Applying Hashcat rule: $RULE_NAME"
    "$HASHCAT_BIN" --stdout "$CLEAN" -r "$RULE_FILE" 2>/dev/null \
        | awk -v min="$MIN_LEN" -v max="$MAX_LEN" \
            'length($0) >= min && length($0) <= max && !seen[$0]++' > "$HASHCAT_OUT"
elif [ -s "$CLEAN" ]; then
    log_warn "Hashcat or rule unavailable; keeping cleaned website words"
fi

awk 'NF && !seen[$0]++' "$BRAND_OUT" "$CLEAN" "$HASHCAT_OUT" > "$POOL"
[ -s "$POOL" ] || { log_err "all candidate sources are empty"; exit 1; }
cp "$POOL" "$RANKED"
chmod 600 "$RAW" "$CLEAN" "$BRAND_OUT" "$HASHCAT_OUT" "$POOL" "$RANKED"

printf '\nCandidate pool: %s (%s entries)\n' "$POOL" "$(wc -l < "$POOL" | tr -d ' ')"
printf 'Compatibility alias: %s\n' "$RANKED"
printf 'Live input: generate and review spray-shortlist.txt; do not pass the candidate pool directly.\n'
