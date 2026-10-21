#!/bin/bash
# 目标词候选池：网站原词 + Hashcat 批量变异 + 品牌词 pydictor 定向变异。

set -euo pipefail

DEPTH=2
MIN_LEN=5
MAX_LEN=14
MODE="balanced"
FILTER="strict"
RATE=5
TIMEOUT_SECONDS=300
REPO_ROOT=""
SEED_FILE=""
CRAWL=true
WITH_BRAND=true
WITH_HASHCAT=true
SELECTED_RULE=""
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
        --timeout) _need_value "$@"; TIMEOUT_SECONDS="$2"; shift 2 ;;
        --repo-root) _need_value "$@"; REPO_ROOT="$2"; shift 2 ;;
        --seed-file) _need_value "$@"; SEED_FILE="$2"; shift 2 ;;
        --rule-file) _need_value "$@"; SELECTED_RULE="$2"; shift 2 ;;
        --skip-crawl) CRAWL=false; shift ;;
        --skip-brand) WITH_BRAND=false; shift ;;
        --skip-hashcat) WITH_HASHCAT=false; shift ;;
        -h|--help)
            echo "Usage: $0 <target> [--seed-file FILE] [--skip-crawl] [--skip-brand] [--skip-hashcat]"
            echo "       [--depth N] [--min-len N] [--max-len N] [--rate N] [--timeout SECONDS]"
            echo "       [--mode minimal|balanced|aggressive] [--rule-file FILE] [--filter strict|loose] [--repo-root DIR]"
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
[[ "$RATE" =~ ^0*[1-9][0-9]*$ && "$TIMEOUT_SECONDS" =~ ^0*[1-9][0-9]*$ ]] \
    || { echo "rate/timeout must be positive integers" >&2; exit 1; }
[ -z "$SEED_FILE" ] || [ -f "$SEED_FILE" ] || { echo "seed-file must be a readable regular file" >&2; exit 1; }
[ -z "$SELECTED_RULE" ] || [ -f "$SELECTED_RULE" ] || { echo "rule-file does not exist" >&2; exit 1; }
case "$FILTER" in strict|loose) ;; *) echo "Unknown filter: $FILTER" >&2; exit 1 ;; esac
case "$MODE" in minimal|balanced|aggressive) ;; *) echo "Unknown mode: $MODE" >&2; exit 1 ;; esac

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log_ok() { echo -e "${GREEN}[+]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
log_err() { echo -e "${RED}[-]${NC} $1" >&2; }

_resolve_exec() {
    local explicit="$1" command_name="$2" fallback="$3"
    if [ -n "$explicit" ]; then
        [ ! -x "$explicit" ] || printf '%s\n' "$explicit"
    elif command -v "$command_name" >/dev/null 2>&1; then command -v "$command_name"
    elif [ -x "$fallback" ]; then printf '%s\n' "$fallback"
    fi
    return 0
}
_resolve_file() {
    local explicit="$1" fallback="$2"
    if [ -n "$explicit" ]; then
        [ ! -f "$explicit" ] || printf '%s\n' "$explicit"
    elif [ -f "$fallback" ]; then printf '%s\n' "$fallback"
    fi
    return 0
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
[ -z "$SELECTED_RULE" ] || RULE_FILE="$SELECTED_RULE"
for variable in CEWLER_BIN HASHCAT_BIN PYDICTOR_BIN RULE_FILE; do
    if [ -n "${!variable}" ]; then
        resolved="$(python3 - "${!variable}" <<'PY'
import sys
from pathlib import Path
print(Path(sys.argv[1]).expanduser().resolve())
PY
)"
        printf -v "$variable" '%s' "$resolved"
    fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -n "$REPO_ROOT" ] || REPO_ROOT="$(dirname "$SCRIPT_DIR")"
umask 077
TARGET_INFO="$(PYTHONPATH="$(dirname "$SCRIPT_DIR")" python3 - "$TARGET" "$REPO_ROOT" "$CRAWL" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit
from tools.target_paths import canonical_target_value, classify_target, target_storage_key
from tools.scope_context import ScopeContext
from tools.scope_source import load_scope_context
target, root, crawl = sys.argv[1:]
info = classify_target(target)
if info['kind'] not in {'domain', 'ip'} or '*' in info['target']:
    raise ValueError('wordlist preparation requires one concrete host or URL')
parsed = urlsplit(target if '://' in target else 'https://' + target)
url = target if '://' in target else 'https://' + target
repo = Path(root).expanduser().resolve()
output = repo / 'recon' / target_storage_key(target) / 'wordlists'
if any(parent.is_symlink() for parent in (output / 'runs', output, *output.parents)):
    raise ValueError('wordlist output must not traverse symlinks')
for name in ('from-website.txt', 'cleaned.txt', 'brand-pydictor.txt', 'website-hashcat.txt', 'candidate-pool.txt', 'ranked.txt', 'summary.json'):
    destination = output / name
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError('wordlist compatibility output must be a regular file')
if crawl == 'true' and (not ScopeContext(root_target=target).allows_active(url)
        or not load_scope_context(repo, canonical_target_value(target)).allows_active(url)):
    raise ValueError('selected crawl URL is outside the current Scope')
print(repo)
print(target_storage_key(target))
print(parsed.hostname)
print(url)
PY
)"
mapfile -t TARGET_INFO_ROWS <<< "$TARGET_INFO"
REPO_ROOT="${TARGET_INFO_ROWS[0]}"
TARGET_KEY="${TARGET_INFO_ROWS[1]}"
TARGET_HOST="${TARGET_INFO_ROWS[2]}"
TARGET_URL="${TARGET_INFO_ROWS[3]}"
BRAND="${TARGET_HOST#www.}"
BRAND="${BRAND%%.*}"
BRAND="$(printf '%s' "$BRAND" | tr -cd '[:alnum:]_-')"

BASE_OUT="$REPO_ROOT/recon/${TARGET_KEY}/wordlists"
mkdir -p "$BASE_OUT/runs"
OUT_DIR="$(mktemp -d "$BASE_OUT/runs/run.XXXXXX")"
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$TIMEOUT_BIN" ] || { log_err "timeout/gtimeout is required"; exit 2; }
DEGRADED=false
_run_stage() {
    local stage="$1" code=0; shift
    python3 - "$OUT_DIR/$stage.argv.json" "$@" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]) + '\n', encoding='utf-8')
PY
    "$TIMEOUT_BIN" --kill-after=2 "$TIMEOUT_SECONDS" "$@" \
        >"$OUT_DIR/$stage.stdout" 2>"$OUT_DIR/$stage.stderr" || code=$?
    printf '%s\n' "$code" > "$OUT_DIR/$stage.exit"
    if [ "$code" -ne 0 ]; then DEGRADED=true; log_warn "$stage exited $code; original output retained"; fi
}
RAW="$OUT_DIR/from-website.txt"
CLEAN="$OUT_DIR/cleaned.txt"
BRAND_OUT="$OUT_DIR/brand-pydictor.txt"
HASHCAT_OUT="$OUT_DIR/website-hashcat.txt"
POOL="$OUT_DIR/candidate-pool.txt"
RANKED="$OUT_DIR/ranked.txt"
: > "$RAW"; : > "$CLEAN"; : > "$BRAND_OUT"; : > "$HASHCAT_OUT"
if [ -n "$SEED_FILE" ]; then
    cp -- "$SEED_FILE" "$OUT_DIR/selected-seeds.txt"
else
    : > "$OUT_DIR/selected-seeds.txt"
fi

if [ "$CRAWL" = true ] && [ -n "$CEWLER_BIN" ]; then
    log_ok "Collecting words from selected URL"
    _run_stage cewler "$CEWLER_BIN" "$TARGET_URL" -d "$DEPTH" -m "$MIN_LEN" -l -r "$RATE" -u "$USER_AGENT" -o "$RAW"
elif [ "$CRAWL" = true ]; then
    printf 'unavailable\n' > "$OUT_DIR/cewler.exit"
    DEGRADED=true
    log_warn "cewler unavailable; continuing with brand sources"
else
    printf 'not_requested\n' > "$OUT_DIR/cewler.exit"
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

if [ "$WITH_BRAND" = true ] && [ -n "$PYDICTOR_BIN" ] && [ -n "$BRAND" ]; then
    PYDICTOR_TMP="$OUT_DIR/pydictor-raw"
    mkdir -p "$PYDICTOR_TMP"
    _run_stage pydictor python3 "$PYDICTOR_BIN" -extend "$BRAND" --leet 0 1 2 11 21 \
        --len "$MIN_LEN" "$MAX_LEN" -o "$PYDICTOR_TMP"
    find "$PYDICTOR_TMP" -type f -name '*.txt' -exec cat {} \; \
        | awk -v min="$MIN_LEN" -v max="$MAX_LEN" \
            'length($0) >= min && length($0) <= max && !seen[$0]++' > "$BRAND_OUT"
elif [ "$WITH_BRAND" = true ]; then
    printf 'unavailable\n' > "$OUT_DIR/pydictor.exit"
    DEGRADED=true
else
    printf 'not_requested\n' > "$OUT_DIR/pydictor.exit"
fi
if [ "$WITH_BRAND" = true ] && [ ! -s "$BRAND_OUT" ] && [ "${#BRAND}" -ge "$MIN_LEN" ] && [ "${#BRAND}" -le "$MAX_LEN" ]; then
    printf '%s\n' "$BRAND" > "$BRAND_OUT"
fi

awk 'NF && !seen[$0]++' "$CLEAN" "$OUT_DIR/selected-seeds.txt" > "$OUT_DIR/mutation-input.txt"
if [ "$WITH_HASHCAT" = true ] && [ -s "$OUT_DIR/mutation-input.txt" ] && [ -n "$HASHCAT_BIN" ] && [ -f "$RULE_FILE" ]; then
    log_ok "Applying Hashcat rule: $RULE_NAME"
    cp -- "$RULE_FILE" "$OUT_DIR/selected-rule.rule"
    _run_stage hashcat "$HASHCAT_BIN" --stdout "$OUT_DIR/mutation-input.txt" -r "$OUT_DIR/selected-rule.rule"
    awk -v min="$MIN_LEN" -v max="$MAX_LEN" \
        'length($0) >= min && length($0) <= max && !seen[$0]++' "$OUT_DIR/hashcat.stdout" > "$HASHCAT_OUT"
elif [ "$WITH_HASHCAT" = true ] && [ -s "$OUT_DIR/mutation-input.txt" ]; then
    printf 'unavailable\n' > "$OUT_DIR/hashcat.exit"
    DEGRADED=true
    log_warn "Hashcat or rule unavailable; keeping cleaned website words"
else
    printf 'not_requested\n' > "$OUT_DIR/hashcat.exit"
fi

awk 'NF && !seen[$0]++' "$OUT_DIR/selected-seeds.txt" "$BRAND_OUT" "$CLEAN" "$HASHCAT_OUT" > "$POOL"
cp "$POOL" "$RANKED"
chmod 600 "$RAW" "$CLEAN" "$BRAND_OUT" "$HASHCAT_OUT" "$POOL" "$RANKED"
PYTHONPATH="$(dirname "$SCRIPT_DIR")" python3 - "$BASE_OUT" "$OUT_DIR" "$TARGET" "$DEGRADED" <<'PY'
import hashlib, json, os, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
from tools.artifact_io import publish_bytes_create_only, write_json_atomic
base, run = map(Path, sys.argv[1:3])
files = {}
for name in ('from-website.txt', 'cleaned.txt', 'brand-pydictor.txt', 'website-hashcat.txt', 'candidate-pool.txt', 'ranked.txt'):
    data = (run / name).read_bytes()
    files[name] = {'path': str(run / name), 'sha256': hashlib.sha256(data).hexdigest(), 'lines': len(data.splitlines())}
    destination = base / name
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError('wordlist compatibility output is not a regular file')
    if destination.exists():
        publish_bytes_create_only(run / 'previous' / name, destination.read_bytes())
    with tempfile.NamedTemporaryFile(dir=base, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
stages = {p.stem: p.read_text().strip() for p in run.glob('*.exit')}
status = 'partial' if sys.argv[4] == 'true' else 'complete'
if not (run / 'candidate-pool.txt').stat().st_size:
    status = 'unavailable'
summary = {'schema_version': 1, 'target': sys.argv[3], 'status': status,
           'ts': datetime.now(timezone.utc).isoformat(), 'run_dir': str(run),
           'files': files, 'stages': stages, 'ranking': 'not_run',
           'live_input': False, 'ranked_txt': 'compatibility alias of candidate pool'}
write_json_atomic(run / 'summary.json', summary)
previous_summary = base / 'summary.json'
if previous_summary.is_symlink() or (previous_summary.exists() and not previous_summary.is_file()):
    raise ValueError('wordlist summary must be a regular file')
if previous_summary.exists():
    publish_bytes_create_only(run / 'previous' / 'summary.json', previous_summary.read_bytes())
write_json_atomic(base / 'summary.json', summary)
print('Receipt: ' + str(run / 'summary.json'))
PY

printf '\nCandidate pool: %s (%s entries)\n' "$POOL" "$(wc -l < "$POOL" | tr -d ' ')"
printf 'Compatibility alias: %s\n' "$RANKED"
printf 'Live input: generate and review spray-shortlist.txt; do not pass the candidate pool directly.\n'
[ -s "$POOL" ] || exit 2
[ "$DEGRADED" = false ] || exit 2
