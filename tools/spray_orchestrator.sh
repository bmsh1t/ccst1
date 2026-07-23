#!/bin/bash
# Spray 兼容入口：负责 CLI、人工确认和适配器分发；确定性契约由 Python owner 校验。

set -euo pipefail

TARGET_URL=""
MODE=""
USERS_FILE=""
PASSES_FILE=""
DELAY=1800
JITTER=60
AGGRESSIVE=false
DRY_RUN=false
CONTINUE_ON_HIT=false
I_UNDERSTAND=false
INSECURE=false
INTERACTIVE_CONFIRMED=false
REQUEST_SPEC=""
PREFLIGHT=""
RESUME=""
POST_DATA=""
CSRF_EXTRACT=""
SUCCESS_REGEX=""
FAIL_REGEX=""
OAUTH_CLIENT_ID=""
OAUTH_CLIENT_SECRET=""
OAUTH_SCOPE=""

_need_value() {
    if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
        echo "Missing value for $1" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)                _need_value "$@"; MODE="$2"; shift 2 ;;
        --users)               _need_value "$@"; USERS_FILE="$2"; shift 2 ;;
        --passes)              _need_value "$@"; PASSES_FILE="$2"; shift 2 ;;
        --delay)               _need_value "$@"; DELAY="$2"; shift 2 ;;
        --jitter)              _need_value "$@"; JITTER="$2"; shift 2 ;;
        --aggressive)          AGGRESSIVE=true; DELAY=60; JITTER=10; shift ;;
        --dry-run)             DRY_RUN=true; shift ;;
        --continue-on-hit)     CONTINUE_ON_HIT=true; shift ;;
        --i-understand)        I_UNDERSTAND=true; shift ;;
        --insecure)            INSECURE=true; shift ;;
        --request-spec)        _need_value "$@"; REQUEST_SPEC="$2"; shift 2 ;;
        --preflight)           _need_value "$@"; PREFLIGHT="$2"; shift 2 ;;
        --resume)              _need_value "$@"; RESUME="$2"; shift 2 ;;
        --post-data)           _need_value "$@"; POST_DATA="$2"; shift 2 ;;
        --csrf-extract)        _need_value "$@"; CSRF_EXTRACT="$2"; shift 2 ;;
        --success-regex)       _need_value "$@"; SUCCESS_REGEX="$2"; shift 2 ;;
        --fail-regex)          _need_value "$@"; FAIL_REGEX="$2"; shift 2 ;;
        --oauth-client-id)     _need_value "$@"; OAUTH_CLIENT_ID="$2"; shift 2 ;;
        --oauth-client-secret) _need_value "$@"; OAUTH_CLIENT_SECRET="$2"; shift 2 ;;
        --oauth-scope)         _need_value "$@"; OAUTH_SCOPE="$2"; shift 2 ;;
        -h|--help)
            cat <<'HELP'
Usage: tools/spray_orchestrator.sh URL --mode MODE --users FILE --passes FILE [flags]
Modes: http-form | oauth | o365 | okta
Common: --delay N --jitter N --dry-run --preflight FILE --resume RUN_DIR
        --continue-on-hit --i-understand
Builtin HTTP/OAuth only: --insecure (explicitly disable TLS certificate verification)
HTTP:   --request-spec FILE
Legacy HTTP: --post-data TEMPLATE --csrf-extract REGEX --success-regex REGEX --fail-regex REGEX
OAuth:  --oauth-client-id ID --oauth-client-secret SECRET --oauth-scope SCOPE
HELP
            exit 0
            ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *)
            if [ -n "$TARGET_URL" ]; then
                echo "Unexpected arg: $1" >&2
                exit 1
            fi
            TARGET_URL="$1"
            shift
            ;;
    esac
done

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_bold() { echo -e "${BOLD}$1${NC}"; }

[ -n "$TARGET_URL" ] || { log_err "Target URL required"; exit 1; }
[ -n "$MODE" ] || { log_err "--mode required: http-form|oauth|o365|okta"; exit 1; }
[ -n "$USERS_FILE" ] || { log_err "--users <file> required"; exit 1; }
[ -n "$PASSES_FILE" ] || { log_err "--passes <file> required"; exit 1; }
[ -f "$USERS_FILE" ] || { log_err "Users file not found: $USERS_FILE"; exit 1; }
[ -f "$PASSES_FILE" ] || { log_err "Passes file not found: $PASSES_FILE"; exit 1; }
[[ "$DELAY" =~ ^[0-9]+$ ]] || { log_err "--delay must be a non-negative integer"; exit 1; }
[[ "$JITTER" =~ ^[0-9]+$ ]] || { log_err "--jitter must be a non-negative integer"; exit 1; }
[[ "$TARGET_URL" =~ ^https?://[^/[:space:]]+ ]] || { log_err "Target must be an http/https URL"; exit 1; }

case "$MODE" in
    http-form|oauth|o365|okta) ;;
    *) log_err "Invalid mode: $MODE"; exit 1 ;;
esac

HTTP_FLAGS_SET=false
[ -n "$POST_DATA$CSRF_EXTRACT$SUCCESS_REGEX$FAIL_REGEX$REQUEST_SPEC" ] && HTTP_FLAGS_SET=true
OAUTH_FLAGS_SET=false
[ -n "$OAUTH_CLIENT_ID$OAUTH_CLIENT_SECRET$OAUTH_SCOPE" ] && OAUTH_FLAGS_SET=true
if [ "$MODE" != "http-form" ] && [ "$HTTP_FLAGS_SET" = true ]; then
    log_err "HTTP form flags are only valid with --mode http-form"
    exit 1
fi
if [ "$MODE" != "oauth" ] && [ "$OAUTH_FLAGS_SET" = true ]; then
    log_err "OAuth flags are only valid with --mode oauth"
    exit 1
fi
if [ "$INSECURE" = true ] && [[ "$MODE" != "http-form" && "$MODE" != "oauth" ]]; then
    log_err "--insecure is only valid with --mode http-form or oauth"
    exit 1
fi
if [ -n "$REQUEST_SPEC" ] && [ -n "$POST_DATA$CSRF_EXTRACT$SUCCESS_REGEX$FAIL_REGEX" ]; then
    log_err "--request-spec cannot be combined with legacy HTTP form flags"
    exit 1
fi
if [ "$DRY_RUN" = true ] && { [ -n "$PREFLIGHT" ] || [ -n "$RESUME" ]; }; then
    log_err "--dry-run cannot be combined with --preflight or --resume"
    exit 1
fi

TARGET_HOST="$(python3 - "$TARGET_URL" <<'PY'
import sys
from urllib.parse import urlparse
print(urlparse(sys.argv[1]).hostname or "")
PY
)"
[ -n "$TARGET_HOST" ] || { log_err "Target URL has no hostname"; exit 1; }
USER_COUNT=$(awk 'NF && !seen[$0]++ {n++} END {print n+0}' "$USERS_FILE")
PASS_COUNT=$(awk 'NF && !seen[$0]++ {n++} END {print n+0}' "$PASSES_FILE")
[ "$USER_COUNT" -gt 0 ] || { log_err "Users file contains no non-empty entries"; exit 1; }
[ "$PASS_COUNT" -gt 0 ] || { log_err "Passes file contains no non-empty entries"; exit 1; }
TOTAL_ATTEMPTS=$((USER_COUNT * PASS_COUNT))
DURATION_SEC=$(((PASS_COUNT > 0 ? PASS_COUNT - 1 : 0) * (DELAY + JITTER / 2)))

printf '\n=============================================\n'
log_bold "  SPRAY PRE-FLIGHT — $TARGET_HOST"
printf '=============================================\n'
printf "  %-18s %s\n" "Target URL:" "$TARGET_URL"
printf "  %-18s %s\n" "Mode:" "$MODE"
printf "  %-18s %s (%d unique)\n" "Users file:" "$USERS_FILE" "$USER_COUNT"
printf "  %-18s %s (%d unique)\n" "Passes file:" "$PASSES_FILE" "$PASS_COUNT"
printf "  %-18s %d\n" "Total attempts:" "$TOTAL_ATTEMPTS"
printf "  %-18s %ds + %ds jitter %s\n" "Delay/round:" "$DELAY" "$JITTER" \
    "$([ "$AGGRESSIVE" = true ] && echo '(--aggressive)' || echo '')"
printf "  %-18s ~%ds\n" "Est. duration:" "$DURATION_SEC"
printf "  %-18s %s\n" "Dry-run:" "$DRY_RUN"
printf '=============================================\n'

log_warn "Each account receives at most one attempt per password round."
log_warn "Configured rounds per account: $PASS_COUNT; no lockout percentage is inferred."

if [ "$I_UNDERSTAND" != true ] && [ "$DRY_RUN" != true ]; then
    read -r -p "Type the target hostname ($TARGET_HOST) to confirm: " TYPED
    [ "$TYPED" = "$TARGET_HOST" ] || { log_err "Hostname confirmation failed"; exit 2; }
    read -r -p "Type 'yes' to proceed (anything else aborts): " CONFIRM
    [ "$CONFIRM" = "yes" ] || { log_warn "Aborted by user"; exit 0; }
    INTERACTIVE_CONFIRMED=true
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SPRAY_REPO_ROOT="$(pwd)"
export SPRAY_DELAY="$DELAY"
export SPRAY_JITTER="$JITTER"
export SPRAY_CONTINUE_ON_HIT="$CONTINUE_ON_HIT"
export SPRAY_TARGET_URL="$TARGET_URL"
export SPRAY_USERS_FILE="$USERS_FILE"
export SPRAY_PASSES_FILE="$PASSES_FILE"
export SPRAY_MODE="$MODE"
export SPRAY_DRY_RUN="$DRY_RUN"
export SPRAY_I_UNDERSTAND="$I_UNDERSTAND"
export SPRAY_PREFLIGHT="$PREFLIGHT"
export SPRAY_RESUME="$RESUME"
export SPRAY_REQUEST_SPEC="$REQUEST_SPEC"
export SPRAY_INSECURE="$INSECURE"
export SPRAY_INTERACTIVE_CONFIRMED="$INTERACTIVE_CONFIRMED"

log_ok "Dispatching to '$MODE' handler"
case "$MODE" in
    http-form)
        export SPRAY_POST_DATA="$POST_DATA"
        export SPRAY_CSRF_EXTRACT="$CSRF_EXTRACT"
        export SPRAY_SUCCESS_REGEX="$SUCCESS_REGEX"
        export SPRAY_FAIL_REGEX="$FAIL_REGEX"
        python3 "$SCRIPT_DIR/_spray_http_form.py"
        ;;
    oauth)
        export SPRAY_OAUTH_CLIENT_ID="$OAUTH_CLIENT_ID"
        export SPRAY_OAUTH_CLIENT_SECRET="$OAUTH_CLIENT_SECRET"
        export SPRAY_OAUTH_SCOPE="$OAUTH_SCOPE"
        python3 "$SCRIPT_DIR/_spray_oauth.py"
        ;;
    o365|okta)
        TREVOR_BIN="$(command -v trevorspray 2>/dev/null || true)"
        [ -n "$TREVOR_BIN" ] || { log_err "trevorspray not installed"; exit 1; }
        export SPRAY_TREVOR_BIN="$TREVOR_BIN"
        python3 "$SCRIPT_DIR/_spray_trevor.py"
        ;;
esac
