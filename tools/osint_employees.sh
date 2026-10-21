#!/bin/bash
# =============================================================================
# OSINT Employees — gather employee names + email patterns for spray prep
#
# Pipeline:
#   1. theHarvester    — emails + names from search engines + CT logs
#   2. (opt) CrossLinked — LinkedIn employee names via Google/Bing dorks
#   3. username-anarchy — expand "First Last" into 32+ username permutations
#   4. (opt) pydictor --extend — personal-style password candidates from names
#
# Defaults are designed to stay OSINT-only (no LinkedIn auth, no shodan/censys
# API keys, no aggressive probing). LinkedIn search is opt-in.
#
# Usage:
#   tools/osint_employees.sh <target.com>
#   tools/osint_employees.sh <target.com> --company "Acme Corp" --with-linkedin
#   tools/osint_employees.sh <target.com> --sources bing,duckduckgo,crtsh --limit 200
# =============================================================================

set -euo pipefail

TARGET=""
COMPANY=""
SOURCES="duckduckgo,brave,yahoo,mojeek,crtsh,certspotter,hackertarget,otx"
LIMIT=500
WITH_LINKEDIN=false
WITH_SOCIAL=false
EMAIL_FORMAT='{first}.{last}'
REPO_ROOT=""
EMAILS_FILE=""
NAMES_FILE=""
WITH_HARVESTER=true
WITH_USERNAMES=true
TIMEOUT_SECONDS=300

_need_value() { [ "$#" -ge 2 ] && [ -n "${2:-}" ] || { echo "Missing value for $1" >&2; exit 1; }; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --company)              _need_value "$@"; COMPANY="$2"; shift 2 ;;
        --sources)              _need_value "$@"; SOURCES="$2"; shift 2 ;;
        --limit)                _need_value "$@"; LIMIT="$2"; shift 2 ;;
        --email-format)         _need_value "$@"; EMAIL_FORMAT="$2"; shift 2 ;;
        --repo-root)            _need_value "$@"; REPO_ROOT="$2"; shift 2 ;;
        --emails-file)          _need_value "$@"; EMAILS_FILE="$2"; shift 2 ;;
        --names-file)           _need_value "$@"; NAMES_FILE="$2"; shift 2 ;;
        --timeout)              _need_value "$@"; TIMEOUT_SECONDS="$2"; shift 2 ;;
        --skip-harvester)       WITH_HARVESTER=false; shift ;;
        --skip-usernames)       WITH_USERNAMES=false; shift ;;
        --with-linkedin)        WITH_LINKEDIN=true; shift ;;
        --with-pydictor-social) WITH_SOCIAL=true; shift ;;
        -h|--help)
            echo "Usage: $0 <target.com> [--company NAME] [--sources CSV] [--limit N]"
            echo "       [--emails-file FILE] [--names-file FILE] [--skip-harvester] [--skip-usernames]"
            echo "       [--with-linkedin] [--with-pydictor-social] [--timeout SECONDS] [--repo-root DIR]"
            echo "--email-format records an observed pattern; it does not confirm users."
            exit 0 ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *) [ -z "$TARGET" ] && TARGET="$1" || { echo "Unexpected arg: $1" >&2; exit 1; }; shift ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target.com> [--company \"Acme Corp\"] [--with-linkedin]" >&2
    exit 1
fi
[[ "$LIMIT" =~ ^0*[1-9][0-9]*$ && "$TIMEOUT_SECONDS" =~ ^0*[1-9][0-9]*$ ]] \
    || { echo "limit/timeout must be positive integers" >&2; exit 1; }
for input_file in "$EMAILS_FILE" "$NAMES_FILE"; do
    [ -z "$input_file" ] || [ -f "$input_file" ] || { echo "selected input file does not exist" >&2; exit 1; }
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -n "$REPO_ROOT" ] || REPO_ROOT="$(dirname "$SCRIPT_DIR")"
umask 077
TARGET_INFO="$(PYTHONPATH="$(dirname "$SCRIPT_DIR")" python3 - "$TARGET" "$REPO_ROOT" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit
from tools.target_paths import classify_target, target_storage_key
target, root = sys.argv[1:]
info = classify_target(target)
if info['kind'] != 'domain' or '*' in info['target']:
    raise ValueError('employee OSINT requires one concrete domain or URL')
repo = Path(root).expanduser().resolve()
output = repo / 'recon' / target_storage_key(target) / 'osint'
if any(parent.is_symlink() for parent in (output / 'runs', output, *output.parents)):
    raise ValueError('OSINT output must not traverse symlinks')
for name in ('emails.txt', 'employee-names.txt', 'observed-names.txt', 'inferred-names.txt', 'usernames.txt', 'personal-passwords.txt', 'summary.json'):
    destination = output / name
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError('OSINT compatibility output must be a regular file')
print(repo)
print(target_storage_key(target))
print(urlsplit(target if '://' in target else 'https://' + target).hostname)
PY
)"
mapfile -t TARGET_INFO_ROWS <<< "$TARGET_INFO"
REPO_ROOT="${TARGET_INFO_ROWS[0]}"
TARGET_KEY="${TARGET_INFO_ROWS[1]}"
TARGET_HOST="${TARGET_INFO_ROWS[2]}"

# Default company name = capitalize first label of domain (e.g., twilio.com -> Twilio)
if [ -z "$COMPANY" ]; then
    COMPANY="$(echo "$TARGET_HOST" | sed -E 's/^(www\.)?([^.]+)\..*/\2/' | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }

_have() { command -v "$1" >/dev/null 2>&1; }
_resolve_exec() {
    local explicit="$1" command_name="$2" fallback="$3"
    if [ -n "$explicit" ]; then
        [ ! -x "$explicit" ] || printf '%s\n' "$explicit"
    elif _have "$command_name"; then command -v "$command_name"
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

THEHARVESTER_BIN="$(_resolve_exec "${THEHARVESTER_BIN:-}" theHarvester "$HOME/Tools/theHarvester/bin/theHarvester")"
USERNAME_ANARCHY_BIN="$(_resolve_exec "${USERNAME_ANARCHY_BIN:-}" username-anarchy "$HOME/Tools/username-anarchy/username-anarchy")"
PYDICTOR_BIN="$(_resolve_file "${PYDICTOR_BIN:-}" "$HOME/Tools/pydictor/pydictor.py")"
CROSSLINKED_BIN="$(_resolve_exec "${CROSSLINKED_BIN:-}" crosslinked "$HOME/.local/bin/crosslinked")"
for variable in THEHARVESTER_BIN USERNAME_ANARCHY_BIN PYDICTOR_BIN CROSSLINKED_BIN; do
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

BASE_OUT="$REPO_ROOT/recon/${TARGET_KEY}/osint"
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
EMAILS="$OUT_DIR/emails.txt"
NAMES="$OUT_DIR/employee-names.txt"
USERNAMES="$OUT_DIR/usernames.txt"
PERSONAL_PW="$OUT_DIR/personal-passwords.txt"
for output_file in "$EMAILS" "$NAMES" "$USERNAMES" "$PERSONAL_PW" "$OUT_DIR/observed-names.txt" "$OUT_DIR/inferred-names.txt"; do
    : > "$output_file"
done
[ -z "$EMAILS_FILE" ] || cp -- "$EMAILS_FILE" "$OUT_DIR/selected-emails.txt"
if [ -n "$NAMES_FILE" ]; then
    cp -- "$NAMES_FILE" "$OUT_DIR/selected-names.txt"
    cp "$OUT_DIR/selected-names.txt" "$OUT_DIR/observed-names.txt"
fi

echo ""
echo "============================================="
echo "  OSINT Employees — $TARGET_HOST"
echo "============================================="
echo "  Company:     $COMPANY"
echo "  Sources:     $SOURCES"
echo "  LinkedIn:    $WITH_LINKEDIN"
echo "  Social PWs:  $WITH_SOCIAL"
echo "============================================="

# Step 1: preserve each collector's originals in the new run directory.
HARVESTER_BASENAME="theharvester"
if [ "$WITH_HARVESTER" = true ] && [ -n "$THEHARVESTER_BIN" ]; then
    log_ok "theHarvester (limit=$LIMIT, sources=$SOURCES)"
    (cd "$OUT_DIR" && _run_stage theharvester "$THEHARVESTER_BIN" -d "$TARGET_HOST" -b "$SOURCES" -l "$LIMIT" -q -f "$HARVESTER_BASENAME")
    [ "$(cat "$OUT_DIR/theharvester.exit")" = 0 ] || DEGRADED=true
elif [ "$WITH_HARVESTER" = true ]; then
    printf 'unavailable\n' > "$OUT_DIR/theharvester.exit"
    DEGRADED=true
    log_warn "theHarvester unavailable; retaining selected local inputs"
else
    printf 'not_requested\n' > "$OUT_DIR/theharvester.exit"
fi

HARVESTER_JSON="$OUT_DIR/${HARVESTER_BASENAME}.json"
if [ -f "$HARVESTER_JSON" ]; then
    if ! python3 - "$HARVESTER_JSON" "$OUT_DIR/harvester-emails.txt" <<'PY' 2>"$OUT_DIR/harvester-parse.stderr"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if not isinstance(data, dict) or not isinstance(data.get('emails', []), list):
    raise ValueError('invalid theHarvester email collection')
emails = data.get('emails', [])
if any(not isinstance(email, str) for email in emails):
    raise ValueError('invalid email row')
Path(sys.argv[2]).write_text(''.join(email + '\n' for email in emails), encoding='utf-8')
PY
    then
        printf 'invalid\n' > "$OUT_DIR/harvester-parse.exit"
        DEGRADED=true
        log_warn "theHarvester JSON is invalid; raw file retained"
    else
        printf '0\n' > "$OUT_DIR/harvester-parse.exit"
    fi
elif [ "$WITH_HARVESTER" = true ] && [ -n "$THEHARVESTER_BIN" ]; then
    printf 'missing\n' > "$OUT_DIR/harvester-parse.exit"
    DEGRADED=true
    log_warn "theHarvester produced no JSON; retained logs distinguish failure from zero observations"
fi
touch "$OUT_DIR/harvester-emails.txt" "$OUT_DIR/selected-emails.txt"
sort -u "$OUT_DIR/harvester-emails.txt" "$OUT_DIR/selected-emails.txt" > "$EMAILS"
EMAIL_COUNT=$(wc -l < "$EMAILS" | tr -d ' ')

# Step 2: derive names from email local-parts
# Heuristic: john.smith@x → "John Smith"; jsmith@x → skip (ambiguous)
log_ok "Step 2: deriving names from email local-parts"
: > "$NAMES"
if [ -s "$EMAILS" ]; then
    awk -F@ '{print $1}' "$EMAILS" \
        | { grep -E '^[a-z]+[._-][a-z]+$' || true; } \
        | tr '._-' '  ' \
        | awk '{print toupper(substr($1,1,1)) substr($1,2), toupper(substr($2,1,1)) substr($2,2)}' \
        | sort -u > "$NAMES"
fi
NAME_COUNT_BEFORE=$(wc -l < "$NAMES" | tr -d ' ')
log_ok "Derived $NAME_COUNT_BEFORE names from email patterns"
cp "$NAMES" "$OUT_DIR/inferred-names.txt"

# Step 3 (opt): CrossLinked for LinkedIn employees
if [ "$WITH_LINKEDIN" = true ]; then
    log_ok "Step 3: CrossLinked LinkedIn search for '$COMPANY'"
    CL_OUT="$OUT_DIR/crosslinked_names"
    if [ -n "$CROSSLINKED_BIN" ]; then
        _run_stage crosslinked "$CROSSLINKED_BIN" \
            -f '{first} {last}' \
            -o "$CL_OUT" \
            "$COMPANY"
        if [ -f "${CL_OUT}.txt" ]; then
            # Keep collector-observed names separate from email-pattern inference.
            cat "${CL_OUT}.txt" "$OUT_DIR/observed-names.txt" | sort -u > "${NAMES}.tmp"
            mv "${NAMES}.tmp" "$OUT_DIR/observed-names.txt"
        else
            DEGRADED=true
            printf 'missing\n' > "$OUT_DIR/crosslinked-output.exit"
            log_warn "CrossLinked produced no output file"
        fi
    else
        printf 'unavailable\n' > "$OUT_DIR/crosslinked.exit"
        DEGRADED=true
        log_warn "CrossLinked unavailable"
    fi
else
    printf 'not_requested\n' > "$OUT_DIR/crosslinked.exit"
fi
sort -u "$OUT_DIR/observed-names.txt" "$OUT_DIR/inferred-names.txt" > "$NAMES"

# Step 4: username-anarchy expansion
if [ "$WITH_USERNAMES" = true ] && [ -s "$NAMES" ] && [ -n "$USERNAME_ANARCHY_BIN" ]; then
    log_ok "Step 4: username-anarchy permutations"
    _run_stage username-anarchy "$USERNAME_ANARCHY_BIN" -i "$NAMES"
    sort -u "$OUT_DIR/username-anarchy.stdout" > "$USERNAMES"
    USERNAME_COUNT=$(wc -l < "$USERNAMES" | tr -d ' ')
    log_ok "Generated $USERNAME_COUNT username permutations -> $USERNAMES"
else
    if [ "$WITH_USERNAMES" = true ] && [ -s "$NAMES" ]; then
        DEGRADED=true
        printf 'unavailable\n' > "$OUT_DIR/username-anarchy.exit"
        log_warn "username-anarchy unavailable; names retained"
    else
        printf 'not_requested\n' > "$OUT_DIR/username-anarchy.exit"
    fi
    : > "$USERNAMES"
    USERNAME_COUNT=0
fi

# Step 5 (opt): pydictor personal-password candidates
if [ "$WITH_SOCIAL" = true ] && [ -s "$NAMES" ] && [ -n "$PYDICTOR_BIN" ]; then
    log_ok "Step 5: pydictor personal-password candidates"
    # Use first-name list as base, --extend adds common variations (year, !, 123)
    awk '{print tolower($1)}' "$NAMES" | sort -u > "$OUT_DIR/firstnames-lower.txt"
    _run_stage pydictor python3 "$PYDICTOR_BIN" \
            -extend "$OUT_DIR/firstnames-lower.txt" \
            --level 3 \
            -o "$OUT_DIR/pydictor_raw"
    if [ -d "$OUT_DIR/pydictor_raw" ]; then
        # pydictor outputs to a directory; flatten
        find "$OUT_DIR/pydictor_raw" -type f -name "*.txt" -exec cat {} \; \
            | sort -u > "$PERSONAL_PW"
        PW_COUNT=$(wc -l < "$PERSONAL_PW" | tr -d ' ')
        log_ok "Generated $PW_COUNT personal-style passwords -> $PERSONAL_PW"
    fi
elif [ "$WITH_SOCIAL" = true ] && [ -s "$NAMES" ]; then
    printf 'unavailable\n' > "$OUT_DIR/pydictor.exit"
    DEGRADED=true
else
    printf 'not_requested\n' > "$OUT_DIR/pydictor.exit"
fi

PYTHONPATH="$(dirname "$SCRIPT_DIR")" python3 - "$BASE_OUT" "$OUT_DIR" "$TARGET" "$DEGRADED" "$EMAIL_FORMAT" <<'PY'
import hashlib, os, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
from tools.artifact_io import publish_bytes_create_only, write_json_atomic
base, run = map(Path, sys.argv[1:3])
files = {}
for name in ('emails.txt', 'employee-names.txt', 'observed-names.txt', 'inferred-names.txt', 'usernames.txt', 'personal-passwords.txt'):
    data = (run / name).read_bytes()
    files[name] = {'path': str(run / name), 'sha256': hashlib.sha256(data).hexdigest(), 'lines': len(data.splitlines())}
    destination = base / name
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError('OSINT compatibility output is not a regular file')
    if destination.exists():
        publish_bytes_create_only(run / 'previous' / name, destination.read_bytes())
    with tempfile.NamedTemporaryFile(dir=base, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
status = 'partial' if sys.argv[4] == 'true' else 'complete'
if not any((run / name).stat().st_size for name in ('emails.txt', 'employee-names.txt')):
    status = 'unavailable' if sys.argv[4] == 'true' else 'complete'
summary = {'schema_version': 1, 'target': sys.argv[3], 'status': status,
           'ts': datetime.now(timezone.utc).isoformat(), 'run_dir': str(run), 'files': files,
           'stages': {p.stem: p.read_text().strip() for p in run.glob('*.exit')},
           'email_format_context': sys.argv[5], 'confirmed_application_accounts': None,
           'names_from_email': 'inferred from pattern; not identity confirmation',
           'observed_names': 'selected file or collector observations; not account confirmation',
           'usernames': 'permutations; not confirmed accounts', 'login_attempts': 0}
write_json_atomic(run / 'summary.json', summary)
previous_summary = base / 'summary.json'
if previous_summary.is_symlink() or (previous_summary.exists() and not previous_summary.is_file()):
    raise ValueError('OSINT summary must be a regular file')
if previous_summary.exists():
    publish_bytes_create_only(run / 'previous' / 'summary.json', previous_summary.read_bytes())
write_json_atomic(base / 'summary.json', summary)
print('Receipt: ' + str(run / 'summary.json'))
PY

# Summary
echo ""
echo "============================================="
echo "  Summary"
echo "============================================="
printf "  %-12s %s\n" "Target:" "$TARGET_HOST"
printf "  %-12s %d emails        %s\n" "Emails:" "$EMAIL_COUNT" "$EMAILS"
printf "  %-12s %d names         %s\n" "Names:" "$(wc -l < "$NAMES" | tr -d ' ')" "$NAMES"
printf "  %-12s %d permutations  %s\n" "Usernames:" "$USERNAME_COUNT" "$USERNAMES"
if [ "$WITH_SOCIAL" = true ] && [ -f "$PERSONAL_PW" ]; then
    printf "  %-12s %d candidates   %s\n" "Personal PW:" "$(wc -l < "$PERSONAL_PW" | tr -d ' ')" "$PERSONAL_PW"
fi
echo ""
echo "  Material status: email observations, inferred names and username permutations are separate."
echo "  Application account ownership and validity have not been confirmed."
echo "============================================="
[ "$DEGRADED" = false ] || exit 2
