#!/bin/bash
# =============================================================================
# Auth-helper — sourced by recon/scanner shell entrypoints.
#
# Reads BBHUNT_AUTH_HEADERS (newline-separated "Name: value" entries) and
# BBHUNT_SESSION_ID from the environment, exposes them as:
#
#   BB_AUTH_ARGS=(-H 'Name1: value1' -H 'Name2: value2' ...)
#   BB_AUTH_SESSION_ID="<12-char-hex>"
#
# Empty session = empty array = no behavior change for anonymous runs.
# =============================================================================

[ "${BASH_SOURCE[0]}" = "$0" ] && {
    echo "_auth_helper.sh must be sourced, not executed" >&2
    return 1 2>/dev/null || exit 1
}

BB_AUTH_ARGS=()
BB_URL_AUTH_ARGS=()
BB_AUTH_SESSION_ID="${BBHUNT_SESSION_ID:-}"
BB_AUTH_SOURCE_TARGET="${BBHUNT_AUTH_TARGET:-}"
BB_AUTH_BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -n "${BBHUNT_AUTH_HEADERS:-}" ]; then
    while IFS= read -r _bb_header; do
        case "$_bb_header" in
            ''|'#'*) continue ;;
        esac
        case "$_bb_header" in
            *$'\r'*) continue ;;
        esac
        BB_AUTH_ARGS+=(-H "$_bb_header")
    done <<< "$BBHUNT_AUTH_HEADERS"
    unset _bb_header

    if [ -z "$BB_AUTH_SESSION_ID" ]; then
        _bb_hash=""
        if command -v shasum >/dev/null 2>&1; then
            _bb_hash=$(printf '%s' "$BBHUNT_AUTH_HEADERS" | LC_ALL=C sort | shasum -a 256 2>/dev/null | cut -c1-12)
        elif command -v sha256sum >/dev/null 2>&1; then
            _bb_hash=$(printf '%s' "$BBHUNT_AUTH_HEADERS" | LC_ALL=C sort | sha256sum 2>/dev/null | cut -c1-12)
        fi
        BB_AUTH_SESSION_ID="$_bb_hash"
        export BBHUNT_SESSION_ID="$_bb_hash"
        unset _bb_hash
    fi
fi

bb_auth_banner() {
    if [ -n "$BB_AUTH_SESSION_ID" ]; then
        echo "[auth] session=$BB_AUTH_SESSION_ID headers=$(( ${#BB_AUTH_ARGS[@]} / 2 ))"
    fi
}

bb_auth_active() {
    [ "${#BB_AUTH_ARGS[@]}" -gt 0 ]
}

bb_auth_bind_target() {
    local requested_target="${1:-}"
    if bb_auth_active && [ -n "$BB_AUTH_SOURCE_TARGET" ] && [ -n "$requested_target" ]; then
        if ! PYTHONPATH="$BB_AUTH_BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" \
            python3 - "$BB_AUTH_SOURCE_TARGET" "$requested_target" <<'PY' >/dev/null 2>&1
import sys

from tools.target_paths import canonical_target_value

try:
    same = canonical_target_value(sys.argv[1]) == canonical_target_value(sys.argv[2])
except (TypeError, ValueError):
    same = False
raise SystemExit(0 if same else 1)
PY
        then
            BB_AUTH_ARGS=()
            BB_AUTH_SESSION_ID=""
            unset BBHUNT_AUTH_HEADERS BBHUNT_SESSION_ID BBHUNT_AUTH_ORIGINS
            unset BBHUNT_AUTH_HEADER BBHUNT_COOKIE BBHUNT_BEARER BBHUNT_API_KEY
        fi
    fi
    BB_AUTH_SOURCE_TARGET="$requested_target"
    BBHUNT_AUTH_TARGET="$requested_target"
    export BBHUNT_AUTH_TARGET
}

bb_auth_url_allowed() {
    local url="${1:-}"
    bb_auth_active || return 1
    [ -n "$url" ] || return 1
    PYTHONPATH="$BB_AUTH_BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        python3 - "$url" <<'PY' >/dev/null 2>&1
import os
import sys

from tools.auth_session import AuthSession

raise SystemExit(0 if AuthSession.from_env(os.environ).allows_url(sys.argv[1]) else 1)
PY
}

bb_auth_args_for_url() {
    BB_URL_AUTH_ARGS=()
    if bb_auth_url_allowed "${1:-}"; then
        BB_URL_AUTH_ARGS=("${BB_AUTH_ARGS[@]}")
    fi
}

bb_auth_filter_file() {
    local input_file="$1"
    local output_file="$2"
    : > "$output_file"
    [ -s "$input_file" ] || return 0
    if ! bb_auth_active; then
        cp "$input_file" "$output_file"
        return 0
    fi

    PYTHONPATH="$BB_AUTH_BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        python3 - "$input_file" "$output_file" <<'PY'
import os
import sys
from pathlib import Path

from tools.auth_session import AuthSession

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
session = AuthSession.from_env(os.environ)
with source.open(encoding="utf-8", errors="replace") as reader, destination.open(
    "w", encoding="utf-8"
) as writer:
    for raw in reader:
        value = raw.strip()
        if value and session.allows_url(value):
            writer.write(value + "\n")
PY
}
