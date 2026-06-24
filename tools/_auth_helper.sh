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
BB_AUTH_SESSION_ID="${BBHUNT_SESSION_ID:-}"

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
