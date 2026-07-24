#!/bin/bash
# =============================================================================
# Enhanced Recon Engine
# Full reconnaissance pipeline for target-driven penetration testing
# Usage: ./recon_engine.sh <target-domain|ip|cidr|list-file> [--quick|--normal|--deep|--full]
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
log_vuln()  { echo -e "${RED}[VULN]${NC} $1"; }

# Emit a machine-readable hint block at the end of a phase. Format is a
# YAML-style key: value block prefixed with `## CLAUDE_HINT` so Claude (in CLI)
# can quickly grok the phase outcome + recommended next action without re-reading
# the full stdout or stat'ing every output file. Pass key/value pairs as args.
#
# Usage:
#   emit_claude_hint \
#     phase subdomain_enum \
#     subdomain_total 234 \
#     sources subfinder,assetfinder \
#     next_priority_action "bash tools/takeover_scanner.sh recon/<t>/subdomains/all.txt"
#
# Multi-line values (lists): pass empty value, then add subsequent rows with the
# `- ` prefix using emit_claude_hint_list (see below) — kept separate so this
# function stays trivially `set -e` safe.
emit_claude_hint() {
    {
        echo ""
        echo "## CLAUDE_HINT"
        while [ "$#" -ge 2 ]; do
            printf '%s: %s\n' "$1" "$2"
            shift 2
        done
    } 2>/dev/null || true
}

# Emit a list under a single hint key. Use after a paired key with empty value.
emit_claude_hint_list() {
    local key="$1"
    shift
    {
        echo "${key}:"
        for item in "$@"; do
            echo "  - ${item}"
        done
    } 2>/dev/null || true
}

# Emit a `next_actions` block (≥1 action). Pass each action as a separate arg.
# Trailing blank line keeps the block visually separated from subsequent phases.
# Intent: surface ≥2 candidate next moves so the agent picks based on evidence
# rather than being locked into a single prescriptive directive.
emit_claude_hint_actions() {
    {
        echo "next_actions:"
        for action in "$@"; do
            echo "  - ${action}"
        done
        echo ""
    } 2>/dev/null || true
}

record_recon_phase() {
    local phase="$1"
    local status="${2:-ok}"
    local artifact="${3:-}"
    local count="${4:-0}"
    local note="${5:-}"

    # Manifest 是阶段账本，不做价值判断；用于让 Claude 区分“无结果”和“未运行/跳过”。
    [ -n "${RECON_MANIFEST:-}" ] || return 0
    python3 - "$RECON_MANIFEST" "$TARGET" "${RECON_TARGET_KEY:-}" "$RECON_PROFILE" \
        "$phase" "$status" "$artifact" "$count" "$note" <<'PY' || true
import json
import sys
from datetime import datetime, timezone

manifest, target, target_key, profile, phase, status, artifact, count, note = sys.argv[1:]
try:
    count_value = int(str(count).strip() or "0")
except ValueError:
    count_value = 0

record = {
    "record_type": "recon_phase",
    "target": target,
    "target_key": target_key,
    "mode": profile,
    "phase": phase,
    "status": status,
    "artifact": artifact,
    "count": count_value,
    "note": note,
    "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
with open(manifest, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
PY
}

record_recon_collector() {
    local collector="$1"
    local status="$2"
    local artifact="$3"
    local count="$4"
    local duration="$5"
    local note="${6:-}"

    [ -n "${RECON_MANIFEST:-}" ] || return 0
    python3 - "$RECON_MANIFEST" "$TARGET" "${RECON_TARGET_KEY:-}" "$RECON_PROFILE" \
        "$collector" "$status" "$artifact" "$count" "$duration" "$note" <<'PY' || true
import json
import sys
from datetime import datetime, timezone

manifest, target, target_key, profile, collector, status, artifact, count, duration, note = sys.argv[1:]
record = {
    "schema_version": 1,
    "record_type": "recon_collector",
    "target": target,
    "target_key": target_key,
    "mode": profile,
    "collector": collector,
    "status": status,
    "artifact": artifact,
    "count": int(count or 0),
    "duration_seconds": int(duration or 0),
    "note": note,
    "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
with open(manifest, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
PY
}

build_filtered_first_backstop() {
    local filtered="$1"
    local raw="$2"
    local output="$3"

    # filtered 只决定优先级，raw 作为无损兜底追加，避免降噪误删导致后续 JS/参数证据变薄。
    : > "$output"
    {
        [ -s "$filtered" ] && cat "$filtered"
        [ -s "$raw" ] && cat "$raw"
    } 2>/dev/null | awk 'NF && !seen[$0]++' > "$output" || true
}

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

COLLECTOR_PIDS=()
COLLECTOR_NAMES=()
COLLECTOR_ARTIFACTS=()
COLLECTOR_ARTIFACT_LABELS=()
COLLECTOR_META_FILES=()

artifact_line_count() {
    local artifact="$1"
    local count
    if [ -s "$artifact" ] || { [ -f "$artifact" ] && [ ! -f "${artifact}.gz" ]; }; then
        wc -l < "$artifact" 2>/dev/null | tr -d ' '
    elif [ -f "${artifact}.gz" ]; then
        count=$(gzip -cd "${artifact}.gz" 2>/dev/null | wc -l | tr -d ' ' || true)
        printf '%s\n' "${count:-0}"
    else
        printf '0\n'
    fi
}

append_artifact() {
    local artifact="$1"
    if [ -s "$artifact" ]; then
        cat "$artifact"
    elif [ -s "${artifact}.gz" ]; then
        gzip -cd "${artifact}.gz" 2>/dev/null || true
    fi
}

run_collector_task() {
    local artifact="$1"
    local meta_file="$2"
    shift 2
    local started rc status note duration temp_artifact merged_artifact
    started=$(date +%s)
    mkdir -p "$(dirname "$artifact")" "$(dirname "$meta_file")"
    temp_artifact="$(mktemp "$(dirname "$artifact")/.${artifact##*/}.collector.XXXXXX")"
    set +e
    "$@" "$temp_artifact"
    rc=$?
    set -e
    duration=$(( $(date +%s) - started ))

    case "$rc" in
        0)
            mv -f "$temp_artifact" "$artifact"
            rm -f "${artifact}.gz"
            status="ok"
            note=""
            ;;
        3)
            rm -f "$temp_artifact"
            [ ! -s "${artifact}.gz" ] || rm -f "$artifact"
            status="unavailable"
            note="required tool unavailable; prior artifact preserved"
            ;;
        4)
            rm -f "$temp_artifact"
            [ ! -s "${artifact}.gz" ] || rm -f "$artifact"
            status="skipped"
            note="not applicable for this target/profile; prior artifact preserved"
            ;;
        124)
            merged_artifact="${temp_artifact}.merged"
            { append_artifact "$artifact"; cat "$temp_artifact"; } \
                | awk 'NF && !seen[$0]++' > "$merged_artifact"
            mv -f "$merged_artifact" "$artifact"
            rm -f "$temp_artifact" "${artifact}.gz"
            status="partial"
            note="collector timed out; prior and partial artifacts preserved"
            ;;
        *)
            if [ -s "$temp_artifact" ]; then
                merged_artifact="${temp_artifact}.merged"
                { append_artifact "$artifact"; cat "$temp_artifact"; } \
                    | awk 'NF && !seen[$0]++' > "$merged_artifact"
                mv -f "$merged_artifact" "$artifact"
                rm -f "$temp_artifact" "${artifact}.gz"
                status="partial"
                note="collector exited $rc; prior and partial artifacts preserved"
            else
                rm -f "$temp_artifact"
                [ ! -s "${artifact}.gz" ] || rm -f "$artifact"
                status="error"
                note="collector exited $rc without new results; prior artifact preserved"
            fi
            ;;
    esac
    printf '%s\t%s\t%s\n' "$status" "$duration" "$note" > "$meta_file"
}

start_collector() {
    local name="$1"
    local artifact="$2"
    local artifact_label="$3"
    shift 3
    local meta_file="$RECON_DIR/logs/collectors/${name}.status"
    mkdir -p "$(dirname "$meta_file")"
    : > "$meta_file"
    log_step "Starting $name collector..."
    run_collector_task "$artifact" "$meta_file" "$@" &
    COLLECTOR_PIDS+=("$!")
    COLLECTOR_NAMES+=("$name")
    COLLECTOR_ARTIFACTS+=("$artifact")
    COLLECTOR_ARTIFACT_LABELS+=("$artifact_label")
    COLLECTOR_META_FILES+=("$meta_file")
}

wait_collector_group() {
    local index pid name artifact artifact_label meta_file status duration note count
    for index in "${!COLLECTOR_PIDS[@]}"; do
        pid="${COLLECTOR_PIDS[$index]}"
        name="${COLLECTOR_NAMES[$index]}"
        artifact="${COLLECTOR_ARTIFACTS[$index]}"
        artifact_label="${COLLECTOR_ARTIFACT_LABELS[$index]}"
        meta_file="${COLLECTOR_META_FILES[$index]}"
        wait "$pid" || true
        status="error"
        duration=0
        note="collector ended without status metadata"
        if [ -s "$meta_file" ]; then
            IFS=$'\t' read -r status duration note < "$meta_file" || true
        fi
        count=$(artifact_line_count "$artifact" || echo 0)
        record_recon_collector "$name" "$status" "$artifact_label" "$count" "$duration" "$note"
        if [ "$status" = "ok" ]; then
            log_done "$name: $count result(s) in ${duration}s"
        else
            log_warn "$name: $status (${note:-no detail})"
        fi
    done
    COLLECTOR_PIDS=()
    COLLECTOR_NAMES=()
    COLLECTOR_ARTIFACTS=()
    COLLECTOR_ARTIFACT_LABELS=()
    COLLECTOR_META_FILES=()
}

env_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

post_compress_raw_recon_urls() {
    local recon_dir="$1"
    local min_mb="${BBHUNT_RECON_COMPRESS_MIN_MB:-5}"
    local min_bytes=0
    local compressed=0
    local skipped=0
    local total_before=0
    local total_after=0
    local src file before after gz_size

    # 默认开启无损压缩：只压缩已并入 all.txt 的原始采集源，
    # 不动 all.txt/with_params.txt/exposure/live/subdomains，避免影响后续 AI 分析。
    # 如需保留原始 .txt 文件形态，可设置 BBHUNT_RECON_POST_COMPRESS=0。
    if ! env_truthy "${BBHUNT_RECON_POST_COMPRESS:-1}"; then
        return 0
    fi

    if ! command -v gzip >/dev/null 2>&1; then
        log_warn "Post-run raw URL compression requested but gzip is not installed"
        return 0
    fi

    if ! [[ "$min_mb" =~ ^[0-9]+$ ]]; then
        log_warn "Invalid BBHUNT_RECON_COMPRESS_MIN_MB=$min_mb — using 5"
        min_mb=5
    fi
    min_bytes=$((min_mb * 1024 * 1024))

    echo ""
    log_info "Post-run storage guard: compress raw URL source files"

    for src in gau wayback waymore katana; do
        file="$recon_dir/urls/${src}.txt"
        [ -f "$file" ] || continue

        before=$(wc -c < "$file" 2>/dev/null | tr -d ' ' || echo 0)
        if [ "${before:-0}" -lt "$min_bytes" ]; then
            skipped=$((skipped + 1))
            continue
        fi

        total_before=$((total_before + before))
        gzip -9 -f "$file" 2>/dev/null || {
            log_warn "Failed to compress $file"
            continue
        }

        gz_size=0
        [ -f "${file}.gz" ] && gz_size=$(wc -c < "${file}.gz" 2>/dev/null | tr -d ' ' || echo 0)
        after="${gz_size:-0}"
        total_after=$((total_after + after))
        compressed=$((compressed + 1))
        log_done "compressed ${src}.txt -> ${src}.txt.gz ($(numfmt --to=iec-i --suffix=B "$before" 2>/dev/null || echo "${before}B") -> $(numfmt --to=iec-i --suffix=B "$after" 2>/dev/null || echo "${after}B"))"
    done

    if [ "$compressed" -eq 0 ]; then
        log_done "No raw URL source files exceeded ${min_mb}MB; nothing compressed"
    else
        local saved=$((total_before - total_after))
        [ "$saved" -lt 0 ] && saved=0
        log_done "Raw URL compression complete: $compressed file(s), saved ~$(numfmt --to=iec-i --suffix=B "$saved" 2>/dev/null || echo "${saved}B")"
    fi
    [ "$skipped" -gt 0 ] && log_step "Skipped $skipped small raw URL source file(s) below ${min_mb}MB"

    emit_claude_hint \
        phase                recon_storage \
        post_compress        "enabled" \
        compressed_raw_files "$compressed" \
        min_size_mb          "$min_mb" \
        note                 "all.txt/with_params.txt/exposure/live/subdomains preserved"
    emit_claude_hint_actions \
        "continue analysis from recon/${RECON_TARGET_KEY}/urls/all.txt and *_filtered.txt; raw source .gz files are evidence archives" \
        "if disk remains tight, review large recon logs before deleting any recon intelligence"
}

cleanup_auth_tmpfiles() {
    [ -n "${WAFW00F_HEADERS_FILE:-}" ] && [ -f "$WAFW00F_HEADERS_FILE" ] && rm -f "$WAFW00F_HEADERS_FILE"
    [ -n "${FFUF_RESULT_TMP:-}" ] && [ -f "$FFUF_RESULT_TMP" ] && rm -f "$FFUF_RESULT_TMP"
    [ -n "${FFUF_CONTROL_TMP:-}" ] && [ -f "$FFUF_CONTROL_TMP" ] && rm -f "$FFUF_CONTROL_TMP"
    [ -n "${FFUF_CONTROL_RUN_TMP:-}" ] && [ -f "$FFUF_CONTROL_RUN_TMP" ] && rm -f "$FFUF_CONTROL_RUN_TMP"
    [ -n "${FFUF_CONTROL_WORDLIST_TMP:-}" ] && [ -f "$FFUF_CONTROL_WORDLIST_TMP" ] && rm -f "$FFUF_CONTROL_WORDLIST_TMP"
    return 0  # Always succeed: EXIT trap propagates its return code to the script
}

prepare_wafw00f_headers_file() {
    [ "${#BB_AUTH_ARGS[@]}" -gt 0 ] || return 1

    WAFW00F_HEADERS_FILE="$(mktemp "${TMPDIR:-/tmp}/bbhunt-wafw00f-headers.XXXXXX")"
    local i=0
    while [ "$i" -lt "${#BB_AUTH_ARGS[@]}" ]; do
        if [ "${BB_AUTH_ARGS[$i]}" = "-H" ] && [ $((i + 1)) -lt "${#BB_AUTH_ARGS[@]}" ]; then
            printf '%s\n' "${BB_AUTH_ARGS[$((i + 1))]}" >> "$WAFW00F_HEADERS_FILE"
        fi
        i=$((i + 2))
    done

    if [ ! -s "$WAFW00F_HEADERS_FILE" ]; then
        rm -f "$WAFW00F_HEADERS_FILE"
        WAFW00F_HEADERS_FILE=""
        return 1
    fi
    return 0
}

resolve_pd_httpx() {
    local cand
    for cand in \
        "$HOME/go/bin/httpx" \
        "/opt/homebrew/bin/httpx" \
        "/usr/local/bin/httpx" \
        "$(command -v httpx 2>/dev/null || true)"; do
        [ -z "$cand" ] && continue
        [ -x "$cand" ] || continue
        if "$cand" -version 2>&1 | grep -qi "projectdiscovery"; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    return 1
}

resolve_linkfinder_path() {
    local cand
    for cand in \
        "$(command -v linkfinder 2>/dev/null || true)" \
        "$(command -v linkfinder.py 2>/dev/null || true)" \
        "$SHARED_TOOLS_DIR/LinkFinder/linkfinder.py" \
        "$HOME/tools/LinkFinder/linkfinder.py" \
        "$HOME/Tools/LinkFinder/linkfinder.py"; do
        [ -z "$cand" ] && continue
        [ -f "$cand" ] || [ -x "$cand" ] || continue
        printf '%s\n' "$cand"
        return 0
    done
    return 1
}

TARGET="${1:?Usage: $0 <target-domain|ip|cidr|list-file> [--quick|--normal|--deep|--full]}"
RECON_MODE_FLAG="${2:-}"
case "$RECON_MODE_FLAG" in
    ""|--full)
        RECON_PROFILE="full"
        QUICK_MODE=""
        ;;
    --quick)
        RECON_PROFILE="quick"
        QUICK_MODE="--quick"
        ;;
    --normal)
        RECON_PROFILE="normal"
        QUICK_MODE=""
        ;;
    --deep)
        RECON_PROFILE="deep"
        QUICK_MODE=""
        ;;
    *)
        log_err "Unknown recon profile: $RECON_MODE_FLAG"
        exit 2
        ;;
esac
RECON_STARTED_EPOCH=$(date +%s)
RECON_SOFT_BUDGET_SECONDS="${BBHUNT_RECON_SOFT_BUDGET_SECONDS:-1800}"
if ! [[ "$RECON_SOFT_BUDGET_SECONDS" =~ ^[0-9]+$ ]]; then
    log_err "Invalid BBHUNT_RECON_SOFT_BUDGET_SECONDS=$RECON_SOFT_BUDGET_SECONDS"
    exit 2
fi
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
if [ "${BBHUNT_RUNTIME_PHASE_LOCKED:-}" != "recon" ] || [ "${BBHUNT_RUNTIME_LOCK_TARGET:-}" != "$TARGET" ]; then
    exec python3 "$BASE_DIR/tools/runtime_phase_exec.py" \
        --repo-root "$BASE_DIR" --target "$TARGET" --phase recon -- \
        bash "$SCRIPT_PATH" "$TARGET" "$RECON_MODE_FLAG"
fi
# 与 Osmedeus 01-osint.yaml 的 `toolsDir` 对齐：默认共用 $HOME/Tools。
# 可用 BBHUNT_TOOLS_DIR 或 OSMEDEUS_TOOLS_DIR 显式覆盖，便于多套工具目录共存。
SHARED_TOOLS_DIR="${BBHUNT_TOOLS_DIR:-${OSMEDEUS_TOOLS_DIR:-$HOME/Tools}}"

# Auth-aware hunting: load BBHUNT_AUTH_HEADERS / BBHUNT_SESSION_ID into
# BB_AUTH_ARGS=(-H 'Name: value' ...). Empty session = no-op.
# shellcheck source=tools/_auth_helper.sh
. "$(dirname "$0")/_auth_helper.sh"
bb_auth_bind_target "$TARGET"
trap cleanup_auth_tmpfiles EXIT

# Prefer Go-installed/security-tool bins over similarly named package-manager CLIs.
export PATH="$HOME/.local/bin:$HOME/go/bin:$SHARED_TOOLS_DIR/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

run_domain_list_batch() {
    local list_file="$1"
    local mode_flag="${2:-}"
    local batch_name batch_key batch_dir targets_file manifest completed_file failed_file summary_file
    local high_value_file ranking_file ai_handoff_file target_links_file
    local pending_file run_targets_file processed_file batch_size_raw batch_size batch_reset chunk_mode
    batch_name="$(basename "$list_file")"
    batch_key="$(python3 - "$list_file" "$BASE_DIR" <<'PY'
import sys

target = sys.argv[1]
base_dir = sys.argv[2]
sys.path.insert(0, base_dir)
sys.path.insert(0, f"{base_dir}/tools")

from tools.target_paths import migrate_legacy_list_storage, target_storage_key

migrate_legacy_list_storage(base_dir, target)
print(target_storage_key(target))
PY
)"
    [ -z "$batch_key" ] && batch_key="scope-list"
    batch_dir="$BASE_DIR/recon/$batch_key"
    targets_file="$batch_dir/batch_targets.txt"
    manifest="$batch_dir/batch_manifest.jsonl"
    completed_file="$batch_dir/completed_targets.txt"
    failed_file="$batch_dir/failed_targets.txt"
    summary_file="$batch_dir/batch_summary.md"
    high_value_file="$batch_dir/high_value_targets.json"
    ranking_file="$batch_dir/surface_ranking.txt"
    ai_handoff_file="$batch_dir/ai_handoff.md"
    target_links_file="$batch_dir/grouped_targets.tsv"
    pending_file="$batch_dir/pending_targets.txt"
    run_targets_file="$batch_dir/current_batch_targets.txt"
    processed_file="$batch_dir/.processed_targets.tmp"

    batch_size_raw="${BBHUNT_BATCH_SIZE:-0}"
    batch_size=0
    if [[ "$batch_size_raw" =~ ^[0-9]+$ ]]; then
        batch_size="$batch_size_raw"
    else
        log_warn "Invalid BBHUNT_BATCH_SIZE=$batch_size_raw — falling back to full batch"
    fi
    chunk_mode=0
    [ "$batch_size" -gt 0 ] && chunk_mode=1

    batch_reset=0
    case "${BBHUNT_BATCH_RESET:-0}" in
        1|true|TRUE|yes|YES) batch_reset=1 ;;
    esac

    mkdir -p "$batch_dir"
    : > "$targets_file"
    if [ "$chunk_mode" -eq 0 ] || [ "$batch_reset" -eq 1 ]; then
        : > "$manifest"
        : > "$completed_file"
        : > "$failed_file"
        : > "$target_links_file"
    else
        touch "$manifest" "$completed_file" "$failed_file" "$target_links_file"
    fi

    # targets.txt is treated as a primary-domain batch list. Keep the cleanup
    # minimal: skip empty/comment lines, drop CR, and strip wildcard prefixes.
    python3 - "$list_file" "$targets_file" <<'PY'
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
seen = set()
out = []
for raw in src.read_text(encoding="utf-8", errors="replace").splitlines():
    value = raw.strip().strip("\ufeff").strip()
    if not value or value.startswith("#"):
        continue
    value = value.rstrip("/").lower()
    if value.startswith("*."):
        value = value[2:]
    if not value or value in seen:
        continue
    seen.add(value)
    out.append(value)
dst.write_text(("\n".join(out) + "\n") if out else "", encoding="utf-8")
PY

    local total
    total=$(wc -l < "$targets_file" 2>/dev/null | tr -d ' ' || echo 0)
    if [ "$total" -eq 0 ]; then
        log_err "Domain list $list_file has no usable targets"
        return 1
    fi

    if [ "$chunk_mode" -eq 1 ]; then
        cat "$completed_file" "$failed_file" 2>/dev/null \
            | awk 'NF && !seen[$0]++' > "$processed_file" || true
        grep -Fvx -f "$processed_file" "$targets_file" > "$pending_file" 2>/dev/null || true
        head -n "$batch_size" "$pending_file" > "$run_targets_file" 2>/dev/null || true
    else
        cp "$targets_file" "$pending_file"
        cp "$targets_file" "$run_targets_file"
    fi

    local selected_total remaining_before
    selected_total=$(wc -l < "$run_targets_file" 2>/dev/null | tr -d ' ' || echo 0)
    remaining_before=$(wc -l < "$pending_file" 2>/dev/null | tr -d ' ' || echo 0)

    echo "============================================="
    echo "  Recon Batch — $batch_key"
    echo "  Source: $list_file"
    echo "  Targets: $total"
    if [ "$chunk_mode" -eq 1 ]; then
        echo "  Batch size: $batch_size"
        echo "  Pending before run: $remaining_before"
        echo "  Selected this run: $selected_total"
        [ "$batch_reset" -eq 1 ] && echo "  Reset: enabled"
    fi
    echo "  Output index: $batch_dir/"
    echo "  Mode: ${mode_flag:---full}"
    echo "  Time: $(date)"
    echo "============================================="
    echo ""

    local idx=0 ok_count=0 fail_count=0
    while IFS= read -r batch_target; do
        [ -n "$batch_target" ] || continue
        idx=$((idx + 1))
        local start_iso end_iso start_epoch duration status exit_code recon_key recon_path grouped_link
        start_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        start_epoch="$(date +%s)"
        recon_key="${batch_target//\//_}"
        recon_path="$BASE_DIR/recon/$recon_key"

        log_info "Batch target $idx/$selected_total (total: $total): $batch_target"
        # Do not let child recon processes inherit the batch stdin stream;
        # otherwise tools that read from stdin can consume the remaining
        # while-read targets and make large batches stop after the first item.
        if bash "$SCRIPT_PATH" "$batch_target" "$mode_flag" </dev/null; then
            status="ok"
            exit_code=0
            ok_count=$((ok_count + 1))
            printf '%s\n' "$batch_target" >> "$completed_file"
        else
            exit_code=$?
            status="failed"
            fail_count=$((fail_count + 1))
            printf '%s\n' "$batch_target" >> "$failed_file"
            log_warn "Batch target failed: $batch_target (exit=$exit_code)"
        fi
        end_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        duration=$(( $(date +%s) - start_epoch ))

        # Keep the canonical per-target artifact path as recon/<domain>/ so
        # /surface, /hunt, /pickup, and runtime_state continue to work. Also
        # create a batch-local browsing link recon/<batch>/<domain> -> ../<domain>
        # so operators running many list files can see which batch produced
        # each domain without changing downstream target semantics.
        if [ "$status" = "ok" ] && [ -d "$recon_path" ]; then
            grouped_link="$batch_dir/$recon_key"
            [ -L "$grouped_link" ] && rm -f "$grouped_link" 2>/dev/null || true
            if [ ! -e "$grouped_link" ]; then
                ln -s "../$recon_key" "$grouped_link" 2>/dev/null || \
                    printf '%s\n' "$recon_path" > "$batch_dir/${recon_key}.path"
            fi
            printf '%s\t%s\t%s\n' "$batch_target" "recon/$batch_key/$recon_key" "recon/$recon_key" >> "$target_links_file"
        fi

        python3 - "$manifest" "$batch_target" "$status" "$exit_code" "$duration" "$start_iso" "$end_iso" "$recon_path" <<'PY'
import json
import sys

manifest, target, status, exit_code, duration, start_iso, end_iso, recon_path = sys.argv[1:]
record = {
    "target": target,
    "status": status,
    "exit_code": int(exit_code),
    "duration_seconds": int(duration),
    "started_at": start_iso,
    "ended_at": end_iso,
    "recon_dir": recon_path,
}
with open(manifest, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
PY
    done < "$run_targets_file"

    local completed_total failed_total processed_this_run remaining_total batch_size_label
    completed_total=$(wc -l < "$completed_file" 2>/dev/null | tr -d ' ' || echo 0)
    failed_total=$(wc -l < "$failed_file" 2>/dev/null | tr -d ' ' || echo 0)
    processed_this_run=$((ok_count + fail_count))
    remaining_total=$((total - completed_total - failed_total))
    [ "$remaining_total" -lt 0 ] && remaining_total=0
    batch_size_label="full"
    [ "$chunk_mode" -eq 1 ] && batch_size_label="$batch_size"

    python3 - "$BASE_DIR" "$batch_key" "$completed_file" "$high_value_file" "$ranking_file" "$ai_handoff_file" <<'PY'
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

base_dir = Path(sys.argv[1])
batch_key = sys.argv[2]
completed_file = Path(sys.argv[3])
high_value_file = Path(sys.argv[4])
ranking_file = Path(sys.argv[5])
ai_handoff_file = Path(sys.argv[6])

def storage_key(target: str) -> str:
    return target.replace("/", "_")

def read_lines(path: Path, limit: int | None = None) -> list[str]:
    if not path.is_file():
        return []
    out = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = raw.strip()
            if not value:
                continue
            out.append(value)
            if limit and len(out) >= limit:
                break
    return out

def line_count(path: Path) -> int:
    return len(read_lines(path))

def first_existing_count(recon_dir: Path, *rel_paths: str) -> int:
    for rel in rel_paths:
        count = line_count(recon_dir / rel)
        if count:
            return count
    return 0

def host_count(lines: list[str], keywords: tuple[str, ...]) -> int:
    hosts = set()
    for item in lines:
        candidate = item.split()[0]
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        host = (parsed.netloc or parsed.path).split("/")[0].lower()
        if any(token in host for token in keywords):
            hosts.add(host)
    return len(hosts)

def add_score(score_parts: list[dict], points: int, reason: str) -> int:
    points = int(points or 0)
    if points > 0:
        score_parts.append({"points": points, "reason": reason})
    return points

targets = []
seen = set()
for target in read_lines(completed_file):
    if target in seen:
        continue
    seen.add(target)
    targets.append(target)

results = []
for target in targets:
    recon_dir = base_dir / "recon" / storage_key(target)
    live_urls = read_lines(recon_dir / "live" / "urls.txt")
    subdomains_lines = read_lines(recon_dir / "subdomains" / "all.txt")
    host_lines = live_urls + subdomains_lines
    details = {
        "subdomains": line_count(recon_dir / "subdomains" / "all.txt"),
        "live_hosts": first_existing_count(recon_dir, "live/urls.txt", "live/httpx_full.txt"),
        "urls": first_existing_count(recon_dir, "urls/all.txt", "live/urls.txt"),
        "api_endpoints": line_count(recon_dir / "urls" / "api_endpoints.txt"),
        "param_urls": line_count(recon_dir / "urls" / "with_params.txt"),
        "js_endpoints": line_count(recon_dir / "js" / "endpoints.txt"),
        "api_doc_candidates": line_count(recon_dir / "exposure" / "api_doc_candidates.txt"),
        "api_leak_candidates": line_count(recon_dir / "exposure" / "api_leak_candidates.txt"),
        "verified_secrets": line_count(recon_dir / "exposure" / "api_leak_trufflehog_verified.jsonl"),
        "config_exposures": line_count(recon_dir / "exposure" / "config_files.txt"),
        "identity_emails": line_count(recon_dir / "exposure" / "identity_intel" / "emails.txt"),
        "leaksearch_hits": line_count(recon_dir / "exposure" / "identity_intel" / "leaksearch.txt"),
        "cloud_enum_hits": line_count(recon_dir / "exposure" / "cloud" / "cloud_enum.txt"),
        "status_401": line_count(recon_dir / "live" / "status_401.txt"),
        "status_403": line_count(recon_dir / "live" / "status_403.txt"),
        "open_ports": first_existing_count(recon_dir, "ports/open_ports_all.txt", "ports/open_ports.txt", "ports/open_ports_naabu.txt"),
    }
    details["api_hosts"] = host_count(host_lines, ("api", "graphql", "gateway", "gw"))
    details["admin_hosts"] = host_count(
        host_lines,
        ("admin", "internal", "portal", "sso", "idp", "auth", "dev", "stage", "staging"),
    )

    score_parts = []
    score = 0
    score += add_score(score_parts, min(details["live_hosts"] * 3, 45), f"{details['live_hosts']} live host(s)")
    score += add_score(score_parts, min(details["api_endpoints"] // 3, 35), f"{details['api_endpoints']} API endpoint(s)")
    score += add_score(score_parts, min(details["param_urls"] // 5, 25), f"{details['param_urls']} parameterized URL(s)")
    score += add_score(score_parts, min(details["js_endpoints"] // 4, 25), f"{details['js_endpoints']} JS endpoint(s)")
    score += add_score(score_parts, min(details["api_doc_candidates"] * 8, 40), f"{details['api_doc_candidates']} API doc candidate(s)")
    score += add_score(score_parts, min(details["api_leak_candidates"] * 10, 60), f"{details['api_leak_candidates']} API leak candidate(s)")
    score += add_score(score_parts, min(details["verified_secrets"] * 20, 60), f"{details['verified_secrets']} verified secret candidate(s)")
    score += add_score(score_parts, min(details["config_exposures"] * 6, 30), f"{details['config_exposures']} config exposure candidate(s)")
    score += add_score(score_parts, min(details["cloud_enum_hits"] // 2, 25), f"{details['cloud_enum_hits']} cloud_enum line(s)")
    score += add_score(score_parts, min(details["leaksearch_hits"] // 2, 20), f"{details['leaksearch_hits']} LeakSearch line(s)")
    score += add_score(score_parts, min(details["api_hosts"] * 5, 25), f"{details['api_hosts']} API-like host(s)")
    score += add_score(score_parts, min(details["admin_hosts"] * 5, 25), f"{details['admin_hosts']} admin/auth/internal-like host(s)")
    score += add_score(score_parts, min((details["status_401"] + details["status_403"]) * 2, 20), f"{details['status_401'] + details['status_403']} auth/403 surface(s)")
    score += add_score(score_parts, min(details["open_ports"] * 2, 20), f"{details['open_ports']} open port line(s)")

    score_parts.sort(key=lambda item: item["points"], reverse=True)
    results.append({
        "target": target,
        "score": score,
        "details": details,
        "top_signals": score_parts[:6],
        "recon_dir": f"recon/{storage_key(target)}",
        "next": f"/surface {target}",
    })

results.sort(key=lambda item: (-item["score"], item["target"]))

high_value_file.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

with ranking_file.open("w", encoding="utf-8") as handle:
    handle.write("ATTACK SURFACE RANKING - TOP 50\n")
    handle.write(f"Batch: {batch_key}\n")
    handle.write("=" * 80 + "\n\n")
    if not results:
        handle.write("No completed targets with recon artifacts yet.\n")
    for idx, item in enumerate(results[:50], 1):
        d = item["details"]
        signals = "; ".join(part["reason"] for part in item["top_signals"]) or "no strong surface counters"
        handle.write(f"#{idx:2d} | {item['target']:30s} | Score: {item['score']:5d}\n")
        handle.write(
            "     "
            f"Subdomains: {d['subdomains']:3d} | Live: {d['live_hosts']:3d} | "
            f"URLs: {d['urls']:4d} | API: {d['api_endpoints']:4d} | "
            f"Params: {d['param_urls']:4d} | JS: {d['js_endpoints']:4d}\n"
        )
        handle.write(
            "     "
            f"API docs: {d['api_doc_candidates']:3d} | API leaks: {d['api_leak_candidates']:3d} | "
            f"Secrets: {d['verified_secrets']:3d} | Configs: {d['config_exposures']:3d} | "
            f"Cloud: {d['cloud_enum_hits']:3d} | Identity: {d['identity_emails'] + d['leaksearch_hits']:3d}\n"
        )
        handle.write(f"     Signals: {signals}\n")
        handle.write(f"     Next: /surface {item['target']}  ->  /hunt {item['target']}\n\n")
    handle.write("=" * 80 + "\n")
    handle.write(f"Total completed targets ranked: {len(results)}\n")

with ai_handoff_file.open("w", encoding="utf-8") as handle:
    handle.write(f"# AI Handoff — Batch Attack Surface ({batch_key})\n\n")
    handle.write("Read this before choosing the next target from a list recon. ")
    handle.write("The batch directory is an index only; continue on individual completed domains.\n\n")
    handle.write("## Top Targets\n\n")
    handle.write("| Rank | Target | Score | Why it matters | Next |\n")
    handle.write("|---:|---|---:|---|---|\n")
    for idx, item in enumerate(results[:10], 1):
        why = "; ".join(part["reason"] for part in item["top_signals"][:3]) or "low-signal completed target"
        handle.write(f"| {idx} | `{item['target']}` | {item['score']} | {why} | `/surface {item['target']}` |\n")
    if not results:
        handle.write("| - | - | - | no completed targets yet | rerun recon batch |\n")
    handle.write("\n## Files For Claude\n\n")
    handle.write(f"- Ranking: `recon/{batch_key}/surface_ranking.txt`\n")
    handle.write(f"- Structured targets: `recon/{batch_key}/high_value_targets.json`\n")
    handle.write(f"- Manifest: `recon/{batch_key}/batch_manifest.jsonl`\n")
    handle.write(f"- Grouped target links: `recon/{batch_key}/<domain>` -> `recon/<domain>`\n\n")
    handle.write("## Recommended Flow\n\n")
    handle.write("1. Pick a top target with concrete surface signals, not the batch index directory.\n")
    handle.write("2. Run `/surface <domain>` to rank that domain's cached URLs/JS/exposure.\n")
    handle.write("3. Run `/hunt <domain>` or `/autopilot <domain> --normal` only after reading `/surface`.\n")
PY

    {
        echo "# Recon Batch Summary — $batch_key"
        echo ""
        echo "- Source: \`$list_file\`"
        echo "- Mode: ${mode_flag:---full}"
        echo "- Total targets: $total"
        echo "- Batch size: $batch_size_label"
        echo "- Processed this run: $processed_this_run"
        echo "- Completed this run: $ok_count"
        echo "- Failed this run: $fail_count"
        echo "- Completed: $completed_total"
        echo "- Failed: $failed_total"
        echo "- Remaining: $remaining_total"
        echo "- Manifest: \`recon/$batch_key/batch_manifest.jsonl\`"
        echo "- AI handoff: \`recon/$batch_key/ai_handoff.md\`"
        echo "- Surface ranking: \`recon/$batch_key/surface_ranking.txt\`"
        echo "- High-value targets: \`recon/$batch_key/high_value_targets.json\`"
        echo "- Grouped target links: \`recon/$batch_key/<domain>\` -> \`recon/<domain>\`"
        echo "- Grouped target TSV: \`recon/$batch_key/grouped_targets.tsv\`"
        if [ "$chunk_mode" -eq 1 ] && [ "$remaining_total" -gt 0 ]; then
            echo "- Continue: \`BBHUNT_BATCH_SIZE=$batch_size python3 tools/hunt.py --target $list_file --recon-only\`"
        fi
        echo ""
        echo "## AI Handoff — Top Attack Surface"
        echo ""
        if [ -s "$ai_handoff_file" ]; then
            sed -n '1,80p' "$ai_handoff_file"
        else
            echo "- No AI handoff generated yet."
        fi
        echo ""
        echo "## Completed"
        if [ -s "$completed_file" ]; then
            sed 's/^/- /' "$completed_file"
        else
            echo "- none"
        fi
        echo ""
        echo "## Failed"
        if [ -s "$failed_file" ]; then
            sed 's/^/- /' "$failed_file"
        else
            echo "- none"
        fi
    } > "$summary_file"

    emit_claude_hint \
        phase                batch_recon \
        target_count         "$total" \
        batch_size           "$batch_size_label" \
        processed_this_run   "$processed_this_run" \
        completed            "$completed_total" \
        failed               "$failed_total" \
        remaining            "$remaining_total" \
        manifest             "recon/$batch_key/batch_manifest.jsonl" \
        ai_handoff           "recon/$batch_key/ai_handoff.md" \
        surface_ranking      "recon/$batch_key/surface_ranking.txt" \
        grouped_links        "recon/$batch_key/<domain> -> recon/<domain>" \
        note                 "targets.txt is treated as a primary-domain batch; each target has its own recon/<domain>/"
    emit_claude_hint_actions \
        "$([ "$chunk_mode" -eq 1 ] && [ "$remaining_total" -gt 0 ] && echo "rerun with BBHUNT_BATCH_SIZE=${batch_size} to process the next batch" || echo "read recon/${batch_key}/batch_summary.md and recon/${batch_key}/surface_ranking.txt, then choose the highest-signal domain for /surface or /hunt")" \
        "review recon/<domain>/exposure/api_leak_candidates.txt and identity/cloud artifacts per completed domain" \
        "rerun failed targets individually after checking recon/${batch_key}/failed_targets.txt"

    echo ""
    echo "============================================="
    echo "  Recon Batch Summary — $batch_key"
    echo "  Processed this run: $processed_this_run"
    echo "  Completed: $completed_total / $total"
    echo "  Failed:    $failed_total"
    echo "  Remaining: $remaining_total"
    echo "  Manifest:  $manifest"
    echo "============================================="

    [ "$ok_count" -gt 0 ] || { [ "$chunk_mode" -eq 1 ] && [ "$remaining_total" -eq 0 ]; }
}

if [ -f "$TARGET" ] && [ -r "$TARGET" ]; then
    run_domain_list_batch "$TARGET" "$RECON_MODE_FLAG"
    exit $?
fi

TARGET_KIND="domain"
if [[ "$TARGET" == *"://"* ]]; then
    TARGET_KIND="url"
elif python3 - "$TARGET" <<'PY' >/dev/null 2>&1
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PY
then
    TARGET_KIND="ip"
elif python3 - "$TARGET" <<'PY' >/dev/null 2>&1
import ipaddress
import re
import sys
value = sys.argv[1]
# host:port form — local lab targets like 127.0.0.1:3000 or app.test:8080.
# Mirrors tools/target_paths.py classification: numeric port 1..65535, host is
# either an ip_address or a DNS-safe token.
if value.count(":") != 1:
    raise SystemExit(1)
host, _, port = value.rpartition(":")
if not (host and port.isdigit() and 1 <= int(port) <= 65535):
    raise SystemExit(1)
try:
    ipaddress.ip_address(host)
except ValueError:
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
        raise SystemExit(1)
PY
then
    TARGET_KIND="ip"
elif python3 - "$TARGET" <<'PY' >/dev/null 2>&1
import ipaddress
import sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY
then
    TARGET_KIND="cidr"
fi

TARGET_HAS_EXPLICIT_PORT="false"
TARGET_HTTP_SEED=""
TARGET_EXPLICIT_PORT=""
if [[ "$TARGET" == *"://"* ]]; then
    TARGET_HTTP_SEED="$TARGET"
    TARGET_EXPLICIT_PORT="$(python3 - "$TARGET" <<'PY' 2>/dev/null || true
from urllib.parse import urlparse
import sys

parsed = urlparse(sys.argv[1])
try:
    port = parsed.port
except ValueError:
    port = None
if parsed.hostname and port is not None:
    print(port)
PY
)"
    if [ -n "$TARGET_EXPLICIT_PORT" ]; then
        TARGET_HAS_EXPLICIT_PORT="true"
    fi
elif [[ "$(printf '%s' "$TARGET" | awk -F: '{print NF-1}')" = "1" ]]; then
    TARGET_HOST_PART="${TARGET%:*}"
    TARGET_PORT_PART="${TARGET##*:}"
    if [[ -n "$TARGET_HOST_PART" ]] && [[ "$TARGET_PORT_PART" =~ ^[0-9]+$ ]] && [ "$TARGET_PORT_PART" -ge 1 ] && [ "$TARGET_PORT_PART" -le 65535 ]; then
        TARGET_HAS_EXPLICIT_PORT="true"
        TARGET_HTTP_SEED="http://$TARGET"
        TARGET_EXPLICIT_PORT="$TARGET_PORT_PART"
    fi
fi

RECON_TARGET_KEY="$(python3 - "$TARGET" "$BASE_DIR" <<'PY'
import sys

target = sys.argv[1]
base_dir = sys.argv[2]
sys.path.insert(0, base_dir)
sys.path.insert(0, f"{base_dir}/tools")

from tools.target_paths import target_storage_key

print(target_storage_key(target))
PY
)"
RECON_DIR="$BASE_DIR/recon/$RECON_TARGET_KEY"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
THREADS="${BB_THREADS:-20}"
RATE_LIMIT="${BB_RATE_LIMIT:-50}"  # requests per second
DISCOVERY_HOSTS_FILE="$RECON_DIR/live/discovery_hosts.txt"
HTTPX_INPUT_FILE="$RECON_DIR/subdomains/all.txt"
HTTPX_BIN="$(resolve_pd_httpx || true)"
if [ -z "$HTTPX_BIN" ]; then
    log_warn "ProjectDiscovery httpx not found. Live-host probing will be skipped."
    log_warn "Install hint: GOBIN=\"\$HOME/go/bin\" go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
fi

mkdir -p "$RECON_DIR"/{subdomains,live,ports,urls,js,dirs,params,exposure,logs}
RECON_MANIFEST="$RECON_DIR/recon_manifest.jsonl"
: > "$RECON_MANIFEST"
: > "$DISCOVERY_HOSTS_FILE"

# Pre-seed result files that summary blocks read via `< file`. Without these,
# ip/cidr branches that skip subdomain/WAF/origin work cause bash redirection
# errors and a non-zero exit code, which makes hunt.py mis-report
# "Recon: Skipped" even on successful URL collection.
touch "$RECON_DIR/subdomains/all.txt" \
      "$RECON_DIR/live/wafw00f.txt" \
      "$RECON_DIR/live/wafw00f_hits.txt" \
      "$RECON_DIR/live/origin_candidates.txt" \
      "$RECON_DIR/live/unwaf_bypass_ips.txt" \
      "$RECON_DIR/ports/open_ports.txt" \
      "$RECON_DIR/ports/open_ports_naabu.txt" \
      "$RECON_DIR/ports/open_ports_all.txt" \
      "$RECON_DIR/js/endpoints.txt" \
      "$RECON_DIR/js/potential_secrets.txt" \
      "$RECON_DIR/js/linkfinder_endpoints.txt" \
      "$RECON_DIR/js/deep_candidates.txt" \
      "$RECON_DIR/params/unique_params.txt" \
      "$RECON_DIR/params/interesting_params.txt" \
      "$RECON_DIR/exposure/config_files.txt" \
      "$RECON_DIR/exposure/api_doc_candidates.txt" \
      "$RECON_DIR/exposure/api_leak_candidates.txt" \
      "$RECON_DIR/exposure/api_leak_trufflehog_verified.jsonl" \
      "$RECON_DIR/exposure/cloud_storage_candidates.txt" \
      "$RECON_DIR/exposure/s3_bucket_candidates.txt" \
      "$RECON_DIR/exposure/external_service_hosts.txt" \
      "$RECON_DIR/exposure/host_pivot_candidates.jsonl" \
      "$RECON_DIR/exposure/ai_asset_candidates.jsonl"

# Clear regenerated summary files so reruns cannot inherit stale counters.
: > "$RECON_DIR/live/httpx_full.txt"
: > "$RECON_DIR/live/urls.txt"
: > "$RECON_DIR/live/seed_urls.txt"
: > "$RECON_DIR/live/wafw00f_hits.txt"
: > "$RECON_DIR/live/unwaf_bypass_ips.txt"
: > "$RECON_DIR/live/origin_candidates.txt"
: > "$RECON_DIR/live/status_200.txt"
: > "$RECON_DIR/live/status_3xx.txt"
: > "$RECON_DIR/live/status_401.txt"
: > "$RECON_DIR/live/status_403.txt"
: > "$RECON_DIR/ports/open_ports.txt"
: > "$RECON_DIR/ports/open_ports_naabu.txt"
: > "$RECON_DIR/ports/open_ports_all.txt"
: > "$RECON_DIR/urls/katana_targets.txt"
: > "$RECON_DIR/urls/all.txt"
: > "$RECON_DIR/urls/all_filtered.txt"
: > "$RECON_DIR/urls/with_params.txt"
: > "$RECON_DIR/urls/with_params_filtered.txt"
: > "$RECON_DIR/urls/with_params_analysis.txt"
: > "$RECON_DIR/urls/js_files.txt"
: > "$RECON_DIR/urls/js_files_filtered.txt"
: > "$RECON_DIR/urls/js_files_analysis.txt"
: > "$RECON_DIR/urls/api_endpoints.txt"
: > "$RECON_DIR/urls/api_endpoints_filtered.txt"
: > "$RECON_DIR/urls/sensitive_paths.txt"
: > "$RECON_DIR/urls/sensitive_paths_filtered.txt"
: > "$RECON_DIR/js/endpoints.txt"
: > "$RECON_DIR/js/potential_secrets.txt"
: > "$RECON_DIR/js/linkfinder_endpoints.txt"

ensure_explicit_port_seed_live() {
    if [ ! -s "$RECON_DIR/live/urls.txt" ] && [ "$TARGET_HAS_EXPLICIT_PORT" = "true" ] && [ -n "$TARGET_HTTP_SEED" ]; then
        local seed_http_code
        bb_auth_args_for_url "$TARGET_HTTP_SEED"
        seed_http_code="$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' "${BB_URL_AUTH_ARGS[@]}" --max-time 5 "$TARGET_HTTP_SEED" 2>/dev/null || true)"
        if [[ "$seed_http_code" =~ ^(2|3)[0-9][0-9]$ ]] || [ "$seed_http_code" = "401" ] || [ "$seed_http_code" = "403" ]; then
            printf '%s\n' "$TARGET_HTTP_SEED" > "$RECON_DIR/live/urls.txt"
            printf '%s\n' "$TARGET_HTTP_SEED" > "$RECON_DIR/live/seed_urls.txt"
            printf '%s [%s] [seed]\n' "$TARGET_HTTP_SEED" "$seed_http_code" > "$RECON_DIR/live/httpx_full.txt"
        fi
    fi
}

collect_subfinder() {
    local output="$1"
    command -v subfinder >/dev/null 2>&1 || return 3
    run_with_timeout 180 subfinder -d "$TARGET" -silent -all -t "${SUBFINDER_THREADS:-50}" \
        -o "$output" \
        2> "$RECON_DIR/logs/subfinder.log"
}

collect_assetfinder() {
    local output="$1"
    command -v assetfinder >/dev/null 2>&1 || return 3
    local raw="$RECON_DIR/logs/assetfinder.raw"
    run_with_timeout 120 assetfinder --subs-only "$TARGET" \
        > "$raw" 2> "$RECON_DIR/logs/assetfinder.log"
    local rc=$?
    tr '[:upper:]' '[:lower:]' < "$raw" \
        | sed 's/^\*\.//' \
        | awk 'NF' \
        | sort -u > "$output" || true
    rm -f "$raw"
    return "$rc"
}

collect_amass() {
    local output="$1"
    [ "$RECON_PROFILE" != "quick" ] || return 4
    command -v amass >/dev/null 2>&1 || return 3
    run_with_timeout 300 amass enum -passive -d "$TARGET" \
        -o "$output" \
        2> "$RECON_DIR/logs/amass.log"
}

collect_crtsh() {
    local output="$1"
    curl -sS --max-time 20 "https://crt.sh/?q=%25.$TARGET&output=json" \
        2> "$RECON_DIR/logs/crtsh.log" \
        | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\\n'):
            name = name.strip().lower()
            if name and '*' not in name and name.endswith('.$TARGET'):
                names.add(name)
            elif name and '*' not in name and '.' in name:
                names.add(name)
    for name in sorted(names):
        print(name)
except (TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
" > "$output"
}

collect_wayback_subdomains() {
    local output="$1"
    curl -sS --max-time 20 \
        "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" \
        2> "$RECON_DIR/logs/wayback_subdomains.log" \
        | sed -nE "s|.*://([a-zA-Z0-9._-]+\.$TARGET).*|\1|p" \
        | sort -u > "$output"
}

collect_gau_urls() {
    local output="$1"
    [ "$TARGET_KIND" = "domain" ] || return 4
    command -v gau >/dev/null 2>&1 || return 3
    printf '%s\n' "$TARGET" \
        | run_with_timeout 180 gau --threads "${GAU_THREADS:-20}" \
            --o "$output" \
            2> "$RECON_DIR/logs/gau.log"
}

collect_wayback_urls() {
    local output="$1"
    [ "$TARGET_KIND" = "domain" ] || return 4
    command -v gau >/dev/null 2>&1 && return 4
    curl -sS --max-time 60 \
        "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=5000" \
        > "$output" \
        2> "$RECON_DIR/logs/wayback_urls.log"
}

collect_waymore_urls() {
    local output="$1"
    [ "$TARGET_KIND" = "domain" ] || return 4
    command -v waymore >/dev/null 2>&1 || return 3
    run_with_timeout 240 waymore \
        -i "$TARGET" \
        -mode U \
        -oU "$output" \
        -ow \
        -lcc 1 \
        2> "$RECON_DIR/logs/waymore.log"
}

collect_katana_urls() {
    local output="$1"
    command -v katana >/dev/null 2>&1 || return 3
    [ -s "$RECON_DIR/live/urls.txt" ] || return 4
    head -50 "$RECON_DIR/live/urls.txt" > "$RECON_DIR/urls/katana_targets.txt"
    local perf_args=()
    [ -n "${KATANA_CONCURRENCY:-}" ] && perf_args+=(-c "$KATANA_CONCURRENCY")
    [ -n "${KATANA_PARALLELISM:-}" ] && perf_args+=(-p "$KATANA_PARALLELISM")
    run_with_timeout 300 katana \
        -list "$RECON_DIR/urls/katana_targets.txt" \
        -d 3 -jc -kf all -silent -dr -fs rdn -do \
        "${perf_args[@]}" \
        "${BB_AUTH_ARGS[@]}" \
        -o "$output" \
        2> "$RECON_DIR/logs/katana.log"
}

echo "============================================="
echo "  Recon Engine — $TARGET"
echo "  Output: $RECON_DIR/"
echo "  Target kind: $TARGET_KIND"
echo "  Mode: $RECON_PROFILE"
echo "  Time: $(date)"
bb_auth_active && bb_auth_banner
echo "============================================="
echo ""
record_recon_phase \
    target_setup \
    ok \
    "recon/${RECON_TARGET_KEY}/" \
    1 \
    "target_kind=${TARGET_KIND}; manifest records phase execution only, not surface value"

# ============================================================
# Phase 1: Subdomain Enumeration
# ============================================================
log_info "Phase 1: Subdomain Enumeration"

if [ "$TARGET_KIND" = "domain" ]; then
    start_collector subfinder "$RECON_DIR/subdomains/subfinder.txt" \
        "recon/${RECON_TARGET_KEY}/subdomains/subfinder.txt" collect_subfinder
    start_collector assetfinder "$RECON_DIR/subdomains/assetfinder.txt" \
        "recon/${RECON_TARGET_KEY}/subdomains/assetfinder.txt" collect_assetfinder
    start_collector amass "$RECON_DIR/subdomains/amass.txt" \
        "recon/${RECON_TARGET_KEY}/subdomains/amass.txt" collect_amass
    start_collector crtsh "$RECON_DIR/subdomains/crtsh.txt" \
        "recon/${RECON_TARGET_KEY}/subdomains/crtsh.txt" collect_crtsh
    start_collector wayback_subdomains "$RECON_DIR/subdomains/wayback_subs.txt" \
        "recon/${RECON_TARGET_KEY}/subdomains/wayback_subs.txt" collect_wayback_subdomains
    wait_collector_group

    cat \
        "$RECON_DIR/subdomains/subfinder.txt" \
        "$RECON_DIR/subdomains/assetfinder.txt" \
        "$RECON_DIR/subdomains/amass.txt" \
        "$RECON_DIR/subdomains/crtsh.txt" \
        "$RECON_DIR/subdomains/wayback_subs.txt" \
        2>/dev/null | awk 'NF' | sort -u > "$RECON_DIR/subdomains/all.txt" || true
    TOTAL_SUBS=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
    log_ok "Total unique subdomains: $TOTAL_SUBS"
elif [ "$TARGET_KIND" = "url" ]; then
    printf '%s\n' "$TARGET" > "$DISCOVERY_HOSTS_FILE"
    HTTPX_INPUT_FILE="$DISCOVERY_HOSTS_FILE"
    log_ok "URL target prepared for probing: 1 URL"
elif [ "$TARGET_KIND" = "ip" ]; then
    printf '%s\n' "$TARGET" > "$DISCOVERY_HOSTS_FILE"
    HTTPX_INPUT_FILE="$DISCOVERY_HOSTS_FILE"
    log_ok "IP target prepared for probing: 1 host"
else
    CIDR_LIMIT=4096
    CIDR_COUNT=$(python3 - "$TARGET" "$DISCOVERY_HOSTS_FILE" "$CIDR_LIMIT" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
output_path = sys.argv[2]
limit = int(sys.argv[3])
count = 0
with open(output_path, "w", encoding="utf-8") as handle:
    for host in network.hosts():
        if count >= limit:
            break
        handle.write(f"{host}\n")
        count += 1
print(count)
PY
)
    HTTPX_INPUT_FILE="$DISCOVERY_HOSTS_FILE"
    log_ok "CIDR candidates prepared: $CIDR_COUNT hosts"
fi

SUBS_TOTAL=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null | tr -d ' ' || echo 0)
SUBDOMAIN_STATUS="ok"
[ "$TARGET_KIND" != "domain" ] && SUBDOMAIN_STATUS="skipped"
record_recon_phase \
    subdomain_enum \
    "$SUBDOMAIN_STATUS" \
    "recon/${RECON_TARGET_KEY}/subdomains/all.txt" \
    "$SUBS_TOTAL" \
    "domain targets run passive enum; URL/IP/CIDR targets seed discovery hosts directly"
emit_claude_hint \
    phase                subdomain_enum \
    target_kind          "$TARGET_KIND" \
    subdomain_total      "$SUBS_TOTAL" \
    sources              "subfinder,assetfinder${QUICK_MODE:+ (quick: amass skipped)}" \
    passive_only         "true"
emit_claude_hint_actions \
    "bash tools/takeover_scanner.sh recon/${RECON_TARGET_KEY}/subdomains/all.txt   # dangling CNAME quick wins" \
    "bash tools/cloud_recon.sh --keyword \"${TARGET%%.*}\"   # auto-derive bucket keyword from target" \
    "python3 tools/surface.py --target ${TARGET}   # rank P1 before deeper recon"

# ============================================================
# Phase 2: HTTP Probing
# ============================================================
echo ""
log_info "Phase 2: HTTP Probing"

if [ "$TARGET_KIND" = "domain" ]; then
    if command -v puredns &>/dev/null && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
        PUREDNS_OUTPUT_FILE="$RECON_DIR/live/puredns_resolved.txt"
        PUREDNS_RATE=$([ "$QUICK_MODE" = "--quick" ] && echo 1000 || echo 5000)
        log_step "Resolving hosts with puredns (massdns + wildcard filtering)..."
        # puredns resolve: massdns first pass with public resolvers, then wildcard
        # filtering, then verification with trusted resolvers. Default resolver
        # files at /root/.config/puredns/{resolvers,resolvers-trusted}.txt; quiet
        # mode keeps stdout clean for log capture.
        puredns resolve "$RECON_DIR/subdomains/all.txt" \
            --rate-limit "$PUREDNS_RATE" \
            --quiet \
            --write "$PUREDNS_OUTPUT_FILE" \
            >/dev/null 2>&1 || true
        # Normalize: strip trailing dot, lowercase, dedupe.
        if [ -s "$PUREDNS_OUTPUT_FILE" ]; then
            tr '[:upper:]' '[:lower:]' < "$PUREDNS_OUTPUT_FILE" \
                | sed 's/\.$//' | awk 'NF' | sort -u > "$DISCOVERY_HOSTS_FILE" || true
        fi
        PUREDNS_COUNT=$(wc -l < "$DISCOVERY_HOSTS_FILE" 2>/dev/null || echo 0)
        if [ "$PUREDNS_COUNT" -gt 0 ]; then
            HTTPX_INPUT_FILE="$DISCOVERY_HOSTS_FILE"
            log_done "puredns resolved: $PUREDNS_COUNT hosts (wildcards filtered)"
        else
            log_warn "puredns found no resolvable hosts — falling back to raw candidates"
        fi
    else
        log_warn "puredns not installed or no host candidates — using raw hosts for httpx"
        log_warn "Install: GOBIN=\"\$HOME/go/bin\" go install github.com/d3mondev/puredns/v2@latest"
    fi
fi

if [ ! -s "$HTTPX_INPUT_FILE" ]; then
    log_warn "Discovery host list is empty — skipping downstream probing"
elif [ -n "$HTTPX_BIN" ]; then
    log_step "Probing with ProjectDiscovery httpx (status, title, tech, content-length)..."
    "$HTTPX_BIN" -l "$HTTPX_INPUT_FILE" \
        -silent \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -follow-host-redirects \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        "${BB_AUTH_ARGS[@]}" \
        -o "$RECON_DIR/live/httpx_full.txt" 2>/dev/null || true

    # Extract just the URLs for other tools
    awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/urls.txt" 2>/dev/null || true

    # Local lab host:port targets can be reachable even when a particular
    # httpx binary/proxy combination emits no rows. Preserve one explicit
    # URL seed so `/autopilot 127.0.0.1:PORT` does not start from a false
    # "no live hosts" state.
    ensure_explicit_port_seed_live

    LIVE_COUNT=$(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)
    log_done "Live hosts: $LIVE_COUNT"

    # Separate by status code
    grep '\[200\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_200.txt" 2>/dev/null || true
    grep '\[30[12]\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || true
    grep '\[403\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_403.txt" 2>/dev/null || true
    grep '\[401\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_401.txt" 2>/dev/null || true

    log_done "200 OK: $(wc -l < "$RECON_DIR/live/status_200.txt" 2>/dev/null || echo 0)"
    log_done "3xx Redirect: $(wc -l < "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || echo 0)"
    log_done "403 Forbidden: $(wc -l < "$RECON_DIR/live/status_403.txt" 2>/dev/null || echo 0)"
    log_done "401 Auth Required: $(wc -l < "$RECON_DIR/live/status_401.txt" 2>/dev/null || echo 0)"
else
    log_warn "ProjectDiscovery httpx not installed — skipping"
fi

ensure_explicit_port_seed_live

LIVE_TOTAL=$(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null | tr -d ' ' || echo 0)
RESOLVED_TOTAL=$(wc -l < "$DISCOVERY_HOSTS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
HTTP_STATUS="ok"
if [ ! -s "$HTTPX_INPUT_FILE" ]; then
    HTTP_STATUS="skipped"
elif [ -z "$HTTPX_BIN" ]; then
    HTTP_STATUS="skipped"
elif [ "$LIVE_TOTAL" -eq 0 ]; then
    HTTP_STATUS="partial"
fi
record_recon_phase \
    http_probing \
    "$HTTP_STATUS" \
    "recon/${RECON_TARGET_KEY}/live/urls.txt" \
    "$LIVE_TOTAL" \
    "httpx live-host inventory; 0 live hosts is low signal, not target closure"
emit_claude_hint \
    phase                http_probing \
    resolved_hosts_total "$RESOLVED_TOTAL" \
    live_hosts_total     "$LIVE_TOTAL" \
    httpx_present        "$([ -n "$HTTPX_BIN" ] && echo true || echo false)" \
    puredns_present      "$(command -v puredns >/dev/null 2>&1 && echo true || echo false)"
emit_claude_hint_actions \
    "python3 tools/surface.py --target ${TARGET}   # build AI surface review pack before broad fuzz" \
    "spawn recon-ranker if live hosts > 50; otherwise read surface.py directly" \
    "if live_hosts_total stays 0 after retry, preserve recon as low-signal and revisit only if scope/browser/source evidence changes"

# ============================================================
# Phase 2.5: WAF Fingerprinting
# ============================================================
echo ""
log_info "Phase 2.5: WAF Fingerprinting"

if command -v wafw00f &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    WAFW00F_MAX_TARGETS=$([ "$QUICK_MODE" = "--quick" ] && echo 3 || echo 10)
    WAFW00F_HTTP_TIMEOUT=$([ "$QUICK_MODE" = "--quick" ] && echo 8 || echo 10)
    WAFW00F_TARGETS_FILE="$RECON_DIR/live/wafw00f_targets.txt"
    WAFW00F_JSON_FILE="$RECON_DIR/live/wafw00f.json"
    WAFW00F_HITS_FILE="$RECON_DIR/live/wafw00f_hits.txt"
    WAFW00F_HEADER_ARGS=()
    WAFW00F_REDIRECT_ARGS=()

    head -"$WAFW00F_MAX_TARGETS" "$RECON_DIR/live/urls.txt" > "$WAFW00F_TARGETS_FILE"
    if prepare_wafw00f_headers_file; then
        WAFW00F_HEADER_ARGS=(-H "$WAFW00F_HEADERS_FILE")
        WAFW00F_REDIRECT_ARGS=(-r)
    fi

    log_step "Running wafw00f (top $WAFW00F_MAX_TARGETS live hosts)..."
    if wafw00f \
        -i "$WAFW00F_TARGETS_FILE" \
        -o "$WAFW00F_JSON_FILE" \
        -f json \
        --no-colors \
        -T "$WAFW00F_HTTP_TIMEOUT" \
        "${WAFW00F_REDIRECT_ARGS[@]}" \
        "${WAFW00F_HEADER_ARGS[@]}" \
        >/dev/null 2>&1; then
        WAFW00F_STATUS="ok"
    else
        WAFW00F_STATUS="partial"
    fi

    python3 - "$WAFW00F_JSON_FILE" "$WAFW00F_HITS_FILE" <<'PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
rows = []

if src.exists() and src.stat().st_size:
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except Exception:
        data = []
    for item in data:
        if isinstance(item, dict) and item.get("detected"):
            rows.append("\t".join([
                str(item.get("url", "")),
                str(item.get("firewall", "")),
                str(item.get("manufacturer", "")),
                str(item.get("trigger_url", "")),
            ]))

dst.write_text(("\n".join(rows) + "\n") if rows else "", encoding="utf-8")
PY

    WAFW00F_COUNT=$(wc -l < "$WAFW00F_HITS_FILE" 2>/dev/null || echo 0)
    log_done "wafw00f scanned: $(wc -l < "$WAFW00F_TARGETS_FILE" 2>/dev/null || echo 0) hosts"
    if [ "$WAFW00F_COUNT" -gt 0 ]; then
        log_warn "WAF detected on $WAFW00F_COUNT host(s) — see $WAFW00F_HITS_FILE"
    else
        log_done "No WAF detected on sampled hosts"
    fi
    [ "$WAFW00F_STATUS" = "partial" ] && log_warn "wafw00f timed out or returned non-zero — partial output may still be useful"
else
    log_warn "wafw00f not installed or no live hosts — skipping WAF fingerprinting"
fi

WAF_HITS=$(wc -l < "$RECON_DIR/live/wafw00f_hits.txt" 2>/dev/null | tr -d ' ' || echo 0)
WAF_PHASE_STATUS="skipped"
if command -v wafw00f >/dev/null 2>&1 && [ -s "$RECON_DIR/live/urls.txt" ]; then
    WAF_PHASE_STATUS="ok"
fi
record_recon_phase \
    waf_fp \
    "$WAF_PHASE_STATUS" \
    "recon/${RECON_TARGET_KEY}/live/wafw00f_hits.txt" \
    "$WAF_HITS" \
    "sampled WAF fingerprinting; no hit does not prove no edge control"
emit_claude_hint \
    phase                waf_fp \
    waf_results_lines    "$WAF_HITS" \
    wafw00f_present      "$(command -v wafw00f >/dev/null 2>&1 && echo true || echo false)"
emit_claude_hint_actions \
    "bash tools/bypass_403.sh <url> on any 403 endpoint discovered later" \
    "if no WAF was detected, treat this as no sampled edge-control signal and continue recon"

# ============================================================
# Phase 2.6: Origin Discovery
# ============================================================
echo ""
log_info "Phase 2.6: Origin Discovery"

UNWAF_ENABLE=0
case "${BBHUNT_ENABLE_UNWAF:-0}" in
    1|true|TRUE|yes|YES) UNWAF_ENABLE=1 ;;
esac
case "${BBHUNT_SKIP_UNWAF:-0}" in
    1|true|TRUE|yes|YES) UNWAF_ENABLE=0 ;;
esac
UNWAF_SKIP=1
[ "$UNWAF_ENABLE" -eq 1 ] && UNWAF_SKIP=0

if [ "$UNWAF_SKIP" -eq 1 ]; then
    log_warn "unwaf origin discovery is disabled by default — set BBHUNT_ENABLE_UNWAF=1 to run it"
elif command -v unwaf &>/dev/null; then
    UNWAF_JSON_FILE="$RECON_DIR/live/unwaf.json"
    UNWAF_IPS_FILE="$RECON_DIR/live/unwaf_bypass_ips.txt"
    UNWAF_TARGETS_FILE="$RECON_DIR/live/unwaf_targets.txt"
    UNWAF_SOURCE_FILE="$RECON_DIR/live/unwaf_source.html"
    UNWAF_HTTP_TIMEOUT=$([ "$QUICK_MODE" = "--quick" ] && echo 5 || echo 8)
    UNWAF_RATE_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 2 || echo 4)
    UNWAF_WORKERS=$([ "$QUICK_MODE" = "--quick" ] && echo 15 || echo 25)
    UNWAF_SOURCE_ARGS=()

    if [ "$TARGET_KIND" = "domain" ]; then
        if bb_auth_active && [ -s "$RECON_DIR/live/urls.txt" ]; then
            head -1 "$RECON_DIR/live/urls.txt" > "$RECON_DIR/live/unwaf_source_url.txt"
            UNWAF_SOURCE_URL="$(head -1 "$RECON_DIR/live/unwaf_source_url.txt" 2>/dev/null || true)"
            if [ -n "$UNWAF_SOURCE_URL" ]; then
                bb_auth_args_for_url "$UNWAF_SOURCE_URL"
                curl -s "${BB_URL_AUTH_ARGS[@]}" --max-time 15 "$UNWAF_SOURCE_URL" -o "$UNWAF_SOURCE_FILE" 2>/dev/null || true
                [ -s "$UNWAF_SOURCE_FILE" ] && UNWAF_SOURCE_ARGS=(-s "$UNWAF_SOURCE_FILE")
            fi
        fi

        log_step "Running unwaf on $TARGET..."
        if unwaf \
            -d "$TARGET" \
            --json \
            -o "$UNWAF_JSON_FILE" \
            --timeout "$UNWAF_HTTP_TIMEOUT" \
            --rate-limit "$UNWAF_RATE_LIMIT" \
            -w "$UNWAF_WORKERS" \
            "${UNWAF_SOURCE_ARGS[@]}" \
            >/dev/null 2>&1; then
            UNWAF_STATUS="ok"
        else
            UNWAF_STATUS="partial"
        fi
        printf '%s\n' "$TARGET" > "$UNWAF_TARGETS_FILE"
    else
        log_warn "unwaf is only applicable to domain targets — skipping"
        UNWAF_STATUS="skip"
    fi

    if [ "${UNWAF_STATUS:-skip}" != "skip" ]; then
        python3 - "$UNWAF_JSON_FILE" "$UNWAF_IPS_FILE" <<'PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
ips = []
seen = set()

def collect(node):
    if isinstance(node, dict):
        bypasses = node.get("bypasses")
        if isinstance(bypasses, list):
            for item in bypasses:
                if isinstance(item, dict):
                    ip = str(item.get("ip", "")).strip()
                    if ip and ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
        for value in node.values():
            collect(value)
    elif isinstance(node, list):
        for value in node:
            collect(value)

if src.exists() and src.stat().st_size:
    try:
        collect(json.loads(src.read_text(encoding="utf-8")))
    except Exception:
        pass

dst.write_text(("\n".join(ips) + "\n") if ips else "", encoding="utf-8")
PY

        # Backward-compatible alias consumed by older summaries/prompts.
        if [ -s "$UNWAF_IPS_FILE" ]; then
            cp "$UNWAF_IPS_FILE" "$RECON_DIR/live/origin_candidates.txt" 2>/dev/null || true
        fi

        UNWAF_IP_COUNT=$(wc -l < "$UNWAF_IPS_FILE" 2>/dev/null || echo 0)
        log_done "unwaf scanned: $(wc -l < "$UNWAF_TARGETS_FILE" 2>/dev/null || echo 0) targets"
        if [ "$UNWAF_IP_COUNT" -gt 0 ]; then
            log_warn "Origin candidates found: $UNWAF_IP_COUNT — see $UNWAF_IPS_FILE"
        else
            log_done "No origin candidates found"
        fi
        [ "$UNWAF_STATUS" = "partial" ] && log_warn "unwaf timed out or returned non-zero — partial output may still be useful"
    fi
else
    log_warn "unwaf not installed — skipping origin discovery"
fi

ORIGIN_CANDS_FILE="$RECON_DIR/live/origin_candidates.txt"
[ -s "$RECON_DIR/live/unwaf_bypass_ips.txt" ] && ORIGIN_CANDS_FILE="$RECON_DIR/live/unwaf_bypass_ips.txt"
ORIGIN_CANDS=$(wc -l < "$ORIGIN_CANDS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
ORIGIN_PHASE_STATUS="skipped"
if [ "$UNWAF_ENABLE" -eq 1 ]; then
    ORIGIN_PHASE_STATUS="${UNWAF_STATUS:-ok}"
fi
record_recon_phase \
    origin_disco \
    "$ORIGIN_PHASE_STATUS" \
    "recon/${RECON_TARGET_KEY}/live/origin_candidates.txt" \
    "$ORIGIN_CANDS" \
    "origin discovery is opt-in; skipped means not attempted, not tested clean"
emit_claude_hint \
    phase                origin_disco \
    origin_candidates    "$ORIGIN_CANDS" \
    unwaf_present        "$(command -v unwaf >/dev/null 2>&1 && echo true || echo false)" \
    unwaf_enabled        "$([ "$UNWAF_ENABLE" -eq 1 ] && echo true || echo false)" \
    unwaf_skipped        "$([ "$UNWAF_SKIP" -eq 1 ] && echo true || echo false)"
emit_claude_hint_actions \
    "curl -H \"Host: ${TARGET}\" http://<origin_ip>/   # WAF bypass via origin" \
    "if origin_candidates is 0, preserve that as an unattempted/low-signal origin lane"

# ============================================================
# Phase 3: Port Scanning
# ============================================================
echo ""
log_info "Phase 3: Port Scanning"

if [ "$TARGET_KIND" = "url" ] || [ "$TARGET_HAS_EXPLICIT_PORT" = "true" ]; then
    log_warn "Skipping broad naabu scan for exact URL/explicit-port target"
    if [ -n "$TARGET_EXPLICIT_PORT" ]; then
        printf '%s/open\n' "$TARGET_EXPLICIT_PORT" > "$RECON_DIR/ports/open_ports_explicit.txt"
    fi
elif command -v naabu &>/dev/null; then
    NAABU_TARGETS_FILE="$RECON_DIR/ports/naabu_targets.txt"
    NAABU_OUTPUT_FILE="$RECON_DIR/ports/naabu.txt"
    NAABU_MAX_TARGETS=$([ "$QUICK_MODE" = "--quick" ] && echo 20 || echo 100)
    NAABU_TOP_PORTS=$([ "$QUICK_MODE" = "--quick" ] && echo 100 || echo 1000)
    NAABU_RATE=$([ "$QUICK_MODE" = "--quick" ] && echo 300 || echo 1000)

    if [ -s "$RECON_DIR/live/urls.txt" ]; then
        python3 - "$RECON_DIR/live/urls.txt" "$NAABU_TARGETS_FILE" "$NAABU_MAX_TARGETS" <<'PY'
from pathlib import Path
from urllib.parse import urlparse
import sys

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
limit = int(sys.argv[3])
hosts = []
seen = set()

for line in src.read_text(encoding="utf-8").splitlines():
    parsed = urlparse(line.strip())
    host = (parsed.hostname or "").strip().lower()
    if host and host not in seen:
        seen.add(host)
        hosts.append(host)
    if len(hosts) >= limit:
        break

dst.write_text(("\n".join(hosts) + "\n") if hosts else "", encoding="utf-8")
PY
    elif [ -s "$DISCOVERY_HOSTS_FILE" ]; then
        head -"$NAABU_MAX_TARGETS" "$DISCOVERY_HOSTS_FILE" > "$NAABU_TARGETS_FILE"
    elif [ "$TARGET_KIND" = "domain" ]; then
        printf '%s\n' "$TARGET" > "$NAABU_TARGETS_FILE"
    fi

    if [ -s "$NAABU_TARGETS_FILE" ]; then
        log_step "Running naabu (top $NAABU_MAX_TARGETS targets, top $NAABU_TOP_PORTS ports)..."
        naabu \
            -list "$NAABU_TARGETS_FILE" \
            -top-ports "$NAABU_TOP_PORTS" \
            -c "$THREADS" \
            -rate "$NAABU_RATE" \
            -silent \
            -o "$NAABU_OUTPUT_FILE" 2>/dev/null || true
        if [ -s "$NAABU_OUTPUT_FILE" ]; then
            sed -nE 's|.*:([0-9]+)$|\1/open|p' "$NAABU_OUTPUT_FILE" | sort -u > "$RECON_DIR/ports/open_ports_naabu.txt" 2>/dev/null || true
            log_done "naabu hits: $(wc -l < "$NAABU_OUTPUT_FILE" 2>/dev/null || echo 0)"
            log_done "naabu open ports: $(wc -l < "$RECON_DIR/ports/open_ports_naabu.txt" 2>/dev/null || echo 0)"
        else
            log_done "naabu: no open ports found"
        fi
    else
        log_warn "No naabu targets prepared — skipping"
    fi
else
    log_warn "naabu not installed — skipping"
fi

if [ "$TARGET_KIND" = "url" ] || [ "$TARGET_HAS_EXPLICIT_PORT" = "true" ]; then
    log_warn "Skipping broad nmap scan for exact URL/explicit-port target"
elif command -v nmap &>/dev/null; then
    if [ "$TARGET_KIND" = "domain" ]; then
        log_step "Running nmap (top 1000 ports) on $TARGET..."
        nmap -sV --top-ports 1000 -T4 --open "$TARGET" \
            -oN "$RECON_DIR/ports/nmap_results.txt" \
            -oG "$RECON_DIR/ports/nmap_greppable.txt" \
            -oX "$RECON_DIR/ports/nmap_results.xml" 2>/dev/null || true
        log_done "Nmap scan complete"
    elif [ -s "$DISCOVERY_HOSTS_FILE" ]; then
        log_step "Running nmap (top 1000 ports) on discovery host list..."
        nmap -sV --top-ports 1000 -T4 --open -iL "$DISCOVERY_HOSTS_FILE" \
            -oN "$RECON_DIR/ports/nmap_results.txt" \
            -oG "$RECON_DIR/ports/nmap_greppable.txt" \
            -oX "$RECON_DIR/ports/nmap_results.xml" 2>/dev/null || true
        log_done "Nmap scan complete"
    else
        log_warn "Discovery host list is empty — skipping port scan"
    fi

    if [ -f "$RECON_DIR/ports/nmap_greppable.txt" ]; then
        # Extract open ports (macOS compatible - no grep -P). Nmap greppable
        # keeps all ports for one host on a single comma-separated line, so
        # split first; otherwise a greedy sed expression only keeps the last
        # open port and under-reports attack surface.
        grep "open" "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null \
            | tr ',' '\n' \
            | sed -nE 's/.*[^0-9]([0-9]+)\/open\/.*/\1\/open/p' \
            | sort -u > "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || true
        log_done "Open ports: $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
    fi
else
    log_warn "nmap not installed — skipping"
fi

cat "$RECON_DIR/ports/open_ports.txt" "$RECON_DIR/ports/open_ports_naabu.txt" "$RECON_DIR/ports/open_ports_explicit.txt" 2>/dev/null \
    | awk 'NF' | sort -u > "$RECON_DIR/ports/open_ports_all.txt" || true
PORTS_OPEN=$(wc -l < "$RECON_DIR/ports/open_ports_all.txt" 2>/dev/null | tr -d ' ' || echo 0)
PORT_PHASE_STATUS="ok"
if [ "$TARGET_KIND" = "url" ] || [ "$TARGET_HAS_EXPLICIT_PORT" = "true" ]; then
    PORT_PHASE_STATUS="seeded"
elif ! command -v naabu >/dev/null 2>&1 && ! command -v nmap >/dev/null 2>&1; then
    PORT_PHASE_STATUS="skipped"
fi
record_recon_phase \
    port_scan \
    "$PORT_PHASE_STATUS" \
    "recon/${RECON_TARGET_KEY}/ports/open_ports_all.txt" \
    "$PORTS_OPEN" \
    "bounded infra inventory; explicit URL/port targets preserve supplied port without broad scan"
emit_claude_hint \
    phase                port_scan \
    open_ports_total     "$PORTS_OPEN"
emit_claude_hint_actions \
    "review non-standard ports (8080/3000/9200/etc) for less-reviewed surface" \
    "treat port results as sampled infra context when the host list is large"

# ============================================================
# Phase 4: URL Collection
# ============================================================
echo ""
log_info "Phase 4: URL Collection"

start_collector gau "$RECON_DIR/urls/gau.txt" \
    "recon/${RECON_TARGET_KEY}/urls/gau.txt" collect_gau_urls
start_collector wayback_urls "$RECON_DIR/urls/wayback.txt" \
    "recon/${RECON_TARGET_KEY}/urls/wayback.txt" collect_wayback_urls
start_collector waymore "$RECON_DIR/urls/waymore.txt" \
    "recon/${RECON_TARGET_KEY}/urls/waymore.txt" collect_waymore_urls
wait_collector_group

# katana 依赖 live hosts，因此只能在被动 URL collector 之后运行。
start_collector katana "$RECON_DIR/urls/katana.txt" \
    "recon/${RECON_TARGET_KEY}/urls/katana.txt" collect_katana_urls
wait_collector_group

# Merge only primary collector outputs. Do not glob every urls/*.txt here:
# derived files from previous runs (with_params/js/api/_filtered) must not feed
# back into the raw URL corpus.
{
    [ -s "$RECON_DIR/live/urls.txt" ] && cat "$RECON_DIR/live/urls.txt"
    [ -s "$RECON_DIR/live/seed_urls.txt" ] && cat "$RECON_DIR/live/seed_urls.txt"
    for url_source in gau wayback waymore katana; do
        append_artifact "$RECON_DIR/urls/${url_source}.txt"
    done
} 2>/dev/null | sort -u > "$RECON_DIR/urls/all.txt" 2>/dev/null || true
log_done "Total unique URLs: $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"

# Filter interesting URLs
: > "$RECON_DIR/urls/with_params.txt"
: > "$RECON_DIR/urls/js_files.txt"
: > "$RECON_DIR/urls/api_endpoints.txt"
: > "$RECON_DIR/urls/sensitive_paths.txt"

if [ -s "$RECON_DIR/urls/all.txt" ]; then
    # URLs with parameters (potential injection points)
    grep '?' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/with_params.txt" 2>/dev/null || true
    log_done "URLs with parameters: $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"

    # JS files
    grep -iE '\.js(\?|$)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
    log_done "JS files: $(wc -l < "$RECON_DIR/urls/js_files.txt" 2>/dev/null || echo 0)"

    # API endpoints
    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || true
    log_done "API endpoints: $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"

    # Potentially sensitive paths
    grep -iE '\.(env|config|xml|json|yaml|yml|bak|backup|old|orig|sql|db|log|txt|conf|ini|htaccess|htpasswd|git)' \
        "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || true
    log_done "Sensitive paths: $(wc -l < "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || echo 0)"
fi

URLS_TOTAL=$(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null | tr -d ' ' || echo 0)
URLS_PARAMS=$(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null | tr -d ' ' || echo 0)
URLS_JS=$(wc -l < "$RECON_DIR/urls/js_files.txt" 2>/dev/null | tr -d ' ' || echo 0)
URLS_API=$(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null | tr -d ' ' || echo 0)
URLS_SENS=$(wc -l < "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null | tr -d ' ' || echo 0)
URL_COLLECTION_STATUS="ok"
[ "$URLS_TOTAL" -eq 0 ] && URL_COLLECTION_STATUS="partial"
record_recon_phase \
    url_collection \
    "$URL_COLLECTION_STATUS" \
    "recon/${RECON_TARGET_KEY}/urls/all.txt" \
    "$URLS_TOTAL" \
    "raw URL corpus is authoritative; filtered files are priority views only"

# ============================================================
# Phase 4.5: URL Denoising (non-destructive)
# ============================================================
echo ""
log_info "Phase 4.5: URL Denoising"

URLS_FILTERED=0
URLS_PARAMS_FILTERED=0
URLS_JS_FILTERED=0
URLS_API_FILTERED=0
URLS_SENS_FILTERED=0
URL_FILTER_LOG="recon/${RECON_TARGET_KEY}/urls/filter.log"
URL_FILTER_LOG_ABS="$RECON_DIR/urls/filter.log"
URL_FILTER_SUMMARY="$RECON_DIR/urls/filter_summary.txt"
URL_DENOISE_STATUS="skipped"

# Avoid stale filtered artifacts when recon is rerun in the same target dir.
: > "$RECON_DIR/urls/all_filtered.txt"
: > "$RECON_DIR/urls/with_params_filtered.txt"
: > "$RECON_DIR/urls/js_files_filtered.txt"
: > "$RECON_DIR/urls/api_endpoints_filtered.txt"
: > "$RECON_DIR/urls/sensitive_paths_filtered.txt"

if [ -s "$RECON_DIR/urls/all.txt" ] && [ -f "$BASE_DIR/tools/recon_filters.py" ]; then
    log_step "Filtering URL noise into auxiliary *_filtered files (raw files preserved)..."
    URL_DENOISE_STATUS="ok"

    : > "$URL_FILTER_LOG_ABS"
    : > "$URL_FILTER_SUMMARY"

    python3 "$BASE_DIR/tools/recon_filters.py" \
        "$RECON_DIR/urls/all.txt" \
        "$RECON_DIR/urls/all_filtered.txt" \
        "$TARGET" \
        --log-file "$URL_FILTER_LOG_ABS" \
        >> "$URL_FILTER_SUMMARY" 2>&1 || true

    if [ -f "$RECON_DIR/urls/all_filtered.txt" ]; then
        grep '?' "$RECON_DIR/urls/all_filtered.txt" > "$RECON_DIR/urls/with_params_filtered.txt" 2>/dev/null || true
        grep -iE '\.js(\?|$)' "$RECON_DIR/urls/all_filtered.txt" > "$RECON_DIR/urls/js_files_filtered.txt" 2>/dev/null || true
        grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$RECON_DIR/urls/all_filtered.txt" > "$RECON_DIR/urls/api_endpoints_filtered.txt" 2>/dev/null || true
        grep -iE '\.(env|config|xml|json|yaml|yml|bak|backup|old|orig|sql|db|log|txt|conf|ini|htaccess|htpasswd|git)' \
            "$RECON_DIR/urls/all_filtered.txt" > "$RECON_DIR/urls/sensitive_paths_filtered.txt" 2>/dev/null || true

        URLS_FILTERED=$(wc -l < "$RECON_DIR/urls/all_filtered.txt" 2>/dev/null | tr -d ' ' || echo 0)
        URLS_PARAMS_FILTERED=$(wc -l < "$RECON_DIR/urls/with_params_filtered.txt" 2>/dev/null | tr -d ' ' || echo 0)
        URLS_JS_FILTERED=$(wc -l < "$RECON_DIR/urls/js_files_filtered.txt" 2>/dev/null | tr -d ' ' || echo 0)
        URLS_API_FILTERED=$(wc -l < "$RECON_DIR/urls/api_endpoints_filtered.txt" 2>/dev/null | tr -d ' ' || echo 0)
        URLS_SENS_FILTERED=$(wc -l < "$RECON_DIR/urls/sensitive_paths_filtered.txt" 2>/dev/null | tr -d ' ' || echo 0)

        log_done "Denoising complete: raw all.txt preserved; filtered URLs: $URLS_FILTERED; review $URL_FILTER_LOG"
    else
        URL_DENOISE_STATUS="partial"
        log_warn "Denoising produced no filtered URL file; raw all.txt preserved"
    fi
else
    log_warn "Skipping denoising - recon_filters.py not found or no URLs collected"
fi

record_recon_phase \
    url_denoising \
    "$URL_DENOISE_STATUS" \
    "recon/${RECON_TARGET_KEY}/urls/all_filtered.txt" \
    "$URLS_FILTERED" \
    "non-destructive priority view; raw all.txt remains the lossless backstop"

emit_claude_hint \
    phase                url_collection \
    urls_total           "$URLS_TOTAL" \
    urls_with_params     "$URLS_PARAMS" \
    js_files             "$URLS_JS" \
    api_endpoints        "$URLS_API" \
    sensitive_paths      "$URLS_SENS" \
    urls_filtered        "$URLS_FILTERED" \
    urls_with_params_filtered "$URLS_PARAMS_FILTERED" \
    js_files_filtered    "$URLS_JS_FILTERED" \
    api_endpoints_filtered "$URLS_API_FILTERED" \
    sensitive_paths_filtered "$URLS_SENS_FILTERED" \
    url_filter_log       "$URL_FILTER_LOG"
emit_claude_hint_actions \
    "tools/role_diff.py --target ${TARGET} --endpoints recon/${RECON_TARGET_KEY}/urls/api_endpoints_filtered.txt --session ...   # fallback to api_endpoints.txt if absent" \
    "tools/param_discovery.sh -l recon/${RECON_TARGET_KEY}/live/urls.txt   # mine hidden params" \
    "spawn js-reader if js_files_filtered/js_files > 0"

# ============================================================
# Phase 5: JS Analysis
# ============================================================
echo ""
log_info "Phase 5: JavaScript Analysis"

JS_FILES_FOR_ANALYSIS="$RECON_DIR/urls/js_files_analysis.txt"
build_filtered_first_backstop \
    "$RECON_DIR/urls/js_files_filtered.txt" \
    "$RECON_DIR/urls/js_files.txt" \
    "$JS_FILES_FOR_ANALYSIS"
JS_ANALYSIS_STATUS="skipped"
JS_CANDIDATE_BUILD_STATUS="skipped"
JS_DEEP_CANDIDATES=0
JS_DEEP_GENERATION=""

if [ -s "$JS_FILES_FOR_ANALYSIS" ]; then
    mkdir -p "$RECON_DIR/js"
    if python3 "$BASE_DIR/tools/recon_candidates.py" \
        --js-input "$JS_FILES_FOR_ANALYSIS" \
        --js-output "$RECON_DIR/js/deep_candidates.txt" \
        --js-limit "${BBHUNT_RECON_JS_CANDIDATE_LIMIT:-800}" \
        > "$RECON_DIR/logs/js_deep_candidates.json" 2>&1; then
        JS_CANDIDATE_BUILD_STATUS="ok"
        JS_DEEP_CANDIDATES=$(wc -l < "$RECON_DIR/js/deep_candidates.txt" 2>/dev/null | tr -d ' ' || echo 0)
        JS_DEEP_GENERATION=$(python3 - "$RECON_DIR/js/deep_candidates.txt" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
)
    else
        JS_CANDIDATE_BUILD_STATUS="partial"
        log_warn "Deep-JS candidate view failed; complete JS inventory and prior candidate artifact were preserved"
    fi

    if [ "$RECON_PROFILE" = "normal" ]; then
        JS_ANALYSIS_STATUS="deferred"
        log_done "Normal profile indexed JS inventory; deep analysis deferred to Action Queue"
        if [ "$JS_CANDIDATE_BUILD_STATUS" != "ok" ]; then
            JS_ANALYSIS_STATUS="partial"
        elif [ "$JS_DEEP_CANDIDATES" -gt 0 ] && ! python3 "$BASE_DIR/tools/action_queue.py" --repo-root "$BASE_DIR" add \
            --target "$TARGET" \
            --type "deep-js-review" \
            --evidence-type "recon-artifact" \
            --evidence "recon/${RECON_TARGET_KEY}/js/deep_candidates.txt" \
            --source "recon" \
            --source-id "deep-js-review" \
            --generation "$JS_DEEP_GENERATION" \
            --next-question "Which JS bundles expose high-value API, auth, source-map, upload, payment, or dynamic-signature behavior?" \
            --action "Review deep JS candidates selected from the complete JS inventory" \
            --priority 58 \
            --command-hint "/js-read $TARGET" \
            --stop-condition "Resolve only after selected high-value bundles are analyzed, or record an explicit blocked/deferred reason." \
            > "$RECON_DIR/logs/deep_js_action_queue.log" 2>&1; then
            JS_ANALYSIS_STATUS="partial"
            log_warn "Deep-JS candidates were preserved, but Action Queue update failed"
        fi
    else
        JS_ANALYSIS_STATUS="ok"
        log_step "Extracting endpoints from JS files (top 50)..."
        LINKFINDER_BIN="$(resolve_linkfinder_path || true)"

        head -50 "$JS_FILES_FOR_ANALYSIS" | while IFS= read -r js_url; do
            bb_auth_args_for_url "$js_url"
            curl -s "${BB_URL_AUTH_ARGS[@]}" --max-time 10 "$js_url" 2>/dev/null | \
                sed -nE 's/.*["'"'"']([a-zA-Z0-9_/.-]*(\/[a-zA-Z0-9_/.-]+)+)["'"'"'].*/\1/p' \
                >> "$RECON_DIR/js/endpoints_raw.txt" 2>/dev/null || true
        done

        if [ -f "$RECON_DIR/js/endpoints_raw.txt" ]; then
            sort -u "$RECON_DIR/js/endpoints_raw.txt" > "$RECON_DIR/js/endpoints.txt"
            log_done "JS endpoints: $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"

            # Extract potential secrets from JS
            head -50 "$JS_FILES_FOR_ANALYSIS" | while IFS= read -r js_url; do
                bb_auth_args_for_url "$js_url"
                curl -s "${BB_URL_AUTH_ARGS[@]}" --max-time 10 "$js_url" 2>/dev/null | \
                    grep -oiE '([a-zA-Z0-9_-]*(api[_-]?key|apiKey|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key|secretKey|token)[a-zA-Z0-9_-]*)["'\''[:space:]]*[:=]["'\''[:space:]]*["'\'' ]?([A-Za-z0-9_./+=:-]{8,})' \
                    >> "$RECON_DIR/js/potential_secrets.txt" 2>/dev/null || true
            done
            if [ -s "$RECON_DIR/js/potential_secrets.txt" ]; then
                sort -u "$RECON_DIR/js/potential_secrets.txt" -o "$RECON_DIR/js/potential_secrets.txt"
                log_warn "Potential secrets found in JS: $(wc -l < "$RECON_DIR/js/potential_secrets.txt")"
            fi
        fi

        if [ -n "$LINKFINDER_BIN" ]; then
            LINKFINDER_MAX_JS=$([ "$QUICK_MODE" = "--quick" ] && echo 10 || echo 25)
            log_step "Running LinkFinder on top $LINKFINDER_MAX_JS JS files..."
            : > "$RECON_DIR/js/linkfinder_raw.txt"
            head -"$LINKFINDER_MAX_JS" "$JS_FILES_FOR_ANALYSIS" | while IFS= read -r js_url; do
                tmp_js="$(mktemp "${TMPDIR:-/tmp}/bbhunt-linkfinder.XXXXXX.js")"
                bb_auth_args_for_url "$js_url"
                if curl -s "${BB_URL_AUTH_ARGS[@]}" --max-time 15 "$js_url" -o "$tmp_js" 2>/dev/null && [ -s "$tmp_js" ]; then
                    if [ "${LINKFINDER_BIN##*.}" = "py" ]; then
                        python3 "$LINKFINDER_BIN" -i "$tmp_js" -o cli 2>/dev/null || true
                    else
                        "$LINKFINDER_BIN" -i "$tmp_js" -o cli 2>/dev/null || true
                    fi
                fi
                rm -f "$tmp_js"
            done > "$RECON_DIR/js/linkfinder_raw.txt"
            sed '/^[[:space:]]*$/d' "$RECON_DIR/js/linkfinder_raw.txt" | sort -u > "$RECON_DIR/js/linkfinder_endpoints.txt" 2>/dev/null || true
            log_done "LinkFinder endpoints: $(wc -l < "$RECON_DIR/js/linkfinder_endpoints.txt" 2>/dev/null || echo 0)"
        else
            log_warn "LinkFinder not installed — skipping JS endpoint extraction"
        fi
        [ "$JS_CANDIDATE_BUILD_STATUS" = "ok" ] || JS_ANALYSIS_STATUS="partial"
    fi
else
    log_warn "No current JS files found — skipping JS analysis; prior candidate artifact remains available to existing queue history"
fi

JS_ENDPOINTS=$(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null | tr -d ' ' || echo 0)
JS_SECRETS=$(wc -l < "$RECON_DIR/js/potential_secrets.txt" 2>/dev/null | tr -d ' ' || echo 0)
JS_LINKFINDER=$(wc -l < "$RECON_DIR/js/linkfinder_endpoints.txt" 2>/dev/null | tr -d ' ' || echo 0)
JS_MANIFEST_COUNT="$JS_ENDPOINTS"
[ "$RECON_PROFILE" != "normal" ] || JS_MANIFEST_COUNT="$JS_DEEP_CANDIDATES"
record_recon_phase \
    js_analysis \
    "$JS_ANALYSIS_STATUS" \
    "recon/${RECON_TARGET_KEY}/js/$([ "$RECON_PROFILE" = "normal" ] && echo deep_candidates.txt || echo endpoints.txt)" \
    "$JS_MANIFEST_COUNT" \
    "all JS URLs remain in urls/js_files.txt; candidate_view=${JS_CANDIDATE_BUILD_STATUS}; limit=${BBHUNT_RECON_JS_CANDIDATE_LIMIT:-800}; normal defers deep analysis without closing coverage"
emit_claude_hint \
    phase                  js_analysis \
    profile                "$RECON_PROFILE" \
    deep_candidates        "$JS_DEEP_CANDIDATES" \
    endpoints_extracted    "$JS_ENDPOINTS" \
    linkfinder_endpoints   "$JS_LINKFINDER" \
    unverified_secret_strings "$JS_SECRETS" \
    secrets_verified       "false (regex-grep only; not interactsh-verified)"
emit_claude_hint_actions \
    "bash tools/secrets_hunter.sh --js-bundle recon/${RECON_TARGET_KEY}   # trufflehog-verified secrets" \
    "spawn js-reader on cached materials for endpoint hypotheses" \
    "tools/oast_listen.py start --target ${TARGET}   # blind callback channel for any RCE/SSRF lead"

# ============================================================
# Phase 6: Directory Fuzzing
# ============================================================
echo ""
log_info "Phase 6: Directory Fuzzing"

WORDLIST_DIR="$BASE_DIR/wordlists"
LEGACY_WORDLIST_DIR="$BASE_DIR/tools/wordlists"
WORDLIST=""
FFUF_ATTEMPTED=0
FFUF_SUCCEEDED=0
FFUF_FAILED=0
FFUF_CONTROL_FAILED=0
FFUF_OBSERVATIONS=0
FFUF_PARSE_ERRORS=0
FFUF_SAMPLE_COUNT=0
FFUF_OVERFLOW=0
FFUF_STATUS_COUNTS="{}"
FFUF_HEAVY_SIGNATURES="-"
FFUF_RESULT_TMP=""
FFUF_CONTROL_TMP=""
FFUF_CONTROL_RUN_TMP=""
FFUF_CONTROL_WORDLIST_TMP=""
FFUF_RESULT_ARTIFACT=""
FFUF_PHASE_ARTIFACT="recon/${RECON_TARGET_KEY}/dirs/"
FFUF_SUMMARY_ARTIFACT="-"
FFUF_SKIP_REASON=""
FFUF_SUMMARY_OK="false"
DIR_FUZZ_STATUS="skipped"
FFUF_LOG="$RECON_DIR/logs/ffuf.log"

if ! command -v ffuf >/dev/null 2>&1; then
    FFUF_SKIP_REASON="ffuf not installed"
elif [ ! -s "$RECON_DIR/live/urls.txt" ]; then
    FFUF_SKIP_REASON="no live URLs"
else
    if [ -f "$WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$WORDLIST_DIR/common.txt"
    elif [ -f "$LEGACY_WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$LEGACY_WORDLIST_DIR/common.txt"
    elif [ -f "$WORDLIST_DIR/raft-medium-dirs.txt" ]; then
        WORDLIST="$WORDLIST_DIR/raft-medium-dirs.txt"
    elif [ -f "$LEGACY_WORDLIST_DIR/raft-medium-dirs.txt" ]; then
        WORDLIST="$LEGACY_WORDLIST_DIR/raft-medium-dirs.txt"
    elif [ -f /usr/share/wordlists/dirb/common.txt ]; then
        WORDLIST="/usr/share/wordlists/dirb/common.txt"
    else
        FFUF_SKIP_REASON="no wordlist"
    fi
fi

if [ -n "$WORDLIST" ]; then
    MAX_FUZZ=$([ "$QUICK_MODE" = "--quick" ] && echo 2 || echo 5)
    SPA_FALLBACK_LOG="$RECON_DIR/dirs/spa_fallback.txt"
    : > "$SPA_FALLBACK_LOG"
    : > "$FFUF_LOG"
    FFUF_CONTROL_TMP="$(mktemp "$RECON_DIR/dirs/.ffuf_controls.XXXXXX")"
    FFUF_RESULT_TMP="$(mktemp "$RECON_DIR/dirs/.ffuf_results.XXXXXX")"

    if command -v gzip >/dev/null 2>&1 && gzip -c /dev/null > "$FFUF_RESULT_TMP" 2>> "$FFUF_LOG"; then
        FFUF_RESULT_ARTIFACT="$RECON_DIR/dirs/ffuf_results.jsonl.gz"
        FFUF_USE_GZIP="true"
    else
        : > "$FFUF_RESULT_TMP"
        FFUF_RESULT_ARTIFACT="$RECON_DIR/dirs/ffuf_results.jsonl"
        FFUF_USE_GZIP="false"
    fi

    while IFS= read -r url && [ "$FFUF_ATTEMPTED" -lt "$MAX_FUZZ" ]; do
        [ -n "$url" ] || continue
        bb_auth_args_for_url "$url"
        FFUF_ATTEMPTED=$((FFUF_ATTEMPTED + 1))
        FFUF_FILTER_ARGS=()
        FFUF_CONTROL_WORDLIST_TMP="$(mktemp "$RECON_DIR/dirs/.ffuf-control-words.XXXXXX")"
        FFUF_CONTROL_RUN_TMP="$(mktemp "$RECON_DIR/dirs/.ffuf-control-run.XXXXXX")"
        printf '__bbhunt_missing_%s_%s\n__bbhunt_missing_%s_%s\n' \
            "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM" > "$FFUF_CONTROL_WORDLIST_TMP"

        if ffuf -u "${url}/FUZZ" \
            -w "$FFUF_CONTROL_WORDLIST_TMP" \
            -mc all \
            -s -json \
            -t 1 \
            -rate "$RATE_LIMIT" \
            -timeout 10 \
            "${BB_URL_AUTH_ARGS[@]}" \
            > "$FFUF_CONTROL_RUN_TMP" 2>> "$FFUF_LOG"; then
            cat "$FFUF_CONTROL_RUN_TMP" >> "$FFUF_CONTROL_TMP"
            if ! SPA_FALLBACK_SIZE="$(python3 "$BASE_DIR/tools/recon_adapter.py" \
                --recon-dir "$RECON_DIR" \
                --ffuf-control-size \
                --controls "$FFUF_CONTROL_RUN_TMP" 2>> "$FFUF_LOG")"; then
                SPA_FALLBACK_SIZE=0
                FFUF_CONTROL_FAILED=$((FFUF_CONTROL_FAILED + 1))
            fi
            if ! [[ "$SPA_FALLBACK_SIZE" =~ ^[0-9]+$ ]]; then
                SPA_FALLBACK_SIZE=0
                FFUF_CONTROL_FAILED=$((FFUF_CONTROL_FAILED + 1))
            fi
            if [ "$SPA_FALLBACK_SIZE" -gt 0 ]; then
                FFUF_FILTER_ARGS=(-fs "$SPA_FALLBACK_SIZE")
                printf '%s\t%s\n' "$url" "$SPA_FALLBACK_SIZE" >> "$SPA_FALLBACK_LOG"
                log_warn "SPA fallback observed for $url (two FFUF controls returned 200 size=$SPA_FALLBACK_SIZE); filtering that size"
            fi
        else
            FFUF_CONTROL_FAILED=$((FFUF_CONTROL_FAILED + 1))
            log_warn "FFUF random-miss controls failed for $url; continuing without a fallback size filter"
        fi
        rm -f "$FFUF_CONTROL_WORDLIST_TMP" "$FFUF_CONTROL_RUN_TMP"
        FFUF_CONTROL_WORDLIST_TMP=""
        FFUF_CONTROL_RUN_TMP=""

        log_step "Fuzzing: $url"
        if [ "$FFUF_USE_GZIP" = "true" ]; then
            if ffuf -u "${url}/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,301,302,403,405 \
                -ac \
                "${FFUF_FILTER_ARGS[@]}" \
                -t "$THREADS" \
                -rate "$RATE_LIMIT" \
                -timeout 10 \
                "${BB_URL_AUTH_ARGS[@]}" \
                -s -json 2>> "$FFUF_LOG" | gzip -c >> "$FFUF_RESULT_TMP"; then
                FFUF_SUCCEEDED=$((FFUF_SUCCEEDED + 1))
            else
                FFUF_FAILED=$((FFUF_FAILED + 1))
                log_warn "FFUF failed for $url; any valid partial JSONL remains in the evidence artifact"
            fi
        else
            if ffuf -u "${url}/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,301,302,403,405 \
                -ac \
                "${FFUF_FILTER_ARGS[@]}" \
                -t "$THREADS" \
                -rate "$RATE_LIMIT" \
                -timeout 10 \
                "${BB_URL_AUTH_ARGS[@]}" \
                -s -json >> "$FFUF_RESULT_TMP" 2>> "$FFUF_LOG"; then
                FFUF_SUCCEEDED=$((FFUF_SUCCEEDED + 1))
            else
                FFUF_FAILED=$((FFUF_FAILED + 1))
                log_warn "FFUF failed for $url; any valid partial JSONL remains in the evidence artifact"
            fi
        fi
    done < "$RECON_DIR/live/urls.txt"

    if [ "$FFUF_ATTEMPTED" -gt 0 ]; then
        mv -f "$FFUF_RESULT_TMP" "$FFUF_RESULT_ARTIFACT"
        FFUF_RESULT_TMP=""
        if [ "$FFUF_USE_GZIP" = "true" ]; then
            rm -f "$RECON_DIR/dirs/ffuf_results.jsonl"
        else
            rm -f "$RECON_DIR/dirs/ffuf_results.jsonl.gz"
        fi
        FFUF_PHASE_ARTIFACT="recon/${RECON_TARGET_KEY}/dirs/$(basename "$FFUF_RESULT_ARTIFACT")"

        if python3 "$BASE_DIR/tools/recon_adapter.py" \
            --recon-dir "$RECON_DIR" \
            --summarize-ffuf \
            --controls "$FFUF_CONTROL_TMP" \
            --attempted "$FFUF_ATTEMPTED" \
            --succeeded "$FFUF_SUCCEEDED" \
            --failed "$FFUF_FAILED" \
            --control-failed "$FFUF_CONTROL_FAILED" \
            >> "$FFUF_LOG" 2>&1; then
            FFUF_SUMMARY_OK="true"
            FFUF_SUMMARY_ARTIFACT="recon/${RECON_TARGET_KEY}/dirs/ffuf_summary.json"
            if FFUF_SUMMARY_VALUES="$(python3 - "$RECON_DIR/dirs/ffuf_summary.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
heavy = ",".join(
    f"{item.get('signature_id', '-')}:status={item.get('status', 0)}/count={item.get('count', 0)}/ratio={item.get('ratio', 0)}/control={str(bool(item.get('matches_random_miss_control'))).lower()}"
    for item in (payload.get("heavy_signatures") or [])[:4]
) or "-"
print(
    payload.get("observations", 0),
    payload.get("parse_error_count", 0),
    payload.get("sample_count", 0),
    payload.get("overflow", 0),
    json.dumps(payload.get("status_counts") or {}, separators=(",", ":")),
    heavy,
    sep="\t",
)
PY
)"; then
                IFS=$'\t' read -r FFUF_OBSERVATIONS FFUF_PARSE_ERRORS FFUF_SAMPLE_COUNT FFUF_OVERFLOW FFUF_STATUS_COUNTS FFUF_HEAVY_SIGNATURES <<< "$FFUF_SUMMARY_VALUES"
            else
                FFUF_SUMMARY_OK="false"
                log_warn "FFUF summary was written but its compact counters could not be read"
            fi
        else
            log_warn "ReconAdapter failed to summarize FFUF evidence; full result artifact was preserved"
        fi
    else
        FFUF_SKIP_REASON="no usable base URLs"
        rm -f "$FFUF_RESULT_TMP"
        FFUF_RESULT_TMP=""
    fi

    rm -f "$FFUF_CONTROL_TMP"
    FFUF_CONTROL_TMP=""
fi

if [ "$FFUF_ATTEMPTED" -gt 0 ]; then
    DIR_FUZZ_STATUS="ok"
    if [ "$FFUF_FAILED" -gt 0 ] || [ "$FFUF_CONTROL_FAILED" -gt 0 ] || \
       [ "$FFUF_PARSE_ERRORS" -gt 0 ] || [ "$FFUF_SUMMARY_OK" != "true" ]; then
        DIR_FUZZ_STATUS="partial"
    fi
    log_done "Directory fuzzing complete: attempted=$FFUF_ATTEMPTED succeeded=$FFUF_SUCCEEDED failed=$FFUF_FAILED observations=$FFUF_OBSERVATIONS"
else
    log_warn "Directory fuzzing skipped: ${FFUF_SKIP_REASON:-no runnable inputs}"
fi

FFUF_PHASE_NOTE="bounded host sampling; attempted=$FFUF_ATTEMPTED succeeded=$FFUF_SUCCEEDED failed=$FFUF_FAILED control_failed=$FFUF_CONTROL_FAILED parse_errors=$FFUF_PARSE_ERRORS; not complete directory coverage"
[ -n "$FFUF_SKIP_REASON" ] && FFUF_PHASE_NOTE="$FFUF_PHASE_NOTE; skipped_reason=$FFUF_SKIP_REASON"
record_recon_phase \
    dir_fuzz \
    "$DIR_FUZZ_STATUS" \
    "$FFUF_PHASE_ARTIFACT" \
    "$FFUF_OBSERVATIONS" \
    "$FFUF_PHASE_NOTE"
emit_claude_hint \
    phase                dir_fuzz \
    status               "$DIR_FUZZ_STATUS" \
    hosts_attempted      "$FFUF_ATTEMPTED" \
    hosts_succeeded      "$FFUF_SUCCEEDED" \
    hosts_failed         "$FFUF_FAILED" \
    observations         "$FFUF_OBSERVATIONS" \
    status_counts        "$FFUF_STATUS_COUNTS" \
    heavy_signatures     "$FFUF_HEAVY_SIGNATURES" \
    review_sample_count  "$FFUF_SAMPLE_COUNT" \
    review_overflow      "$FFUF_OVERFLOW" \
    artifact             "$FFUF_PHASE_ARTIFACT" \
    summary              "$FFUF_SUMMARY_ARTIFACT" \
    interpretation       "AI review required; control matches are evidence hints, not exclusions"

# ============================================================
# Phase 6.5: Config File Exposure Check
# ============================================================
echo ""
log_info "Phase 6.5: Config File Exposure Check"

if [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Checking for exposed config files (env.js, app_env.js, .env, etc.)..."
    CONFIG_PATHS=(
        "/env.js"
        "/app_env.js"
        "/config.js"
        "/settings.js"
        "/.env"
        "/.env.local"
        "/.env.production"
        "/.env.development"
        "/config/env.js"
        "/static/env.js"
        "/assets/env.js"
    )

    mkdir -p "$RECON_DIR/exposure"
    : > "$RECON_DIR/exposure/config_files.txt"

    while IFS= read -r base_url; do
        for path in "${CONFIG_PATHS[@]}"; do
            bb_auth_args_for_url "${base_url}${path}"
            STATUS=$(curl -s "${BB_URL_AUTH_ARGS[@]}" -o /dev/null -w "%{http_code}" --max-time 5 "${base_url}${path}" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ]; then
                CONTENT_TYPE=$(curl -sI "${BB_URL_AUTH_ARGS[@]}" --max-time 5 "${base_url}${path}" 2>/dev/null | grep -i content-type | head -1 || true)
                # Only flag if it returns JS/JSON/text (not HTML error pages)
                if echo "$CONTENT_TYPE" | grep -qiE '(javascript|json|text/plain)'; then
                    echo "[EXPOSED] ${base_url}${path}" >> "$RECON_DIR/exposure/config_files.txt"
                    log_vuln "Config exposed: ${base_url}${path}"
                fi
            fi
        done
    done < <(head -30 "$RECON_DIR/live/urls.txt")

    CONFIG_COUNT=$(wc -l < "$RECON_DIR/exposure/config_files.txt" 2>/dev/null | tr -d ' ')
    [ "$CONFIG_COUNT" -gt 0 ] && log_warn "Exposed config files: $CONFIG_COUNT" || log_done "Config files: clean"
else
    log_warn "No live hosts — skipping config check"
fi

CONFIG_EXPOSED=$(wc -l < "$RECON_DIR/exposure/config_files.txt" 2>/dev/null | tr -d ' ' || echo 0)
CONFIG_PHASE_STATUS="skipped"
[ -s "$RECON_DIR/live/urls.txt" ] && CONFIG_PHASE_STATUS="ok"
record_recon_phase \
    config_exposure \
    "$CONFIG_PHASE_STATUS" \
    "recon/${RECON_TARGET_KEY}/exposure/config_files.txt" \
    "$CONFIG_EXPOSED" \
    "fixed low-impact config path probes; evidence candidates require AI review"
emit_claude_hint \
    phase                config_exposure \
    exposed_count        "$CONFIG_EXPOSED" \
    paths_checked        11
emit_claude_hint_actions \
    "curl each exposed path; grep response body for keys/tokens" \
    "bash tools/secrets_hunter.sh --filesystem recon/${RECON_TARGET_KEY}/exposure/   # verify any extracted keys"

# ============================================================
# Phase 6.6: Exposure Candidate Correlation
# ============================================================
echo ""
log_info "Phase 6.6: Exposure Candidate Correlation"

API_DOC_CANDIDATES="$RECON_DIR/exposure/api_doc_candidates.txt"
CLOUD_STORAGE_CANDIDATES="$RECON_DIR/exposure/cloud_storage_candidates.txt"
S3_BUCKET_CANDIDATES="$RECON_DIR/exposure/s3_bucket_candidates.txt"
EXTERNAL_SERVICE_HOSTS="$RECON_DIR/exposure/external_service_hosts.txt"

: > "$API_DOC_CANDIDATES"
: > "$CLOUD_STORAGE_CANDIDATES"
: > "$S3_BUCKET_CANDIDATES"
: > "$EXTERNAL_SERVICE_HOSTS"

# 这里只做“已采集材料的二次归类”，不额外启动重型外部 OSINT 扫描。
# 深度情报、云枚举、源码和密钥验证仍交给对应的独立命令。
API_DOC_RE='(swagger|openapi|api-docs|swagger-ui|redoc|postman|graphql-playground|graphiql)'
CLOUD_SERVICE_RE='([a-z0-9][a-z0-9.-]*\.)?(s3[.-][a-z0-9-]+\.amazonaws\.com|s3\.amazonaws\.com|s3-website[.-][a-z0-9-]+\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|digitaloceanspaces\.com|cloudfront\.net|firebaseio\.com|firebasestorage\.app|azurewebsites\.net|herokuapp\.com|vercel\.app|netlify\.app|pages\.dev|workers\.dev)'

collect_exposure_candidates() {
    local src="$1"
    local label="$2"
    [ -s "$src" ] || return 0

    # API 文档 / Postman / GraphQL IDE 入口通常是低成本高回报入口，先归档为候选。
    grep -aEi "$API_DOC_RE" "$src" 2>/dev/null \
        | sed "s|^|[$label] |" >> "$API_DOC_CANDIDATES" || true

    # 从 URL/JS/config 缓存中抽云存储与第三方托管域名；只归类，不主动扫描。
    grep -aEio "https?://[^[:space:]\"'<>()]+" "$src" 2>/dev/null \
        | sed 's/[),.;]*$//' \
        | grep -aEi "$CLOUD_SERVICE_RE" \
        | sed "s|^|[$label] |" >> "$CLOUD_STORAGE_CANDIDATES" || true
    grep -aEio "$CLOUD_SERVICE_RE" "$src" 2>/dev/null \
        | sed "s|^|[$label] |" >> "$EXTERNAL_SERVICE_HOSTS" || true
}

collect_exposure_candidates "$RECON_DIR/urls/all.txt" "urls"
collect_exposure_candidates "$RECON_DIR/js/endpoints.txt" "js"
collect_exposure_candidates "$RECON_DIR/js/linkfinder_endpoints.txt" "linkfinder"
collect_exposure_candidates "$RECON_DIR/js/potential_secrets.txt" "js-secrets"
collect_exposure_candidates "$RECON_DIR/exposure/config_files.txt" "config"

sort -u "$API_DOC_CANDIDATES" -o "$API_DOC_CANDIDATES" 2>/dev/null || true
sort -u "$CLOUD_STORAGE_CANDIDATES" -o "$CLOUD_STORAGE_CANDIDATES" 2>/dev/null || true
sort -u "$EXTERNAL_SERVICE_HOSTS" -o "$EXTERNAL_SERVICE_HOSTS" 2>/dev/null || true

python3 - "$CLOUD_STORAGE_CANDIDATES" "$S3_BUCKET_CANDIDATES" <<'PY' 2>/dev/null || true
from pathlib import Path
from urllib.parse import urlparse
import re
import sys

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
seen = set()
out = []

def add(value: str) -> None:
    value = (value or "").strip().strip("/")
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value) and value not in seen:
        seen.add(value)
        out.append(value)

if src.exists():
    for raw in src.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = re.sub(r"^\[[^]]+\]\s+", "", raw.strip())
        parsed = urlparse(value if "://" in value else f"https://{value}")
        host = (parsed.hostname or "").lower()
        first_path = parsed.path.strip("/").split("/", 1)[0]
        if value.startswith("s3://"):
            add(value[5:].split("/", 1)[0])
        elif ".s3" in host and host.endswith("amazonaws.com"):
            add(host.split(".s3", 1)[0])
        elif ".s3-website" in host and host.endswith("amazonaws.com"):
            add(host.split(".s3-website", 1)[0])
        elif host.startswith(("s3.", "s3-")):
            add(first_path)

dst.write_text(("\n".join(out[:500]) + "\n") if out else "", encoding="utf-8")
PY

API_DOC_COUNT=$(wc -l < "$API_DOC_CANDIDATES" 2>/dev/null | tr -d ' ' || echo 0)
CLOUD_CANDIDATE_COUNT=$(wc -l < "$CLOUD_STORAGE_CANDIDATES" 2>/dev/null | tr -d ' ' || echo 0)
S3_BUCKET_COUNT=$(wc -l < "$S3_BUCKET_CANDIDATES" 2>/dev/null | tr -d ' ' || echo 0)
EXTERNAL_SERVICE_COUNT=$(wc -l < "$EXTERNAL_SERVICE_HOSTS" 2>/dev/null | tr -d ' ' || echo 0)

log_done "API doc candidates: $API_DOC_COUNT"
log_done "Cloud storage candidates: $CLOUD_CANDIDATE_COUNT"
log_done "S3 bucket candidates: $S3_BUCKET_COUNT"
log_done "External service hosts: $EXTERNAL_SERVICE_COUNT"

EXPOSURE_TOTAL=$((API_DOC_COUNT + CLOUD_CANDIDATE_COUNT + S3_BUCKET_COUNT + EXTERNAL_SERVICE_COUNT))
record_recon_phase \
    exposure_candidates \
    ok \
    "recon/${RECON_TARGET_KEY}/exposure/" \
    "$EXPOSURE_TOTAL" \
    "correlation over already collected recon artifacts; no extra OSINT scan"

emit_claude_hint \
    phase                exposure_candidates \
    api_doc_candidates   "$API_DOC_COUNT" \
    cloud_candidates     "$CLOUD_CANDIDATE_COUNT" \
    s3_bucket_candidates "$S3_BUCKET_COUNT" \
    external_hosts       "$EXTERNAL_SERVICE_COUNT" \
    note                 "derived from recon artifacts only; no extra OSINT scan"
emit_claude_hint_actions \
    "curl recon/${RECON_TARGET_KEY}/exposure/api_doc_candidates.txt entries first; Swagger/OpenAPI often exposes auth model and hidden endpoints" \
    "run /cloud-recon --keyword ${TARGET%%.*} only when cloud candidates look target-owned" \
    "run /secrets-hunt --filesystem recon/${RECON_TARGET_KEY}/exposure/ if config/cloud artifacts contain key-like material"

# ============================================================
# Phase 6.7: API Leak Detection
# ============================================================
echo ""
log_info "Phase 6.7: API Leak Detection"

API_LEAK_DIR="$RECON_DIR/exposure/api_leaks"
API_LEAK_CANDIDATES="$RECON_DIR/exposure/api_leak_candidates.txt"
API_LEAK_TRUFFLEHOG="$RECON_DIR/exposure/api_leak_trufflehog_verified.jsonl"
POSTMAN_LEAKS="$API_LEAK_DIR/postman_leaks.txt"
POSTLEAKS_DIR="$API_LEAK_DIR/postleaksNg"
POSTLEAKS_LOG="$API_LEAK_DIR/postleaksNg.log"
POSTLEAKS_URLS="$API_LEAK_DIR/postleaks_urls.txt"
SWAGGER_LEAKS="$API_LEAK_DIR/swagger_leaks.txt"
API_LEAK_TARGET=""
API_LEAK_TIMEOUT=$([ "$QUICK_MODE" = "--quick" ] && echo 120 || echo 240)

mkdir -p "$API_LEAK_DIR" "$POSTLEAKS_DIR"
: > "$API_LEAK_CANDIDATES"
: > "$API_LEAK_TRUFFLEHOG"
: > "$POSTMAN_LEAKS"
: > "$POSTLEAKS_LOG"
: > "$POSTLEAKS_URLS"
: > "$SWAGGER_LEAKS"

if [ "$TARGET_KIND" = "domain" ]; then
    API_LEAK_TARGET="$TARGET"
fi

if [ -n "$API_LEAK_TARGET" ]; then
    if command -v porch-pirate &>/dev/null; then
        log_step "Searching public Postman leaks with porch-pirate..."
        run_with_timeout "$API_LEAK_TIMEOUT" porch-pirate -s "$API_LEAK_TARGET" -l 25 --dump \
            > "$POSTMAN_LEAKS" 2>/dev/null || \
        run_with_timeout "$API_LEAK_TIMEOUT" porch-pirate -s "$API_LEAK_TARGET" -l 25 \
            > "$POSTMAN_LEAKS" 2>/dev/null || true
        log_done "porch-pirate lines: $(wc -l < "$POSTMAN_LEAKS" 2>/dev/null || echo 0)"
    else
        log_warn "porch-pirate not installed — skipping Postman public workspace search"
    fi

    if command -v postleaksNg &>/dev/null; then
        POSTLEAKS_THREADS=$([ "$QUICK_MODE" = "--quick" ] && echo 1 || echo 2)
        log_step "Searching Postman leaks with postleaksNg..."
        run_with_timeout "$API_LEAK_TIMEOUT" postleaksNg \
            -k "$API_LEAK_TARGET" \
            --output "$POSTLEAKS_DIR" \
            -t "$POSTLEAKS_THREADS" \
            > "$POSTLEAKS_LOG" 2>&1 || true

        # postleaksNg 输出格式可能随版本变化；这里按文本方式提取 URL，避免 jq 依赖。
        while IFS= read -r -d '' leak_file; do
            grep -aEio "https?://[^[:space:]\"'<>()]+" "$leak_file" 2>/dev/null \
                | sed 's/[),.;]*$//' >> "$POSTLEAKS_URLS" || true
        done < <(find "$POSTLEAKS_DIR" -type f -print0 2>/dev/null)
        sort -u "$POSTLEAKS_URLS" -o "$POSTLEAKS_URLS" 2>/dev/null || true
        log_done "postleaksNg URLs: $(wc -l < "$POSTLEAKS_URLS" 2>/dev/null || echo 0)"
    else
        log_warn "postleaksNg not installed — skipping enhanced Postman leak search"
    fi

    if [ -x "$SHARED_TOOLS_DIR/SwaggerSpy/venv/bin/python3" ] && [ -f "$SHARED_TOOLS_DIR/SwaggerSpy/swaggerspy.py" ]; then
        log_step "Searching Swagger/OpenAPI leaks with Osmedeus SwaggerSpy..."
        (
            cd "$SHARED_TOOLS_DIR/SwaggerSpy" 2>/dev/null && \
            run_with_timeout "$API_LEAK_TIMEOUT" \
                "$SHARED_TOOLS_DIR/SwaggerSpy/venv/bin/python3" \
                "$SHARED_TOOLS_DIR/SwaggerSpy/swaggerspy.py" \
                "$API_LEAK_TARGET"
        ) > "$SWAGGER_LEAKS" 2>/dev/null || true
    else
        log_warn "Osmedeus SwaggerSpy not found under $SHARED_TOOLS_DIR/SwaggerSpy — skipping Swagger/OpenAPI leak search"
    fi
    log_done "Swagger/OpenAPI leak lines: $(wc -l < "$SWAGGER_LEAKS" 2>/dev/null || echo 0)"
else
    log_warn "API leak search is domain-keyed — skipping for $TARGET_KIND target"
fi

for f in "$POSTMAN_LEAKS" "$POSTLEAKS_URLS" "$SWAGGER_LEAKS" "$API_DOC_CANDIDATES"; do
    [ -s "$f" ] || continue
    grep -aEi '(https?://|postman|swagger|openapi|api-docs|swagger-ui|redoc|graphql|apikey|api[_-]?key|token|secret|authorization|bearer|client_secret)' "$f" \
        >> "$API_LEAK_CANDIDATES" 2>/dev/null || true
done
sort -u "$API_LEAK_CANDIDATES" -o "$API_LEAK_CANDIDATES" 2>/dev/null || true

if command -v trufflehog &>/dev/null && find "$API_LEAK_DIR" -type f -size +0c 2>/dev/null | grep -q .; then
    log_step "Verifying API leak artifacts with trufflehog..."
    run_with_timeout 180 trufflehog filesystem "$API_LEAK_DIR" \
        --json \
        --no-update \
        --only-verified \
        > "$API_LEAK_TRUFFLEHOG" 2>/dev/null || true
    log_done "verified API secrets: $(wc -l < "$API_LEAK_TRUFFLEHOG" 2>/dev/null || echo 0)"
else
    log_warn "trufflehog not installed or API leak artifacts empty — skipping verified secret pass"
fi

API_LEAK_CANDIDATE_COUNT=$(wc -l < "$API_LEAK_CANDIDATES" 2>/dev/null | tr -d ' ' || echo 0)
API_LEAK_VERIFIED_COUNT=$(wc -l < "$API_LEAK_TRUFFLEHOG" 2>/dev/null | tr -d ' ' || echo 0)
POSTMAN_LINE_COUNT=$(wc -l < "$POSTMAN_LEAKS" 2>/dev/null | tr -d ' ' || echo 0)
POSTLEAKS_URL_COUNT=$(wc -l < "$POSTLEAKS_URLS" 2>/dev/null | tr -d ' ' || echo 0)
SWAGGER_LINE_COUNT=$(wc -l < "$SWAGGER_LEAKS" 2>/dev/null | tr -d ' ' || echo 0)
API_LEAK_PHASE_STATUS="skipped"
[ -n "$API_LEAK_TARGET" ] && API_LEAK_PHASE_STATUS="ok"
record_recon_phase \
    api_leak_detection \
    "$API_LEAK_PHASE_STATUS" \
    "recon/${RECON_TARGET_KEY}/exposure/api_leak_candidates.txt" \
    "$API_LEAK_CANDIDATE_COUNT" \
    "domain-keyed public API leak signal; raw candidates remain for AI review"

emit_claude_hint \
    phase                api_leak_detection \
    postman_lines        "$POSTMAN_LINE_COUNT" \
    postleaks_urls       "$POSTLEAKS_URL_COUNT" \
    swagger_lines        "$SWAGGER_LINE_COUNT" \
    leak_candidates      "$API_LEAK_CANDIDATE_COUNT" \
    verified_secrets     "$API_LEAK_VERIFIED_COUNT"
emit_claude_hint_actions \
    "review recon/${RECON_TARGET_KEY}/exposure/api_leak_candidates.txt; prioritize imported Postman collections and OpenAPI specs" \
    "if verified_secrets > 0, inspect recon/${RECON_TARGET_KEY}/exposure/api_leak_trufflehog_verified.jsonl and validate minimal impact only" \
    "use /secrets-hunt --filesystem recon/${RECON_TARGET_KEY}/exposure/api_leaks/ for a fuller scanner pass when candidates are non-empty"

# ============================================================
# Phase 6.7.5: API Candidate Validation (Denoising)
# ============================================================
echo ""
log_info "Phase 6.7.5: API Candidate Validation"

API_VALIDATION_STATUS="skipped"
if [ -f "tools/validate_api_candidates.sh" ]; then
    log_step "Validating API leak and doc candidates (filtering non-API documents)..."
    API_VALIDATION_STATUS="ok"

    # Validate API leak candidates
    if [ -f "$API_LEAK_CANDIDATES" ] && [ -s "$API_LEAK_CANDIDATES" ]; then
        bash tools/validate_api_candidates.sh \
            "$API_LEAK_CANDIDATES" \
            "$API_LEAK_CANDIDATES" \
            >> "$RECON_DIR/logs/denoising.log" 2>&1 || true

        # Update count after validation
        API_LEAK_CANDIDATE_COUNT=$(wc -l < "${API_LEAK_CANDIDATES}.validated" 2>/dev/null | tr -d ' ' || echo 0)
    fi

    # Validate API doc candidates
    if [ -f "$API_DOC_CANDIDATES" ] && [ -s "$API_DOC_CANDIDATES" ]; then
        bash tools/validate_api_candidates.sh \
            "$API_DOC_CANDIDATES" \
            "$API_DOC_CANDIDATES" \
            >> "$RECON_DIR/logs/denoising.log" 2>&1 || true

        # Update count after validation
        API_DOC_COUNT=$(wc -l < "${API_DOC_CANDIDATES}.validated" 2>/dev/null | tr -d ' ' || echo 0)
    fi

    log_done "API candidate validation complete - see *.validated files"
else
    log_warn "validate_api_candidates.sh not found - skipping API candidate validation"
fi
API_VALIDATED_TOTAL=$((API_LEAK_CANDIDATE_COUNT + API_DOC_COUNT))
record_recon_phase \
    api_candidate_validation \
    "$API_VALIDATION_STATUS" \
    "recon/${RECON_TARGET_KEY}/exposure/*.validated" \
    "$API_VALIDATED_TOTAL" \
    "validated files are denoised views; original candidates are preserved"

# ============================================================
# Phase 6.7.6: OpenAPI Semantic Extraction
# ============================================================
echo ""
log_info "Phase 6.7.6: OpenAPI Semantic Extraction"

OPENAPI_SEMANTIC_STATUS="failed"
OPENAPI_OPERATION_COUNT=0
OPENAPI_AUTH_BOUNDARY_COUNT=0
OPENAPI_PLATFORM_METADATA_COUNT=0
OPENAPI_PLATFORM_HOST_BUDGET="${BBHUNT_OPENAPI_MAX_PLATFORM_HOSTS:-20}"

if python3 "$BASE_DIR/tools/openapi_semantics.py" \
    --repo-root "$BASE_DIR" \
    --target "$TARGET" \
    --max-platform-hosts "$OPENAPI_PLATFORM_HOST_BUDGET" \
    >> "$RECON_DIR/logs/denoising.log" 2>&1; then
    OPENAPI_SEMANTIC_STATUS="$(python3 - "$RECON_DIR/api_specs/summary.json" <<'PY' 2>/dev/null || printf 'partial\n'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload.get("status") or "partial")
PY
)"
    OPENAPI_OPERATION_COUNT=$(wc -l < "$RECON_DIR/api_specs/operations.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
    OPENAPI_AUTH_BOUNDARY_COUNT=$(wc -l < "$RECON_DIR/api_specs/auth_boundary_candidates.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
    OPENAPI_PLATFORM_METADATA_COUNT=$(wc -l < "$RECON_DIR/api_specs/platform_metadata.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
    log_done "OpenAPI operations: $OPENAPI_OPERATION_COUNT; auth boundaries: $OPENAPI_AUTH_BOUNDARY_COUNT"
else
    log_warn "OpenAPI semantic extraction failed — raw API candidates remain available"
fi

record_recon_phase \
    openapi_semantics \
    "$OPENAPI_SEMANTIC_STATUS" \
    "recon/${RECON_TARGET_KEY}/api_specs/summary.json" \
    "$OPENAPI_OPERATION_COUNT" \
    "schema declarations are discovery facts; runtime auth evidence remains required"
emit_claude_hint \
    phase                  openapi_semantics \
    status                 "$OPENAPI_SEMANTIC_STATUS" \
    operations             "$OPENAPI_OPERATION_COUNT" \
    auth_boundaries        "$OPENAPI_AUTH_BOUNDARY_COUNT" \
    platform_metadata      "$OPENAPI_PLATFORM_METADATA_COUNT"
emit_claude_hint_actions \
    "review recon/${RECON_TARGET_KEY}/api_specs/auth_boundary_candidates.jsonl and select high-value operations" \
    "capture anonymous baseline plus controlled auth/role/object differences before promoting a finding"

# ============================================================
# Phase 6.8: Identity and Cloud Intel
# ============================================================
echo ""
log_info "Phase 6.8: Identity and Cloud Intel"

IDENTITY_DIR="$RECON_DIR/exposure/identity_intel"
CLOUD_INTEL_DIR="$RECON_DIR/exposure/cloud"
EMAILS_OUT="$IDENTITY_DIR/emails.txt"
LEAKSEARCH_OUT="$IDENTITY_DIR/leaksearch.txt"
IDENTITY_SUMMARY="$IDENTITY_DIR/summary.md"
CLOUD_ENUM_OUT="$CLOUD_INTEL_DIR/cloud_enum.txt"
CLOUD_KEYWORD="$(printf '%s\n' "$TARGET" | sed -E 's|^https?://||; s|/.*$||; s|^\*\.||; s|:.*$||; s|\..*$||')"

mkdir -p "$IDENTITY_DIR" "$CLOUD_INTEL_DIR"
: > "$EMAILS_OUT"
: > "$LEAKSEARCH_OUT"
: > "$CLOUD_ENUM_OUT"

EMAILFINDER_STATUS="missing"
EMAILFINDER_SCRIPT="$SHARED_TOOLS_DIR/emailfinder/emailfinder.py"
if [ "$TARGET_KIND" = "domain" ] && [ -f "$EMAILFINDER_SCRIPT" ]; then
    log_step "Running emailfinder via Osmedeus toolsDir..."
    if run_with_timeout 120 python3 "$EMAILFINDER_SCRIPT" -d "$TARGET" > "$EMAILS_OUT" 2>/dev/null; then
        EMAILFINDER_STATUS="ok"
    else
        EMAILFINDER_STATUS="partial"
    fi
elif [ "$TARGET_KIND" = "domain" ] && command -v emailfinder &>/dev/null; then
    log_step "Running emailfinder..."
    if run_with_timeout 120 emailfinder -d "$TARGET" > "$EMAILS_OUT" 2>/dev/null; then
        EMAILFINDER_STATUS="ok"
    else
        EMAILFINDER_STATUS="partial"
    fi
else
    log_warn "emailfinder not found — skipping identity email discovery"
fi

LEAKSEARCH_STATUS="missing"
LEAKSEARCH_SCRIPT="$SHARED_TOOLS_DIR/LeakSearch/LeakSearch.py"
LEAKSEARCH_PY="$SHARED_TOOLS_DIR/LeakSearch/venv/bin/python3"
[ -x "$LEAKSEARCH_PY" ] || LEAKSEARCH_PY="python3"
if [ "$TARGET_KIND" = "domain" ] && [ -f "$LEAKSEARCH_SCRIPT" ]; then
    log_step "Running LeakSearch via Osmedeus toolsDir..."
    if run_with_timeout 180 "$LEAKSEARCH_PY" "$LEAKSEARCH_SCRIPT" -k "$TARGET" -o "$LEAKSEARCH_OUT" > "$IDENTITY_DIR/leaksearch.log" 2>&1; then
        LEAKSEARCH_STATUS="ok"
    else
        LEAKSEARCH_STATUS="partial"
    fi
else
    log_warn "LeakSearch not found under $SHARED_TOOLS_DIR/LeakSearch — skipping leak-search hints"
fi

CLOUD_ENUM_STATUS="missing"
CLOUD_ENUM_CMD=()
CLOUD_ENUM_BIN="$(command -v cloud_enum 2>/dev/null || true)"
CLOUD_ENUM_SCRIPT="$SHARED_TOOLS_DIR/cloud_enum/cloud_enum.py"
CLOUD_ENUM_PY="$SHARED_TOOLS_DIR/cloud_enum/venv/bin/python3"
if [ -n "$CLOUD_ENUM_BIN" ]; then
    CLOUD_ENUM_CMD=("$CLOUD_ENUM_BIN")
elif [ -f "$CLOUD_ENUM_SCRIPT" ]; then
    [ -x "$CLOUD_ENUM_PY" ] || CLOUD_ENUM_PY="python3"
    CLOUD_ENUM_CMD=("$CLOUD_ENUM_PY" "$CLOUD_ENUM_SCRIPT")
fi

if [ "$TARGET_KIND" = "domain" ] && [ -n "$CLOUD_KEYWORD" ]; then
    if [ "${#CLOUD_ENUM_CMD[@]}" -gt 0 ]; then
        log_step "Running cloud_enum keyword sweep: $CLOUD_KEYWORD"
        if run_with_timeout 180 "${CLOUD_ENUM_CMD[@]}" -k "$CLOUD_KEYWORD" -t 5 -qs -l "$CLOUD_ENUM_OUT" > "$CLOUD_INTEL_DIR/cloud_enum.log" 2>&1; then
            CLOUD_ENUM_STATUS="ok"
        else
            CLOUD_ENUM_STATUS="partial"
        fi
    else
        log_warn "cloud_enum not found in PATH or $SHARED_TOOLS_DIR/cloud_enum — skipping cloud keyword sweep"
    fi
else
    log_warn "cloud_enum skipped because target is not a domain or keyword is empty"
fi

EMAIL_COUNT=$(wc -l < "$EMAILS_OUT" 2>/dev/null | tr -d ' ' || echo 0)
LEAKSEARCH_COUNT=$(wc -l < "$LEAKSEARCH_OUT" 2>/dev/null | tr -d ' ' || echo 0)
CLOUD_ENUM_COUNT=$(wc -l < "$CLOUD_ENUM_OUT" 2>/dev/null | tr -d ' ' || echo 0)

{
    echo "# Identity and Cloud Intel — $TARGET"
    echo ""
    echo "These artifacts are recon signals, not vulnerability conclusions."
    echo ""
    echo "- emailfinder: $EMAILFINDER_STATUS ($EMAIL_COUNT non-empty lines)"
    echo "- LeakSearch: $LEAKSEARCH_STATUS ($LEAKSEARCH_COUNT non-empty lines)"
    echo "- cloud_enum: $CLOUD_ENUM_STATUS ($CLOUD_ENUM_COUNT lines, keyword: $CLOUD_KEYWORD)"
    echo "- emails: \`recon/${RECON_TARGET_KEY}/exposure/identity_intel/emails.txt\`"
    echo "- leaksearch: \`recon/${RECON_TARGET_KEY}/exposure/identity_intel/leaksearch.txt\`"
    echo "- cloud_enum: \`recon/${RECON_TARGET_KEY}/exposure/cloud/cloud_enum.txt\`"
    echo ""
    echo "Next hypotheses:"
    echo "- Use emails for SSO, invite, reset-flow, and tenant-enumeration hypotheses only."
    echo "- If LeakSearch has hits, perform attribution/minimal validation; never auto-login or credential-stuff."
    echo "- Treat cloud_enum hits as candidates; verify ownership and permissions before any deeper cloud testing."
} > "$IDENTITY_SUMMARY"

log_done "emailfinder: $EMAIL_COUNT lines ($EMAILFINDER_STATUS)"
log_done "LeakSearch: $LEAKSEARCH_COUNT lines ($LEAKSEARCH_STATUS)"
log_done "cloud_enum: $CLOUD_ENUM_COUNT lines ($CLOUD_ENUM_STATUS)"

IDENTITY_TOTAL=$((EMAIL_COUNT + LEAKSEARCH_COUNT + CLOUD_ENUM_COUNT))
record_recon_phase \
    identity_cloud_intel \
    ok \
    "recon/${RECON_TARGET_KEY}/exposure/identity_intel/summary.md" \
    "$IDENTITY_TOTAL" \
    "identity/cloud artifacts are hypothesis seeds, not credential-use actions"

emit_claude_hint \
    phase                identity_cloud_intel \
    emailfinder_status   "$EMAILFINDER_STATUS" \
    emails               "$EMAIL_COUNT" \
    leaksearch_status    "$LEAKSEARCH_STATUS" \
    leaksearch_lines     "$LEAKSEARCH_COUNT" \
    cloud_enum_status    "$CLOUD_ENUM_STATUS" \
    cloud_enum_lines     "$CLOUD_ENUM_COUNT"
emit_claude_hint_actions \
    "review recon/${RECON_TARGET_KEY}/exposure/identity_intel/summary.md before SSO/reset/invite hypotheses" \
    "review recon/${RECON_TARGET_KEY}/exposure/cloud/cloud_enum.txt only as candidate cloud evidence" \
    "if identity/cloud hits are meaningful, carry them into /intel or /cloud-recon for focused follow-up"

# ============================================================
# Phase 7: Parameter Discovery
# ============================================================
echo ""
log_info "Phase 7: Parameter Discovery"

PARAM_URLS_FOR_DISCOVERY="$RECON_DIR/urls/with_params_analysis.txt"
build_filtered_first_backstop \
    "$RECON_DIR/urls/with_params_filtered.txt" \
    "$RECON_DIR/urls/with_params.txt" \
    "$PARAM_URLS_FOR_DISCOVERY"
PARAM_DISCOVERY_STATUS="skipped"

if [ -s "$PARAM_URLS_FOR_DISCOVERY" ]; then
    PARAM_DISCOVERY_STATUS="ok"
    log_step "Extracting parameters from collected URLs..."

    # Extract parameter names (macOS compatible - no grep -P)
    sed -nE 's/.*[?&]([^=&]+)=.*/\1/p' "$PARAM_URLS_FOR_DISCOVERY" 2>/dev/null \
        | sort | uniq -c | sort -rn > "$RECON_DIR/params/param_frequency.txt" 2>/dev/null || true

    # Get unique param names
    awk '{print $2}' "$RECON_DIR/params/param_frequency.txt" > "$RECON_DIR/params/unique_params.txt" 2>/dev/null || true
    log_done "Unique parameters: $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

    # Flag interesting params (potential injection points)
    grep -iE '(url|redirect|next|return|callback|dest|file|path|page|template|include|src|ref|uri|link|target|goto|out|view|dir|show|site|domain|rurl|return_to|continue|window|data|reference|to|img|load|doc|download)' \
        "$RECON_DIR/params/unique_params.txt" > "$RECON_DIR/params/interesting_params.txt" 2>/dev/null || true

    if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
        log_warn "Interesting params (potential vulns): $(wc -l < "$RECON_DIR/params/interesting_params.txt")"
        echo "      Params: $(head -5 "$RECON_DIR/params/interesting_params.txt" | tr '\n' ', ')"
    fi
else
    log_warn "No parameterized URLs found — skipping"
fi

UNIQUE_PARAMS=$(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null | tr -d ' ' || echo 0)
INTERESTING_PARAMS=$(wc -l < "$RECON_DIR/params/interesting_params.txt" 2>/dev/null | tr -d ' ' || echo 0)
record_recon_phase \
    param_disco \
    "$PARAM_DISCOVERY_STATUS" \
    "recon/${RECON_TARGET_KEY}/params/unique_params.txt" \
    "$UNIQUE_PARAMS" \
    "parameter input uses filtered-first ordering plus raw with_params.txt backstop"
emit_claude_hint \
    phase                param_disco \
    unique_params        "$UNIQUE_PARAMS" \
    interesting_params   "$INTERESTING_PARAMS" \
    note                 "extraction only — not active hidden-param mining"
emit_claude_hint_actions \
    "bash tools/param_discovery.sh -l recon/${RECON_TARGET_KEY}/live/urls.txt   # active arjun/x8 mining" \
    "review interesting_params.txt for redirect/url/path candidates"

# ============================================================
# Phase 8: CI/CD Workflow Scan (auto-detect GitHub org)
# ============================================================
log_info "Phase 8: CI/CD Workflow Scan"

GITHUB_ORGS=""
CICD_SCANNER="$(dirname "$0")/cicd_scanner.sh"

# Extract github.com/<org> patterns from recon data
for f in "$RECON_DIR/live/httpx_full.txt" "$RECON_DIR/js/endpoints.txt" "$RECON_DIR/urls/all.txt"; do
    if [ -f "$f" ]; then
        GITHUB_ORGS="$GITHUB_ORGS $(grep -oP 'github\.com/\K[a-zA-Z0-9_-]+' "$f" 2>/dev/null || true)"
    fi
done

# Deduplicate and limit to 5. Append `|| true` so an empty pipeline under
# `set -euo pipefail` (grep -v returning 1 on empty input) does not kill recon.
GITHUB_ORGS=$(echo "$GITHUB_ORGS" | tr ' ' '\n' | grep -v '^$' | sort -u | head -5 || true)

if [ -n "$GITHUB_ORGS" ] && [ -x "$CICD_SCANNER" ] && command -v sisakulint &>/dev/null; then
    for ORG in $GITHUB_ORGS; do
        log_info "CI/CD scan: org:$ORG"
        bash "$CICD_SCANNER" "org:$ORG" --output-dir "$RECON_DIR/cicd/$ORG/" || true
    done
else
    if [ -z "$GITHUB_ORGS" ]; then
        log_warn "GitHub org not detected — CI/CD scan skipped"
    elif ! command -v sisakulint &>/dev/null; then
        log_warn "sisakulint not installed — CI/CD scan skipped"
    fi
fi

CICD_ORGS_FOUND=$(printf '%s\n' "$GITHUB_ORGS" | grep -cE '^[a-zA-Z0-9_-]+' 2>/dev/null || true)
[ -n "$CICD_ORGS_FOUND" ] || CICD_ORGS_FOUND=0
CICD_PHASE_STATUS="skipped"
if [ -n "$GITHUB_ORGS" ] && [ -x "$CICD_SCANNER" ] && command -v sisakulint >/dev/null 2>&1; then
    CICD_PHASE_STATUS="ok"
fi
record_recon_phase \
    cicd \
    "$CICD_PHASE_STATUS" \
    "recon/${RECON_TARGET_KEY}/cicd/" \
    "$CICD_ORGS_FOUND" \
    "CI/CD workflow scan runs only when GitHub orgs and sisakulint are available"
emit_claude_hint \
    phase                cicd \
    orgs_scanned         "$CICD_ORGS_FOUND" \
    sisakulint_present   "$(command -v sisakulint >/dev/null 2>&1 && echo true || echo false)"
emit_claude_hint_actions \
    "review findings/cicd/<org>/scan_results.txt for pull_request_target / unsafe-context risks" \
    "if no GitHub orgs were auto-detected, leave CI/CD as no cached signal rather than tested clean"

# ============================================================
# Routing candidates: existing evidence only, no new requests
# ============================================================
ROUTING_CANDIDATE_STATUS="ok"
if ! python3 "$BASE_DIR/tools/recon_candidates.py" \
    --repo-root "$BASE_DIR" \
    --target "$TARGET" \
    > "$RECON_DIR/logs/recon_candidates.json" 2>&1; then
    ROUTING_CANDIDATE_STATUS="partial"
    log_warn "Host/AI routing candidate generation failed; raw recon remains available"
fi
HOST_PIVOT_CANDIDATES=$(wc -l < "$RECON_DIR/exposure/host_pivot_candidates.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
AI_ASSET_CANDIDATES=$(wc -l < "$RECON_DIR/exposure/ai_asset_candidates.jsonl" 2>/dev/null | tr -d ' ' || echo 0)
record_recon_phase \
    routing_candidates \
    "$ROUTING_CANDIDATE_STATUS" \
    "recon/${RECON_TARGET_KEY}/exposure/" \
    "$((HOST_PIVOT_CANDIDATES + AI_ASSET_CANDIDATES))" \
    "builds evidence-backed candidates only; Host/SNI/VirtualHost and AI behavior validation remain Autopilot lanes"
emit_claude_hint \
    phase                 routing_candidates \
    host_pivot_candidates "$HOST_PIVOT_CANDIDATES" \
    ai_asset_candidates   "$AI_ASSET_CANDIDATES" \
    active_probing        "false"
emit_claude_hint_actions \
    "review Host pivot candidates only with default-vhost/CDN/error-page controls" \
    "route AI candidates through web-llm-tool-chains before behavioral validation"

# ============================================================
# Optional post-run storage guard
# ============================================================
post_compress_raw_recon_urls "$RECON_DIR"

# Surface index/projection 是可重建派生视图。收尾失败不能抹掉已完成的
# recon artifact，也不能把本次 recon 伪装成 tested-clean；后续显式
# `/surface --refresh` 可恢复。
SURFACE_FINALIZER_STATUS="ok"
if ! python3 "$BASE_DIR/tools/surface_finalizer.py" \
    --repo-root "$BASE_DIR" \
    --target "$TARGET" \
    --json; then
    SURFACE_FINALIZER_STATUS="failed"
    log_warn "Surface finalizer failed; raw recon remains complete. Run python3 tools/surface.py --target $TARGET --refresh to retry."
else
    log_done "Surface exact index and bounded projection refreshed"
fi
record_recon_phase \
    surface_finalize \
    "$SURFACE_FINALIZER_STATUS" \
    "state/${RECON_TARGET_KEY}/surface-projection.json" \
    0 \
    "derived cache only; failure is recoverable and does not close attack surface"

RECON_ELAPSED_SECONDS=$(( $(date +%s) - RECON_STARTED_EPOCH ))
RECON_BUDGET_STATUS="ok"
[ "$RECON_ELAPSED_SECONDS" -gt "$RECON_SOFT_BUDGET_SECONDS" ] && RECON_BUDGET_STATUS="partial"
record_recon_phase \
    run_budget \
    "$RECON_BUDGET_STATUS" \
    "recon/${RECON_TARGET_KEY}/recon_manifest.jsonl" \
    0 \
    "elapsed_seconds=${RECON_ELAPSED_SECONDS}; soft_budget_seconds=${RECON_SOFT_BUDGET_SECONDS}; soft target never deletes raw surface"
emit_claude_hint \
    phase               run_budget \
    profile             "$RECON_PROFILE" \
    elapsed_seconds     "$RECON_ELAPSED_SECONDS" \
    soft_budget_seconds "$RECON_SOFT_BUDGET_SECONDS" \
    soft_budget_status  "$RECON_BUDGET_STATUS"

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================="
echo "  Recon Summary — $TARGET"
echo "  Completed: $(date)"
echo "============================================="
echo ""
echo "  Subdomains:        $(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/live/urls.txt" ] && \
echo "  Live hosts:        $(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/ports/open_ports_all.txt" ] && \
echo "  Open ports:        $(wc -l < "$RECON_DIR/ports/open_ports_all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/all.txt" ] && \
echo "  URLs collected:    $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/all_filtered.txt" ] && \
echo "  URLs filtered:     $(wc -l < "$RECON_DIR/urls/all_filtered.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/with_params.txt" ] && \
echo "  Parameterized:     $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/api_endpoints.txt" ] && \
echo "  API endpoints:     $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/api_endpoints_filtered.txt" ] && \
echo "  API endpoints filtered: $(wc -l < "$RECON_DIR/urls/api_endpoints_filtered.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/js/endpoints.txt" ] && \
echo "  JS endpoints:      $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/params/unique_params.txt" ] && \
echo "  Unique params:     $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/exposure/api_doc_candidates.txt" ] && \
echo "  API doc candidates: $(wc -l < "$RECON_DIR/exposure/api_doc_candidates.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/exposure/cloud_storage_candidates.txt" ] && \
echo "  Cloud candidates:  $(wc -l < "$RECON_DIR/exposure/cloud_storage_candidates.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_MANIFEST" ] && \
echo "  Phase manifest:    $RECON_MANIFEST"

[ -d "$RECON_DIR/cicd" ] && \
echo "  CI/CD findings:   $(find "$RECON_DIR/cicd" -name 'scan_results.txt' -exec grep -cP '\.github/workflows/' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')"

echo ""
echo "  Results: $RECON_DIR/"
echo "============================================="
echo ""
echo "  Next: Build the AI evidence pack, then choose the highest-value hypothesis"
echo "    python3 tools/surface.py --target $TARGET"
echo "    python3 tools/context_pack.py --target $TARGET"
echo "    # Optional breadth sensor after AI/browser/source review:"
echo "    python3 tools/hunt.py --target $TARGET --scan-only --quick"
echo "============================================="
