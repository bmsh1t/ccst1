#!/usr/bin/env bash
# =============================================================================
# archive_root_clutter.sh — safely move top-level generated clutter into archive/
#
# Default is dry-run. Use --apply to move files. Nothing is deleted.
# A manifest is written for every run so moved files can be restored.
# =============================================================================
set -euo pipefail

MODE="dry-run"
RESTORE_MANIFEST=""
NO_GZIP=0
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_BASE="archive/root-clutter/${STAMP}"

usage() {
  cat <<'EOF'
Usage:
  tools/archive_root_clutter.sh [--dry-run]
  tools/archive_root_clutter.sh --apply [--no-gzip]
  tools/archive_root_clutter.sh --restore archive/root-clutter/<ts>/MANIFEST.tsv

What it archives from repo root:
  - top-level *.log and campaign/recon logs -> logs/
  - FINAL_*.md, *_REPORT.md, *_SUMMARY.md, checkpoints/decisions -> reports/
  - mb*.txt, yuembb*.txt, target list files -> target-lists/
  - top-level one-off batch/analyze/extract/final/check scripts -> scripts/
  - selected scratch markdown/html artifacts -> scratch/

It does NOT touch core dirs such as commands/, agents/, skills/, tools/, docs/,
recon/, findings/, evidence/, reports/, output/, memory/, state/, tests/, etc.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run"; shift ;;
    --apply) MODE="apply"; shift ;;
    --no-gzip) NO_GZIP=1; shift ;;
    --restore) RESTORE_MANIFEST="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() { printf '%s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

is_core_file() {
  case "$1" in
    AGENTS.md|CLAUDE.md|README.md|CHANGELOG.md|FAQ.md|TERMS.md|LICENSE|SKILL.md|hunting-plan.md) return 0 ;;
    install.sh|install_tools.sh|requirements.txt|requirements-dev.txt|pytest.ini|config.json|config.example.json|logo.png) return 0 ;;
    .gitignore) return 0 ;;
  esac
  return 1
}

category_for() {
  local f="$1"
  is_core_file "$f" && return 1

  case "$f" in
    *.log|fofamap.log|recon_*.log|hunt_*.log) echo "logs"; return 0 ;;
  esac

  case "$f" in
    FINAL_*.md|*_FINAL*.md|*_REPORT.md|*_SUMMARY.md|*_STATUS.md|*_CHECKPOINT.md|*_DECISION.md|*_CONFIRMATION.md|*_CONCLUSION.md|PROJECT_*|DELIVERY.md|UPDATE_DELIVERABLES.md|AUTOPILOT_DECISION.md|ATTACK_PATHS_REMAINING.md|validation_report.md|summary_*targets.md)
      echo "reports"; return 0 ;;
  esac

  case "$f" in
    mb*.txt|baji*.txt|bajin.txt|yuembb*.txt|yuenewnew*.txt|yuenan.md|wp_targets.txt|priority_targets.txt|high_value_targets.txt|httpx_*.txt|nuclei_*.txt|fia.gov.pk.txt)
      echo "target-lists"; return 0 ;;
  esac

  case "$f" in
    batch_*.sh|analyze_*.sh|extract_*.sh|final_*.sh|check_*.sh|launch_*.sh|prepare_*.sh|generate_attack_surface_report.sh|identify_remaining_tasks.sh|verify_all_systems.sh|fix_api_endpoint_regeneration.py|analyze_top_priority_denoising.py)
      echo "scripts"; return 0 ;;
  esac

  case "$f" in
    debug_*.html|fofa_*queries.md|nextplan.md|plana.md|fmb.md|ctf_checkpoint.md|CTF_CHECKPOINT.md|README_DENOISING.md|README_QUICKSTART.md|QUICKSTART.md|TROUBLESHOOTING.md|ULTRACODE_LESSONS_LEARNED.md)
      echo "scratch"; return 0 ;;
  esac

  return 1
}

restore_from_manifest() {
  local manifest="$1"
  [[ -n "$manifest" && -f "$manifest" ]] || { echo "Restore manifest not found: $manifest" >&2; exit 2; }
  local restored=0 skipped=0
  while IFS=$'\t' read -r action category original archived final_path note; do
    [[ "$action" == "MOVE" ]] || continue
    [[ -n "$original" && -n "$final_path" ]] || continue
    if [[ ! -e "$final_path" ]]; then
      # If the archived file was gzipped, final_path should include .gz. Restore as .gz;
      # the operator can gunzip manually if desired.
      warn "missing archived path, skip: $final_path"
      skipped=$((skipped + 1))
      continue
    fi
    if [[ -e "$original" ]]; then
      warn "destination exists, skip: $original"
      skipped=$((skipped + 1))
      continue
    fi
    mkdir -p "$(dirname -- "$original")"
    mv -- "$final_path" "$original"
    restored=$((restored + 1))
  done < "$manifest"
  log "Restore complete: restored=$restored skipped=$skipped"
}

if [[ -n "$RESTORE_MANIFEST" ]]; then
  restore_from_manifest "$RESTORE_MANIFEST"
  exit 0
fi

candidates=()
while IFS= read -r -d '' path; do
  f="${path#./}"
  category="$(category_for "$f" || true)"
  [[ -n "$category" ]] || continue
  candidates+=("$category|$f")
done < <(find . -maxdepth 1 -type f -print0)

if [[ ${#candidates[@]} -eq 0 ]]; then
  log "No top-level clutter candidates found."
  exit 0
fi

log "Mode: $MODE"
log "Archive base: $ARCHIVE_BASE"
log "Candidates: ${#candidates[@]}"

if [[ "$MODE" == "dry-run" ]]; then
  for item in "${candidates[@]}"; do
    category="${item%%|*}"
    f="${item#*|}"
    printf 'DRY-RUN\t%s\t%s\t%s/%s/%s\n' "$category" "$f" "$ARCHIVE_BASE" "$category" "$f"
  done | sort
  log "\nNo files moved. Re-run with --apply to archive."
  exit 0
fi

manifest="$ARCHIVE_BASE/MANIFEST.tsv"
mkdir -p "$ARCHIVE_BASE"/{logs,reports,target-lists,scripts,scratch}
printf 'ACTION\tCATEGORY\tORIGINAL\tARCHIVED\tFINAL_PATH\tNOTE\n' > "$manifest"

moved=0
gzipped=0
for item in "${candidates[@]}"; do
  category="${item%%|*}"
  f="${item#*|}"
  dest="$ARCHIVE_BASE/$category/$f"
  final_path="$dest"
  mkdir -p "$(dirname -- "$dest")"
  mv -- "$f" "$dest"
  note="moved"
  moved=$((moved + 1))

  if [[ "$category" == "logs" && "$NO_GZIP" -eq 0 && -s "$dest" ]] && command -v gzip >/dev/null 2>&1; then
    gzip -n -- "$dest"
    final_path="$dest.gz"
    note="moved+gzipped"
    gzipped=$((gzipped + 1))
  fi

  printf 'MOVE\t%s\t%s\t%s\t%s\t%s\n' "$category" "$f" "$dest" "$final_path" "$note" >> "$manifest"
done

log "Archive complete: moved=$moved gzipped=$gzipped"
log "Manifest: $manifest"
log "Restore: tools/archive_root_clutter.sh --restore $manifest"
