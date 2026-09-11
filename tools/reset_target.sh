#!/bin/bash
# Reset local state for a single target so the next run starts from scratch.

set -euo pipefail

SCRIPT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${BBHUNT_BASE_DIR:-${SCRIPT_REPO_ROOT}}"
TARGET=""
PRINT_ONLY=false

while [[ $# -gt 0 ]]; do
    case "${1}" in
        --print-only|--dry-run)
            PRINT_ONLY=true
            ;;
        --help|-h)
            cat <<'EOF'
Usage:
  bash tools/reset_target.sh <target> [--print-only]

Deletes every target-scoped owner state location. The list is derived
from tools/target_paths.py::target_scoped_owner_roots — the single
source of truth — so a new owner path is covered automatically:

  - recon/, findings/, reports/, state/, evidence/ (per storage key)
  - memory/evidence/<key>/          (per-target Evidence Ledger)
  - memory/goals/targets/<key>.json (per-target goal memory)
  - memory/goals/active.json        (only when it points at this target)
  - targets/<key>/sessions/
  - hunt-memory/targets|guards/<key>.json
  - journal session_summary rows for this target (row filter; the
    global journal/patterns/audit files themselves are preserved)

Global cross-target files are preserved by design.

Environment variables:
  BBHUNT_BASE_DIR   Override the project root (mainly for tests)
  HUNT_MEMORY_DIR   Override the hunt-memory directory
EOF
            exit 0
            ;;
        *)
            if [[ -z "${TARGET}" ]]; then
                TARGET="${1}"
            else
                echo "Unknown option: ${1}" >&2
                exit 2
            fi
            ;;
    esac
    shift
done

if [[ -z "${TARGET}" ]]; then
    echo "Usage: bash tools/reset_target.sh <target> [--print-only]" >&2
    exit 2
fi

mapfile -t RESET_INFO < <(
    BASE_DIR="${BASE_DIR}" IMPORT_ROOT="${SCRIPT_REPO_ROOT}" TARGET="${TARGET}" python3 - <<'PY'
import json
import os
import sys
from pathlib import Path

base_dir = os.environ["BASE_DIR"]
import_root = os.environ["IMPORT_ROOT"]
target = os.environ["TARGET"]
sys.path.insert(0, import_root)

from tools.target_paths import (
    active_goal_pointer_path,
    canonical_target_value,
    target_scoped_owner_roots,
    target_storage_key,
)

canonical = canonical_target_value(target)
storage_key = target_storage_key(target)

print(f"CANONICAL={canonical}")
print(f"STORAGE_KEY={storage_key}")
print(f"JOURNAL={Path(os.environ.get('HUNT_MEMORY_DIR', str(Path(base_dir) / 'hunt-memory'))) / 'journal.jsonl'}")

# Conditional active-goal pointer: reset it only when it names this target.
active_pointer = Path(active_goal_pointer_path(base_dir))
if active_pointer.is_file():
    try:
        payload = json.loads(active_pointer.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        payload = {}
    if str(payload.get("target") or "") == canonical:
        print(f"PATH={active_pointer}")

for name, path in target_scoped_owner_roots(base_dir, target).items():
    print(f"PATH={path}")
PY
)

CANONICAL_TARGET=""
STORAGE_KEY=""
JOURNAL=""
PATHS_TO_DELETE=()

for line in "${RESET_INFO[@]}"; do
    case "${line}" in
        CANONICAL=*) CANONICAL_TARGET="${line#CANONICAL=}" ;;
        STORAGE_KEY=*) STORAGE_KEY="${line#STORAGE_KEY=}" ;;
        JOURNAL=*) JOURNAL="${line#JOURNAL=}" ;;
        PATH=*) PATHS_TO_DELETE+=("${line#PATH=}") ;;
    esac
done

echo "Reset target: ${CANONICAL_TARGET}"
echo "Storage key:  ${STORAGE_KEY}"
echo ""
echo "Target-scoped owner paths:"
for path in "${PATHS_TO_DELETE[@]}"; do
    echo "  - ${path}"
done
echo ""
echo "Global memory files preserved (per-target journal rows are filtered):"
echo "  - ${JOURNAL}"

if [[ "${PRINT_ONLY}" == "true" ]]; then
    echo ""
    echo "[dry-run] No files were deleted."
    exit 0
fi

DELETED=0
for path in "${PATHS_TO_DELETE[@]}"; do
    if [[ -e "${path}" ]]; then
        rm -rf "${path}"
        echo "[deleted] ${path}"
        DELETED=$((DELETED + 1))
    else
        echo "[skip] ${path} (not found)"
    fi
done

# Filter per-target session_summary rows from the global journal. The journal
# itself is global cross-target memory and is preserved; only this target's
# rows go, so the next round's resume/latest-session projections start clean.
if [[ -n "${JOURNAL}" && -f "${JOURNAL}" ]]; then
    FILTERED=$(python3 - "${JOURNAL}" "${CANONICAL_TARGET}" <<'PY'
import json
import sys

journal_path, target = sys.argv[1], sys.argv[2]
kept = []
removed = 0
with open(journal_path, encoding="utf-8") as handle:
    for line in handle:
        stripped = line.strip()
        if not stripped:
            continue
        if target in line:
            try:
                entry = json.loads(stripped)
            except ValueError:
                kept.append(line.rstrip("\n"))
                continue
            if entry.get("vuln_class") == "session_summary":
                removed += 1
                continue
        kept.append(line.rstrip("\n"))
with open(journal_path, "w", encoding="utf-8") as handle:
    for line in kept:
        handle.write(line + "\n")
print(removed)
PY
    )
    if [[ "${FILTERED}" != "0" ]]; then
        echo "[filtered] ${FILTERED} session_summary row(s) for ${CANONICAL_TARGET} from ${JOURNAL}"
    fi
fi

echo ""
echo "Done. Deleted ${DELETED} target-scoped path(s)."
echo "Next run starts fresh for ${CANONICAL_TARGET}; global cross-target memory stays intact."
