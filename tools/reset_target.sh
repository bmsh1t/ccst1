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

By default this deletes target-scoped local state:
  - recon/<target-storage-key>/
  - findings/<target-storage-key>/
  - reports/<target-storage-key>/
  - state/<target-storage-key>/
  - targets/<target-storage-key>/sessions/
  - hunt-memory/targets/<target>.json
  - hunt-memory/guards/<target>.json

Global memory files are preserved:
  - hunt-memory/journal.jsonl
  - hunt-memory/patterns.jsonl
  - hunt-memory/audit.jsonl

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
import os
import sys
from pathlib import Path

base_dir = os.environ["BASE_DIR"]
import_root = os.environ["IMPORT_ROOT"]
target = os.environ["TARGET"]
sys.path.insert(0, import_root)

from memory.target_profile import default_memory_dir, target_filename
from tools.target_paths import canonical_target_value, target_storage_key

canonical = canonical_target_value(target)
storage_key = target_storage_key(target)
memory_dir = Path(default_memory_dir(base_dir))
profile_name = target_filename(target)

paths = [
    Path(base_dir) / "recon" / storage_key,
    Path(base_dir) / "findings" / storage_key,
    Path(base_dir) / "reports" / storage_key,
    Path(base_dir) / "state" / storage_key,
    Path(base_dir) / "targets" / storage_key / "sessions",
    memory_dir / "targets" / profile_name,
    memory_dir / "guards" / profile_name,
]

print(f"CANONICAL={canonical}")
print(f"STORAGE_KEY={storage_key}")
print(f"MEMORY_DIR={memory_dir}")
for path in paths:
    print(f"PATH={path}")
PY
)

CANONICAL_TARGET=""
STORAGE_KEY=""
MEMORY_DIR=""
PATHS_TO_DELETE=()

for line in "${RESET_INFO[@]}"; do
    case "${line}" in
        CANONICAL=*) CANONICAL_TARGET="${line#CANONICAL=}" ;;
        STORAGE_KEY=*) STORAGE_KEY="${line#STORAGE_KEY=}" ;;
        MEMORY_DIR=*) MEMORY_DIR="${line#MEMORY_DIR=}" ;;
        PATH=*) PATHS_TO_DELETE+=("${line#PATH=}") ;;
    esac
done

echo "Reset target: ${CANONICAL_TARGET}"
echo "Storage key:  ${STORAGE_KEY}"
echo "Memory dir:   ${MEMORY_DIR}"
echo ""
echo "Target-scoped paths:"
for path in "${PATHS_TO_DELETE[@]}"; do
    echo "  - ${path}"
done
echo ""
echo "Global memory files preserved:"
echo "  - ${MEMORY_DIR}/journal.jsonl"
echo "  - ${MEMORY_DIR}/patterns.jsonl"
echo "  - ${MEMORY_DIR}/audit.jsonl"

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

echo ""
echo "Done. Deleted ${DELETED} target-scoped path(s)."
echo "Next run starts fresh for ${CANONICAL_TARGET}, but global journal/pattern memory stays intact."
