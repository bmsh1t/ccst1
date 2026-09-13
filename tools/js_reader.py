#!/usr/bin/env python3
"""Prepare local materials for the JS static-reading agent.

Responsibilities:
  1) Collect cached JS file paths from recon output
  2) Skip vendor / minified / oversize files
  3) Reuse source_intel route/marker observations when present
  4) Read recon-extracted endpoints / secrets / JS URL lists
  5) Write materials.json plus a markdown summary for the js-reader agent

This module does not call an LLM. LLM reasoning happens through
agents/js-reader.md in the main Claude Code conversation with the Read tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.target_paths import target_storage_key
    from tools.surface_source_intel import load_source_intel
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import target_storage_key
    from surface_source_intel import load_source_intel

TOOLS_DIR = Path(__file__).resolve().parent
BASE_DIR = TOOLS_DIR.parent

DEFAULT_MAX_FILES = 50
DEFAULT_MAX_FILE_BYTES = 200 * 1024  # 200 KB
READABLE_SOURCE_SUFFIXES = {".js", ".mjs", ".cjs", ".map", ".ts", ".tsx", ".vue"}

VENDOR_PATTERNS = (
    "react", "react-dom", "vue", "angular", "lodash", "moment", "jquery",
    "chunk-vendor", "vendors~", "polyfill", "runtime~", "bootstrap.min",
    "core-js", "regenerator-runtime", "axios.min", "zone.min", "rxjs.min",
)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_target(target: str) -> str:
    return target_storage_key(target)


def _looks_like_vendor(path: Path) -> bool:
    name = path.name.lower()
    return any(p in name for p in VENDOR_PATTERNS)


def _list_cached_js_paths(target: str, repo_root: Path) -> list[Path]:
    """Infer locally cached JS file paths from recon/<target>/.

    Prefer explicit dump directories. If the target only has URL lists and no
    downloaded JS, return an empty list so the agent can rely on recon-extracted
    artifacts instead.
    """
    target_dir = repo_root / "recon" / target
    packer_dir = target_dir / "js_dump" / "packer"
    candidates: list[Path] = []
    for sub in ("js_dump", "js/files", "js_files", "katana_js", "js/dump"):
        p = target_dir / sub
        if p.is_dir():
            candidates.extend(
                path
                for path in sorted(p.rglob("*"))
                if path.is_file() and path.suffix.lower() in READABLE_SOURCE_SUFFIXES
            )
    # 动态恢复文件是本轮新增证据，不能被旧缓存先占满读取预算。
    return sorted(
        candidates,
        key=lambda path: (not path.is_relative_to(packer_dir), str(path)),
    )


def _read_recon_extracted(target: str, repo_root: Path) -> dict[str, list[str]]:
    """Read recon-extracted endpoints / secrets / JS URL lists."""
    target_dir = repo_root / "recon" / target
    out: dict[str, list[str]] = {}
    for key, rel in (
        ("js_urls", "urls/js_files.txt"),
        ("endpoints", "js/endpoints.txt"),
        ("endpoints_raw", "js/endpoints_raw.txt"),
        ("potential_secrets", "js/potential_secrets.txt"),
    ):
        p = target_dir / rel
        if p.is_file():
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                out[key] = [ln.strip() for ln in lines if ln.strip()]
            except OSError:
                out[key] = []
        else:
            out[key] = []
    return out


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _previous_js_hashes(path: Path) -> dict[str, str]:
    """Read the previous material inventory; malformed cache is ignored."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    selected = payload.get("selected_js_files") if isinstance(payload, dict) else None
    if not isinstance(selected, list):
        return {}
    return {
        str(item.get("path")): str(item.get("sha256"))
        for item in selected
        if isinstance(item, dict) and item.get("path") and item.get("sha256")
    }


def prepare_materials(
    target: str,
    *,
    repo_root: Path = BASE_DIR,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    skip_vendor: bool = True,
) -> dict:
    """Collect LLM-reading materials under findings/<target>/js_intel/."""
    safe_target = _safe_target(target)
    output_dir = repo_root / "findings" / safe_target / "js_intel"
    output_dir.mkdir(parents=True, exist_ok=True)
    materials_path = output_dir / "materials.json"
    previous_hashes = _previous_js_hashes(materials_path)

    cached_js = _list_cached_js_paths(safe_target, repo_root)
    selected: list[dict] = []
    skipped: list[dict] = []
    hash_states = {"new": 0, "unchanged": 0, "changed": 0}

    for p in cached_js:
        try:
            size = p.stat().st_size
        except OSError:
            continue
        rel_path = str(p.relative_to(repo_root))
        if skip_vendor and _looks_like_vendor(p):
            skipped.append({"path": rel_path, "size": size, "reason": "vendor"})
            continue
        if size > max_file_bytes:
            skipped.append({"path": rel_path, "size": size, "reason": f"oversize_{size}"})
            continue
        digest = _sha256(p)
        previous = previous_hashes.get(rel_path)
        content_status = (
            "new" if previous is None else "unchanged" if previous == digest else "changed"
        )
        hash_states[content_status] += 1
        selected.append({
            "path": rel_path,
            "size": size,
            "sha256": digest,
            "content_status": content_status,
        })
        if len(selected) >= max_files:
            break

    recon_extracted = _read_recon_extracted(safe_target, repo_root)
    source_intel = load_source_intel(repo_root / "findings" / safe_target)

    materials = {
        "target": safe_target,
        "generated_at": _now_utc(),
        "cap": {
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "skip_vendor": skip_vendor,
        },
        "selected_js_files": selected,
        "skipped_js_files": skipped,
        "hash_states": hash_states,
        "recon_extracted": recon_extracted,
        "source_intel_present": bool(source_intel.get("available")),
        "source_intel": source_intel,
    }

    materials_path.write_text(
        json.dumps(materials, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    summary_path = output_dir / "materials_summary.md"
    summary_path.write_text(_format_materials_summary(materials), encoding="utf-8")

    return {
        "target": safe_target,
        "materials": materials,
        "selected_count": len(selected),
        "skipped_count": len(skipped),
        "unchanged_count": hash_states["unchanged"],
        "changed_count": hash_states["changed"],
        "recon_artifacts_present": any(v for v in recon_extracted.values()),
        "source_intel_present": bool(source_intel.get("available")),
        "artifacts": {
            "materials": str(materials_path),
            "summary": str(summary_path),
        },
    }


def _format_materials_summary(materials: dict) -> str:
    lines: list[str] = [
        f"# JS Reader Materials — {materials['target']}",
        "",
        f"Generated: {materials['generated_at']}",
        "",
        "## Cap",
        f"- max_files: {materials['cap']['max_files']}",
        f"- max_file_bytes: {materials['cap']['max_file_bytes']}",
        f"- skip_vendor: {materials['cap']['skip_vendor']}",
        f"- content hashes: new={materials['hash_states']['new']}, "
        f"unchanged={materials['hash_states']['unchanged']}, "
        f"changed={materials['hash_states']['changed']}",
        "",
        "## Selected JS files",
        f"({len(materials['selected_js_files'])} files)",
    ]
    for item in materials["selected_js_files"][:20]:
        lines.append(f"- `{item['path']}` ({item['size']} bytes)")
    if len(materials["selected_js_files"]) > 20:
        lines.append(f"- ... and {len(materials['selected_js_files']) - 20} more")
    if not materials["selected_js_files"] and not any(materials["recon_extracted"].values()):
        lines.extend([
            "",
            "No cached JS or recon-extracted JS artifacts were found.",
            f"Run `/recon {materials['target']}` first, or add JS files under `recon/{materials['target']}/js_dump/`.",
        ])

    if materials["skipped_js_files"]:
        lines.extend([
            "",
            "## Skipped (with reason)",
            f"({len(materials['skipped_js_files'])} files)",
        ])
        for item in materials["skipped_js_files"][:10]:
            lines.append(f"- `{item['path']}` — {item['reason']}")

    re_extract = materials["recon_extracted"]
    lines.extend([
        "",
        "## Recon-extracted artifacts (already-grep results)",
        f"- js_urls: {len(re_extract.get('js_urls', []))} URLs",
        f"- endpoints: {len(re_extract.get('endpoints', []))} entries",
        f"- endpoints_raw: {len(re_extract.get('endpoints_raw', []))} entries",
        f"- potential_secrets: {len(re_extract.get('potential_secrets', []))} entries",
        "",
        "## Source intel (from prior source intelligence run)",
        f"- present: {materials['source_intel_present']}",
        "",
        "## Next step",
        "Hand `materials.json` to the `js-reader` agent. The agent will read",
        "the most promising JS files via the Read tool and produce",
        "`hypotheses.json` with attack-surface leads, auth model, sink hot spots,",
        "and ranked next actions.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare JS materials for the js-reader agent. Does NOT call any LLM."
    )
    parser.add_argument("--target", required=True, help="Target name used under recon/<target>/ and findings/<target>/")
    parser.add_argument("--repo-root", default=str(BASE_DIR), help="Repository root containing recon/ and findings/")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="Maximum number of JS files to surface for LLM read")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES, help="Skip JS files larger than this many bytes")
    parser.add_argument("--no-skip-vendor", dest="skip_vendor", action="store_false", help="Do not skip vendor JS bundles")
    args = parser.parse_args()

    result = prepare_materials(
        target=args.target,
        repo_root=Path(args.repo_root),
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        skip_vendor=args.skip_vendor,
    )
    print(Path(result["artifacts"]["summary"]).read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
