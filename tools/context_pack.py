#!/usr/bin/env python3
"""为 Claude CLI 装配当前目标的最小高信号上下文包。

Context Pack 是只读导航层：它收敛 Claude 本轮应该加载的目标、Skill、
知识卡和检查规则，同时给出发散假设与相邻角度。它不扫描目标、不写目标
记忆、不自动修改知识库或 Skill。
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from memory.target_profile import default_memory_dir
    from tools.coverage_matrix import high_value_gaps_from_matrix, read_matrix, require_matching_truth
    from tools.evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary
    from tools.knowledge_registry import (
        load_card_metadata_by_file,
        load_card_paths,
    )
    from tools.structured_findings import (
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from tools.surface import _load_surface_context, rank_surface
    from tools.surface_index import surface_safe_preview
    from tools.surface_projection import load_surface_projection
    from tools.target_paths import compact_url, canonical_target_value, target_storage_key
    from tools.target_memory import load_active_file, load_goal_memory, format_current_handoff
    from tools.current_truth import current_cell_projection
    from tools.target_store import TargetStore, runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    from memory.target_profile import default_memory_dir
    from coverage_matrix import high_value_gaps_from_matrix, read_matrix, require_matching_truth  # type: ignore
    from evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary  # type: ignore
    from knowledge_registry import (  # type: ignore
        load_card_metadata_by_file,
        load_card_paths,
    )
    from structured_findings import (  # type: ignore
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from surface import _load_surface_context, rank_surface  # type: ignore
    from surface_index import surface_safe_preview  # type: ignore
    from surface_projection import load_surface_projection  # type: ignore
    from target_paths import compact_url, canonical_target_value, target_storage_key  # type: ignore
    from target_memory import load_active_file, load_goal_memory, format_current_handoff  # type: ignore
    from current_truth import current_cell_projection  # type: ignore
    from target_store import TargetStore, runtime_store  # type: ignore


# S1 native skill loading (ai-capability-roadmap batch 3): every skill loads
# on demand via the native Claude Code Skill tool (frontmatter description is
# the routing surface). The pack neither recommends a skill nor publishes a
# skill catalog — discoverability belongs to the platform skill surface.
# The former `selected_skill` / `skill_route` / `selected_skill_id` /
# `why_this_skill` shell fields were removed; readers treat them as absent
# (checkpoint/resume use .get with defaults, so old checkpoints still parse).
# for old checkpoint/witness readers.

TELERIK_DIALOG_SIGNAL_RE = re.compile(
    r"\b(?:telerik|asyncupload|serializedparameters|dialogparameters)\b",
    re.I,
)


CARD_PATHS = load_card_paths(BASE_DIR)


def _load_capability_registry(repo_root: Path | str = BASE_DIR) -> dict[str, dict[str, str]]:
    """读取 card file -> metadata；临时 target repo 可回落到安装仓库。"""
    raw = load_card_metadata_by_file(repo_root, fallback_root=BASE_DIR)
    return {
        path: {key: str(value) for key, value in item.items() if value is not None}
        for path, item in raw.items()
    }


def _card_capability(
    path: str,
    repo_root: Path | str = BASE_DIR,
    *,
    registry: dict[str, dict[str, str]] | None = None,
) -> dict[str, str]:
    registry = registry if registry is not None else _load_capability_registry(repo_root)
    item = registry.get(path, {})
    return {
        "file": path,
        "id": item.get("id") or Path(path).stem,
        "layer": item.get("layer") or "unregistered",
        "load": item.get("load") or "unknown",
        "purpose": item.get("purpose") or "unknown",
    }


def _card_catalog(
    repo_root: Path | str = BASE_DIR,
    *,
    registry: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Publish the FULL card catalog (id + layer + load + purpose).

    Selection authority stays with the AI: the pack presents every card and
    its purpose line; word-list matches appear as signal annotations in
    knowledge_card_recall; nothing is hidden by not matching a token table.
    """
    registry = registry if registry is not None else _load_capability_registry(repo_root)
    seen: set[str] = set()
    catalog: list[dict[str, str]] = []
    for path in sorted(registry):
        if path in seen:
            continue
        seen.add(path)
        capability = _card_capability(path, repo_root, registry=registry)
        catalog.append(capability)
    return catalog


def _card_capabilities(
    paths: list[str],
    repo_root: Path | str = BASE_DIR,
    *,
    registry: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    registry = registry if registry is not None else _load_capability_registry(repo_root)
    return [_card_capability(path, repo_root, registry=registry) for path in paths]


def _read_local_intel_json(
    path: Path, repo_root: Path, *, list_fields: tuple[str, ...] = (), object_fields: tuple[str, ...] = (),
) -> tuple[dict, dict]:
    """Read bounded browser shape data without turning it into route obligations."""
    relative = _display(path, repo_root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, {"path": relative, "status": "missing"}
    except UnicodeError:
        return {}, {"path": relative, "status": "invalid", "error": "invalid UTF-8"}
    except json.JSONDecodeError as exc:
        return {}, {"path": relative, "status": "invalid", "error": f"JSON decode error: {exc.msg}"}
    except OSError as exc:
        return {}, {"path": relative, "status": "unreadable", "error": str(exc)}
    if not isinstance(payload, dict):
        return {}, {"path": relative, "status": "invalid", "error": "expected a JSON object"}
    for field in list_fields:
        if field in payload and (not isinstance(payload[field], list)
                                 or any(not isinstance(item, dict) for item in payload[field])):
            return {}, {"path": relative, "status": "invalid", "error": f"{field} must be a list of objects"}
    for field in object_fields:
        if field in payload and not isinstance(payload[field], dict):
            return {}, {"path": relative, "status": "invalid", "error": f"{field} must be an object"}
    return payload, {"path": relative, "status": "ok"}


def _read_lines(path: Path, limit: int = 50) -> list[str]:
    if not path.is_file():
        return []
    if limit <= 0:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        return _dedupe([line.strip() for line in lines if line.strip()])[:limit]
    items: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                value = line.strip()
                if not value or value in seen:
                    continue
                seen.add(value)
                items.append(value)
                if len(items) >= limit:
                    break
    except OSError:
        return []
    return items


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _display(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _entry_text(item: object) -> str:
    if isinstance(item, dict):
        return str(item.get("text") or item.get("summary") or item.get("title") or "").strip()
    return str(item or "").strip()


def _json_list(items: object) -> list[dict]:
    out: list[dict] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, str):
            try:
                item = json.loads(item)
            except json.JSONDecodeError:
                item = {"title": item}
        if isinstance(item, dict):
            out.append(item)
    return out


def _looks_like_target(value: str) -> bool:
    """Disambiguate legacy positionals by syntax, not a second Skill catalog."""
    value = value.strip()
    if not value:
        return False
    if "://" in value:
        return True
    if "/" in value and not value.startswith("/"):
        return True
    if ":" in value and not value.startswith("http"):
        return True
    return "." in value


def _resolve_cli_args(args: argparse.Namespace, repo_root: Path) -> tuple[str, str]:
    positional = list(args.args or [])
    target = args.target or ""
    focus_parts: list[str] = []

    if target:
        focus_parts.extend(positional)
    elif positional and _looks_like_target(positional[0]):
        target = positional[0]
        focus_parts.extend(positional[1:])
    else:
        focus_parts.extend(positional)

    if args.focus:
        focus_parts.append(args.focus)

    if not target:
        active = load_active_file(repo_root / "memory" / "goals" / "active.json")
        target = str(active.get("target") or "").strip()
    if not target:
        raise SystemExit(
            "No target resolved. Use --target target.com or set active target with "
            "`python3 tools/target_memory.py set <target>`."
        )

    return canonical_target_value(target), " ".join(focus_parts).strip()


def _load_goal_memory(repo_root: Path, target: str) -> dict:
    projection = load_goal_memory(repo_root, target, experience_limit=5)
    projection["active_path"] = _display(
        repo_root / "memory" / "goals" / "active.json", repo_root
    )
    if projection.get("source", {}).get("kind") == "store":
        projection["target_path"] = _display(
            TargetStore(repo_root, target).path, repo_root
        )
    else:
        projection["target_path"] = _display(
            repo_root / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json",
            repo_root,
        )
    return projection


def _target_facts_projection(goal_memory: dict, *, limit: int = 20) -> list[dict]:
    """Project the keyed confirmed-fact map into the pack.

    Facts are the cheap context-recovery layer: after compaction, reading
    these key/text pairs replaces re-reading full history. Bounded by design.
    """
    target_memory = goal_memory.get("target") or {}
    facts = target_memory.get("facts")
    if not isinstance(facts, dict):
        return []
    projected = []
    for key in sorted(facts):
        item = facts.get(key)
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "")).strip()
        if not text:
            continue
        refs = item.get("evidence_refs")
        projected.append(
            {
                "key": key,
                "text": text,
                "evidence_refs": [str(ref) for ref in refs] if isinstance(refs, list) else [],
            }
        )
        if len(projected) >= limit:
            break
    return projected


def _load_findings(repo_root: Path, target_key: str, *, target: str | None = None) -> dict:
    snapshot = runtime_store(repo_root, target or target_key).finding_summary(limit=5)
    return {"counts": snapshot["counts"], "items": [{
        "id": item["id"], "type": item["family"], "category": item["family"],
        "url": item["endpoint"],
        "validation_status": "validated" if (item.get("assessment") or {}).get("verdict") == "confirmed" else "",
        "report_status": "generated" if item["report_recorded"] else "not_generated",
    } for item in snapshot["items"]]}


def _artifact_path(path: Path, repo_root: Path) -> str:
    return _display(path, repo_root) if path.is_file() else ""


def _load_local_intel(repo_root: Path, target_key: str) -> dict:
    """Read browser shapes and expose raw artifact paths for native inspection.

    JS/source interpretation belongs to Claude's native Read/Grep/delegation.
    This function deliberately does not parse hypotheses, routes, or signals.
    """
    browser_dir = repo_root / "recon" / target_key / "browser"

    diagnostics = []
    browser_summary, detail = _read_local_intel_json(browser_dir / "summary.json", repo_root)
    diagnostics.append(detail)
    forms_payload, detail = _read_local_intel_json(browser_dir / "forms.json", repo_root, list_fields=("forms",))
    diagnostics.append(detail)
    forms = []
    if isinstance(forms_payload, dict) and isinstance(forms_payload.get("forms"), list):
        forms = [item for item in forms_payload["forms"] if isinstance(item, dict)]

    page_js_map, detail = _read_local_intel_json(
        browser_dir / "page_js_map.json", repo_root, object_fields=("pages", "js_index"))
    diagnostics.append(detail)
    pages = page_js_map.get("pages") if isinstance(page_js_map.get("pages"), dict) else {}
    js_index = page_js_map.get("js_index") if isinstance(page_js_map.get("js_index"), dict) else {}

    raw_candidates = [
        repo_root / "recon" / target_key / "js" / "endpoints.txt",
        repo_root / "recon" / target_key / "js" / "endpoints_raw.txt",
        repo_root / "recon" / target_key / "js_dump" / "packer" / "manifest.json",
        repo_root / "findings" / target_key / "js_intel" / "hypotheses.json",
        repo_root / "findings" / target_key / "source_intel" / "routes.json",
        repo_root / "findings" / target_key / "source_intel" / "summary.md",
    ]
    raw_paths = _dedupe([_artifact_path(path, repo_root) for path in raw_candidates])
    invalid_count = sum(item["status"] in {"invalid", "unreadable"} for item in diagnostics)

    return {
        "browser": {
            "summary": browser_summary,
            "xhr_endpoints": _read_lines(browser_dir / "xhr_endpoints.txt"),
            "api_endpoints": _read_lines(browser_dir / "api_endpoints.txt"),
            "params": _read_lines(browser_dir / "browser_params.txt"),
            "forms": forms,
            "page_count": len(pages),
            "js_file_count": len(js_index),
            "paths": _dedupe([
                _artifact_path(browser_dir / "xhr_endpoints.txt", repo_root),
                _artifact_path(browser_dir / "api_endpoints.txt", repo_root),
                _artifact_path(browser_dir / "browser_params.txt", repo_root),
                _artifact_path(browser_dir / "page_js_map.json", repo_root),
                _artifact_path(browser_dir / "summary.json", repo_root),
            ]),
        },
        "raw_paths": raw_paths,
        "health": {"status": "unavailable" if invalid_count else "ready",
                   "invalid_count": invalid_count, "diagnostics": diagnostics},
    }


def _finding_anchor(finding: dict, *, compact: bool = False) -> str:
    label = str(finding.get("id") or finding.get("type") or finding.get("title") or "finding").strip()
    vuln = str(finding.get("vuln_class") or finding.get("class") or finding.get("category") or "").strip()
    endpoint = str(finding.get("endpoint") or finding.get("url") or "").strip()
    if compact:
        endpoint = compact_url(endpoint)
    status = str(finding.get("validation_status") or finding.get("report_status") or finding.get("status") or "").strip()
    parts = [label]
    if vuln:
        parts.append(f"[{vuln}]")
    if endpoint:
        parts.append(f"-> {endpoint}")
    if status:
        parts.append(f"status={status}")
    return " ".join(parts)


def _safe_find_gaps(target: str, target_key: str, repo_root: Path) -> tuple[list[dict], dict]:
    matrix = read_matrix(target, repo_root=repo_root, current_only=True)
    return high_value_gaps_from_matrix(matrix), matrix


def _surface_state(repo_root: Path, target: str, memory_dir: str | None, *, coverage_state: dict | None = None) -> dict:
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    projection = load_surface_projection(
        repo_root,
        target,
        memory_dir=resolved_memory_dir,
    )
    if projection.get("status") == "valid":
        return dict(projection.get("surface") or {})
    context = _load_surface_context(
        repo_root,
        target,
        memory_dir=resolved_memory_dir,
        coverage_state=coverage_state,
    )
    return rank_surface(context)


def _local_intel_blob(local_intel: dict) -> list[str]:
    pieces: list[str] = []
    browser = local_intel.get("browser") or {}
    pieces.extend(browser.get("xhr_endpoints") or [])
    pieces.extend(browser.get("api_endpoints") or [])
    pieces.extend(browser.get("params") or [])
    for form in (browser.get("forms") or [])[:5]:
        pieces.append(
            "{method} {action} {fields}".format(
                method=form.get("method", ""),
                action=form.get("action", ""),
                fields=" ".join(str(field) for field in (form.get("hidden_fields") or [])),
            )
        )

    pieces.extend(local_intel.get("raw_paths") or [])
    return [piece for piece in pieces if str(piece).strip()]


def _ranked_tech_stack(ranked: dict, *, limit: int = 12) -> list[str]:
    """Return a small, ordered technology projection from ranked candidates."""

    values: list[str] = []
    sources = [ranked.get("tech_stack")]
    for key in ("review_pool", "p1", "p2"):
        items = ranked.get(key) or []
        sources.extend(
            item.get("tech_stack")
            for item in items[:16]
            if isinstance(item, dict)
        )
    for source in sources:
        if isinstance(source, str):
            source = [source]
        if not isinstance(source, (list, tuple)):
            continue
        for item in source:
            name = item.get("name") if isinstance(item, dict) else item
            name = str(name or "").strip()
            if name and name.casefold() not in {value.casefold() for value in values}:
                values.append(name)
                if len(values) >= limit:
                    return values
    return values


def _text_blob(
    focus: str,
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
    findings: list[dict],
    local_intel: dict,
) -> str:
    pieces: list[str] = [focus]
    tech_stack = _ranked_tech_stack(ranked)
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    for key in ("active_goal", "current_hypothesis", "phase", "mode"):
        pieces.append(str(active.get(key) or target_memory.get(key) or ""))
    for field in ("active_leads", "next_actions", "dead_ends", "useful_patterns"):
        for item in (target_memory.get(field) or [])[-5:]:
            pieces.append(_entry_text(item))
    review_items = ranked.get("review_pool") or (ranked.get("p1", [])[:5] + ranked.get("p2", [])[:3])
    for item in review_items[:8]:
        semantic = item.get("semantic_shape") if isinstance(item.get("semantic_shape"), dict) else {}
        request_shapes = item.get("request_shapes") if isinstance(item.get("request_shapes"), list) else []
        request_hint = ""
        if request_shapes:
            request_bits = []
            for shape in request_shapes[:2]:
                if not isinstance(shape, dict):
                    continue
                body = shape.get("body") if isinstance(shape.get("body"), dict) else {}
                request_bits.append(
                    f"{str(shape.get('method') or 'GET').upper()} {body.get('content_type_hint') or ''}".strip()
                )
            request_hint = " ".join(request_bits)
        pieces.extend([
            surface_safe_preview(str(item.get("url") or "")),
            str(item.get("path") or ""),
            f"semantic={semantic.get('path_template', '')} params={','.join(str(name) for name, _count in semantic.get('parameter_multiset', [])[:12])} {request_hint}".strip(),
            " ".join(str(reason) for reason in item.get("reasons", [])[:3]),
            str(item.get("suggested") or ""),
        ])
    for lead in _json_list(ranked.get("workflow_leads"))[:5]:
        pieces.extend([
            str(lead.get("title") or ""),
            str(lead.get("category") or ""),
            str(lead.get("next_action") or ""),
            str(lead.get("rationale") or ""),
        ])
    for gap in gaps[:8]:
        pieces.append(f"{gap.get('endpoint')} {gap.get('vuln_class')}")
    for finding in findings[:5]:
        pieces.append(_finding_anchor(finding))
    if tech_stack:
        pieces.append("tech_stack=" + " ".join(tech_stack))
    pieces.extend(_local_intel_blob(local_intel))
    return "\n".join(piece for piece in pieces if piece)


def _required_checks(blob: str, has_candidate: bool) -> list[str]:
    # Platform startup owns action safety; Context Pack only emits route checks.
    # Skill recommendation is retired (S1 native loading): the reporting rule
    # loads on the owner fact "a candidate awaits validation", which is what
    # the old triage-validation recommendation encoded.
    checks = ["rules/coverage-gate.md"]
    if has_candidate:
        checks.append("rules/reporting.md")
    checks.append("rules/playbook-router.md")
    return _dedupe(checks)


def _phase(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("phase") or target_memory.get("phase") or "unknown").strip() or "unknown"


def _active_goal(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("active_goal") or target_memory.get("active_goal") or "").strip()


def _hypothesis(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("current_hypothesis") or target_memory.get("current_hypothesis") or "").strip()


def _surface_anchor(item: dict) -> str:
    url = surface_safe_preview(str(item.get("url") or "").strip())
    reasons = ", ".join(str(reason) for reason in (item.get("reasons") or [])[:2])
    review_reason = str(item.get("review_reason") or "surface evidence").strip()
    value_summary = item.get("value_summary") if isinstance(item.get("value_summary"), dict) else {}
    value_bits = []
    for signal in (value_summary.get("signals") or [])[:3]:
        classes = "/".join(str(value) for value in signal.get("classes", [])[:3] if str(value))
        name = str(signal.get("name") or "param")[:40]
        value_bits.append(f"{name}:{classes or 'structured'}:{signal.get('length', '?')}")
    value_hint = f" values={','.join(value_bits)}" if value_bits else ""
    return f"Surface review {url} reason={review_reason}{value_hint}; {reasons}".strip()


def _gap_anchor(gap: dict) -> str:
    return f"Coverage gap: {gap.get('endpoint', '')} x {gap.get('vuln_class', '')}"


def _runner_candidate_anchors(candidates: list[dict]) -> list[str]:
    anchors: list[str] = []
    for item in candidates[:4]:
        anchors.append(
            "Runner candidate evidence: {lane}/{result} {method} {url}; "
            "requires /validate gates before report".format(
                lane=item.get("lane", ""),
                result=item.get("result", ""),
                method=item.get("method", "GET"),
                url=compact_url(item.get("url", "")),
            )
        )
    return anchors


def _local_intel_anchors(local_intel: dict) -> list[str]:
    anchors: list[str] = []
    browser = local_intel.get("browser") or {}
    for url in (browser.get("xhr_endpoints") or [])[:3]:
        anchors.append(f"Browser XHR/API: {compact_url(url)}")
    for line in (browser.get("params") or [])[:3]:
        anchors.append(f"Browser param: {line}")
    for form in (browser.get("forms") or [])[:2]:
        method = str(form.get("method") or "").strip() or "GET"
        action = str(form.get("action") or "").strip() or "(current page)"
        hidden_fields = [str(field) for field in (form.get("hidden_fields") or []) if str(field).strip()]
        suffix = f" hidden_fields={','.join(hidden_fields[:4])}" if hidden_fields else ""
        anchors.append(f"Browser form: {method} {action}{suffix}")

    for path in (local_intel.get("raw_paths") or [])[:4]:
        anchors.append(f"Raw artifact (read directly): {path}")
    return _dedupe(anchors)


def _build_evidence_anchors(
    ranked: dict,
    goal_memory: dict,
    gaps: list[dict],
    findings: list[dict],
    local_intel: dict,
) -> list[str]:
    anchors: list[str] = []
    for item in (ranked.get("review_pool") or ranked.get("p1", []))[:3]:
        anchors.append(_surface_anchor(item))
    anchors.extend(_local_intel_anchors(local_intel)[:6])
    for lead in _json_list(ranked.get("workflow_leads"))[:3]:
        title = str(lead.get("title") or "").strip()
        category = str(lead.get("category") or "workflow").strip()
        priority = str(lead.get("priority") or "medium").strip()
        anchors.append(f"Workflow lead [{priority}/{category}]: {title}")
    target_memory = goal_memory.get("target") or {}
    for label, field in (
        ("Target lead", "active_leads"),
        ("Current next intent (advisory, not Queue)", "next_actions"),
        ("Dead end", "dead_ends"),
    ):
        for item in (target_memory.get(field) or [])[-2:]:
            text = _entry_text(item)
            if text:
                anchors.append(f"{label}: {text}")
    for gap in gaps[:5]:
        anchors.append(_gap_anchor(gap))
    for finding in findings[:3]:
        anchors.append(f"Finding: {_finding_anchor(finding, compact=True)}")
    return _dedupe(anchors)[:12] or ["No strong local evidence anchor yet; start from target memory and recon freshness."]


def _has_telerik_dialog_signal(value: str) -> bool:
    return bool(TELERIK_DIALOG_SIGNAL_RE.search(value))


def _unknowns(
    ranked: dict,
    goal_memory: dict,
    matrix: dict,
    findings: list[dict],
    local_intel: dict,
) -> list[str]:
    items: list[str] = []
    items.extend(f"Browser material {item['path']}: {item['error']}"
                 for item in (local_intel.get("health") or {}).get("diagnostics", [])
                 if item.get("error"))
    if not ranked.get("available"):
        items.append("No surface review pack available from local recon cache.")
    stats = ranked.get("stats") or {}
    observation_inventory = ranked.get("observation_inventory") or {}
    inventory_error = str(observation_inventory.get("error") or "").strip()
    if inventory_error:
        items.append(f"Observation inventory could not be read: {inventory_error}")
    elif observation_inventory.get("available") and observation_inventory.get("untouched"):
        items.append(
            "Observation inventory still has {untouched} untouched item(s), including {stale} stale; "
            "use the bounded sample or inventory list before declaring surface exhaustion.".format(
                untouched=observation_inventory.get("untouched", 0),
                stale=observation_inventory.get("stale", 0),
            )
        )
    if ranked.get("available") and not stats.get("review_pool") and not stats.get("p1") and not stats.get("p2"):
        items.append("Surface review pool has no candidates; recon may be thin or low-signal.")
    browser = ranked.get("browser") or {}
    local_browser = local_intel.get("browser") or {}
    if (
        not browser.get("xhr_count")
        and not browser.get("api_count")
        and not local_browser.get("xhr_endpoints")
        and not local_browser.get("api_endpoints")
    ):
        items.append("No browser-observed XHR/API context loaded.")
    summary = matrix.get("summary") or {}
    if not summary.get("total_cells"):
        items.append("Coverage matrix is empty or not rebuilt for this target.")
    if not findings:
        items.append("No Store findings recorded for this target.")
    if not (goal_memory.get("active") or goal_memory.get("target")):
        items.append("No target memory found; write back the first concrete lead/handoff after work.")
    return items or ["No major local unknowns surfaced by context_pack."]


def _contradictions(
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
) -> list[str]:
    items: list[str] = []
    workflow_leads = _json_list(ranked.get("workflow_leads"))
    if not gaps and workflow_leads:
        items.append(
            "Coverage gaps are empty, but workflow leads still exist; do not treat empty matrix gaps as full exhaustion."
        )
    if not ranked.get("available") and ((goal_memory.get("target") or {}).get("active_leads")):
        items.append(
            "Target memory has active leads, but local surface is unavailable; use memory as hypothesis, not proof."
        )
    return _dedupe(items) or ["None detected."]


def _write_back_commands(repo_root: Path, target: str) -> list[str]:
    memory = shlex.join(["python3", "tools/target_memory.py", "--repo-root", str(repo_root.resolve())])
    target_arg = shlex.quote(target)
    return [
        f'{memory} lead "STATEMENT" --target {target_arg} --conditions "CONDITIONS" --reopen-when "REOPEN_WHEN" --next-intent "NEXT_INTENT"',
        f'{memory} next "NEXT_INTENT" --target {target_arg}',
        f'{memory} dead-end "STATEMENT" --target {target_arg} --conditions "CONDITIONS" --reopen-when "REOPEN_WHEN" --operation-ref OPERATION_ID:0',
        f'{memory} handoff "STATEMENT" --target {target_arg}',
        shlex.join([
            "python3", "tools/validation_runner.py", "record-evidence", "--repo-root", str(repo_root.resolve()),
            "--target", target, "--finding-id", "FINDING_ID", "--evidence-json", "EVIDENCE_JSON",
        ]),
        "/retrospect <target>  # 可复用经验只建议晋升到知识库 / Skill / Rules，默认不自动改文件",
    ]


def _local_intel_paths(local_intel: dict) -> list[str]:
    paths = list(((local_intel.get("browser") or {}).get("paths") or [])[:5])
    paths.extend((local_intel.get("raw_paths") or [])[:6])
    return _dedupe(paths)


def _local_intel_source_summary(local_intel: dict) -> dict:
    browser = local_intel.get("browser") or {}
    health = local_intel.get("health") or {}
    return {
        "local_intel_status": health.get("status", "ready"),
        "local_intel_invalid_count": health.get("invalid_count", 0),
        "local_intel_diagnostics": health.get("diagnostics", []),
        "browser_xhr": len(browser.get("xhr_endpoints") or []),
        "browser_api": len(browser.get("api_endpoints") or []),
        "browser_params": len(browser.get("params") or []),
        "browser_forms": len(browser.get("forms") or []),
        "browser_pages_with_js": int(browser.get("page_count") or 0),
        "raw_artifact_paths": len(local_intel.get("raw_paths") or []),
    }


def _focus_endpoints_for_ledger(ranked: dict, gaps: list[dict], local_intel: dict) -> list[str]:
    endpoints: list[str] = []
    review_items = ranked.get("review_pool") or (ranked.get("p1", [])[:4] + ranked.get("p2", [])[:2])
    for item in review_items[:6]:
        endpoints.append(str(item.get("url") or item.get("path") or ""))
    for gap in gaps[:4]:
        endpoints.append(str(gap.get("endpoint") or ""))
    browser = local_intel.get("browser") or {}
    endpoints.extend((browser.get("xhr_endpoints") or [])[:4])
    return _dedupe(endpoints)[:8]


def _owner_backed_vuln_classes(evidence_records: list[dict]) -> list[str]:
    canonical_by_name = {item.casefold(): item for item in ACTOR_MATRIX_VULN_CLASSES}
    return _dedupe([
        canonical_by_name[value.casefold()]
        for record in evidence_records
        if isinstance(record, dict)
        and (value := str(record.get("vuln_class") or "").strip())
        and value.casefold() in canonical_by_name
    ])


def _ledger_anchors(summary: dict) -> list[str]:
    anchors: list[str] = []
    for entry in (summary.get("recent_entries") or [])[-3:]:
        anchors.append(
            "Ledger: {method} {endpoint} x {vuln} {actor}/{scope}/{variant} -> {result}".format(
                method=entry.get("method", ""),
                endpoint=entry.get("endpoint", ""),
                vuln=entry.get("vuln_class", ""),
                actor=entry.get("actor", ""),
                scope=entry.get("object_scope", ""),
                variant=entry.get("variant", ""),
                result=entry.get("result", ""),
            )
        )
    matrix = summary.get("actor_matrix") or {}
    for gap in (matrix.get("gaps") or [])[:3]:
        anchors.append(
            "Actor gap: {endpoint} x {vuln} {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=gap.get("endpoint", ""),
                vuln=gap.get("vuln_class", ""),
                actor=gap.get("actor", ""),
                scope=gap.get("object_scope", ""),
                variant=gap.get("variant", ""),
                expected=gap.get("expected", ""),
                status=gap.get("status", ""),
            )
        )
    return _dedupe(anchors)


def _ledger_unknowns(summary: dict) -> list[str]:
    items: list[str] = []
    if not summary.get("entry_count"):
        items.append("No evidence ledger entries found; exact actor/object/replay coverage is not recorded yet.")
    matrix = summary.get("actor_matrix") or {}
    if matrix.get("gap_count"):
        items.append(
            f"Actor matrix has {matrix.get('gap_count')} missing/pending/blocked role-object checks."
        )
    if summary.get("redline_unchecked_count"):
        items.append(
            f"Evidence ledger has {summary.get('redline_unchecked_count')} state-changing record(s) without red-line check."
        )
    return items


def _ledger_source_summary(summary: dict) -> dict:
    matrix = summary.get("actor_matrix") or {}
    result_counts = summary.get("result_counts") or {}
    # 来源与健康状态由同一 Store 快照提供。
    source = summary.get("evidence_source") or {}
    return {
        "evidence_source_kind": str(source.get("kind") or ""),
        "evidence_source_status": str(source.get("status") or ""),
        "evidence_ledger_entries": int(summary.get("entry_count") or 0),
        "actor_matrix_gaps": int(matrix.get("gap_count") or 0),
        "actor_matrix_covered": int(matrix.get("covered_count") or 0),
        "evidence_candidates": int(result_counts.get("candidate", 0) or 0),
        "evidence_redline_unchecked": int(summary.get("redline_unchecked_count") or 0),
    }


def build_context_pack(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    focus: str = "",
    memory_dir: str | None = None,
    surface_state: dict | None = None,
    coverage_state: tuple[list[dict], dict] | None = None,
    validation_runner_candidates: list[dict] | None = None,
    ledger_truth: dict | None = None,
) -> dict:
    """Read current owners; public caller snapshots never authorize this view."""
    return _build_context_pack(repo_root, target=target, focus=focus, memory_dir=memory_dir)


def _build_context_pack(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    focus: str = "",
    memory_dir: str | None = None,
    surface_state: dict | None = None,
    coverage_state: tuple[list[dict], dict] | None = None,
    validation_runner_candidates: list[dict] | None = None,
    ledger_truth: dict | None = None,
) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    store = runtime_store(repo, resolved_target)
    store_binding = store.binding()
    # Private assembly accepts only inputs captured by this call's owner reader.
    goal_memory = _load_goal_memory(repo, resolved_target)
    gaps, matrix = coverage_state or _safe_find_gaps(resolved_target, target_key, repo)
    ranked = (surface_state if surface_state is not None
              else _surface_state(repo, resolved_target, memory_dir, coverage_state=matrix))
    finding_summary = _load_findings(repo, target_key, target=resolved_target)
    findings = finding_summary["items"]
    runner_candidates = (
        validation_runner_candidates
        if isinstance(validation_runner_candidates, list)
        else load_validation_runner_candidate_pool(repo, resolved_target)
    )
    local_intel = _load_local_intel(repo, target_key)
    tech_stack = _ranked_tech_stack(ranked)
    blob = _text_blob(focus, goal_memory, ranked, gaps, findings, local_intel)
    telerik_dialog_signal = _has_telerik_dialog_signal(blob)
    viewstate_signal = bool(re.search(r"\bviewstate\b|__viewstate", blob, re.I))
    has_candidate = finding_summary["counts"]["total"] > finding_summary["counts"]["confirmed"]
    historical_patterns = []
    # 2026-09-12 收敛裁定：跨目标现场经验不自动进入本目标的 Pack。
    # surface 新计算路径已不再产生跨目标 pattern_suggestions，但升级前的
    # 旧 v2 投影在输入 owner 未变时仍被判 valid——这里的消费边界负责拒绝
    # 任何非当前目标 provenance 的残留建议，缓存与真源（新计算）双侧闭合。
    for item in ((ranked.get("memory") or {}).get("pattern_suggestions") or []):
        lesson = str(item).strip()
        provenance, separator, stripped_lesson = lesson.partition(": ")
        if separator:
            try:
                same_target = canonical_target_value(provenance).casefold() == resolved_target.casefold()
            except ValueError:
                same_target = False
            if not same_target:
                # 其他目标的残留建议（旧投影缓存）：跳过，不进 historical_patterns。
                continue
            lesson = stripped_lesson.strip()
        if lesson and lesson not in historical_patterns:
            historical_patterns.append(lesson)
        if len(historical_patterns) == 3:
            break
    registry = _load_capability_registry(repo)
    # 语义选卡已退役（原生能力审计 2026-09-13）：关键词分支/否定盲/人工
    # 排序是在替 AI 做语义理解。Pack 发布完整卡片目录（card_catalog，
    # id + layer + load + purpose），选择权在 AI；knowledge_cards 等
    # 字段保留为空兼容投影，消费方不破坏。
    cards: list[str] = []
    deferred_cards: list[str] = []
    knowledge_card_recall: list[dict[str, object]] = []
    checks = _required_checks(blob, has_candidate)
    ledger_truth = ledger_truth if ledger_truth is not None else current_cell_projection(repo, resolved_target, _store=store)
    require_matching_truth(matrix, ledger_truth)
    evidence_summary = build_evidence_summary(
        repo,
        target=resolved_target,
        focus_endpoints=_focus_endpoints_for_ledger(ranked, gaps, local_intel),
        vuln_classes=_owner_backed_vuln_classes(ledger_truth["records"]),
        _truth=ledger_truth,
    )
    current_binding = store.binding()
    if current_binding != store_binding:
        raise ValueError(
            "primary context inputs changed during assembly; rebuild from one store revision"
        )

    # Must-read lists only paths that exist: goal memory is legitimately
    # absent after a reset/fresh start, and a contract that points at missing
    # files gives the reader no way to tell a defect from a fresh start.
    # Repo-owned assets (runtime protocol, signal-matched tools) are
    # unconditional: they live in the repository, not in target state.
    _REPO_UNCONDITIONAL = {
        "skills/runtime-protocol.md",
        "tools/aspnet_viewstate_knownkey.py",
        "tools/telerik_knownkey.py",
    }

    def _must_read_candidate(relative: str) -> bool:
        if not relative:
            return False
        if relative in _REPO_UNCONDITIONAL:
            return True
        try:
            return (repo / relative).is_file()
        except OSError:
            return False

    must_read = _dedupe([
        goal_memory["active_path"],
        "skills/runtime-protocol.md",
    ] + (["tools/aspnet_viewstate_knownkey.py"] if viewstate_signal else []) + (["tools/telerik_knownkey.py"] if telerik_dialog_signal else []) + _local_intel_paths(local_intel) + [
        str(item.get("summary_path") or "")
        for item in runner_candidates[:6]
        if item.get("summary_path")
    ])
    must_read = [item for item in must_read if _must_read_candidate(item)]
    experience_window = (goal_memory.get("source") or {}).get("experience_window") or {}
    recall_command = experience_window["recall_command"]

    pack = {
        "target": resolved_target,
        "target_storage_key": target_key,
        "phase": _phase(goal_memory),
        "active_goal": _active_goal(goal_memory),
        "current_hypothesis": _hypothesis(goal_memory),
        "facts": _target_facts_projection(goal_memory),
        "target_experiences": {
            **experience_window,
            "items": goal_memory.get("recent_entries") or [],
            "current_handoff": goal_memory["target"]["current_handoff"],
            "next_actions": goal_memory["target"]["next_actions"],
            "next_command": (
                f"{recall_command} --cursor {shlex.quote(experience_window['next_cursor'])}"
                if experience_window.get("has_more") else ""
            ),
            "expand_command": f"{recall_command} --id EXPERIENCE_ID",
        },
        "focus": focus,
        "tech_stack": tech_stack,
        "must_read": must_read,
        "knowledge_cards": cards,
        "card_catalog": _card_catalog(repo, registry=registry),
        "knowledge_card_capabilities": _card_capabilities(cards, repo, registry=registry),
        "deferred_knowledge_cards": deferred_cards,
        "deferred_knowledge_card_capabilities": _card_capabilities(deferred_cards, repo, registry=registry),
        "knowledge_card_recall": knowledge_card_recall,
        # Compatibility field: generic technique references are intentionally
        # retired; project-specific guidance comes from knowledge_cards.
        "reference_hints": [],
        "historical_patterns": historical_patterns,
        "required_checks": checks,
        "evidence_anchors": _build_evidence_anchors(ranked, goal_memory, gaps, findings, local_intel)
        + _runner_candidate_anchors(runner_candidates)
        + _ledger_anchors(evidence_summary),
        "source_queries": {
            "surface": ranked.get("surface_index") or {"status": "unavailable"},
            "coverage": {
                "total": len(gaps),
                "order": "endpoint,vuln_class",
                "command": shlex.join([
                    "python3", "tools/coverage_matrix.py", "find-gaps", "--repo-root",
                    str(repo.resolve()), "--target", resolved_target,
                ]),
            },
        },
        "validation_runner_candidates": runner_candidates,
        # 静态假设/发散建议已退役（原生能力审计 2026-09-13）：
        # if 某张卡 in cards: append 固定思路 是卡片正文的复读层，
        # 独有知识已确认在对应卡片中（语义覆盖审计）。假设由 AI 在
        # 真实证据和完整卡片上自己提出。字段保留为空兼容投影。
        "hypothesis_seeds": [],
        "alternative_angles": [],
        "unknowns": _unknowns(ranked, goal_memory, matrix, findings, local_intel)
        + _ledger_unknowns(evidence_summary),
        "contradictions": _contradictions(goal_memory, ranked, gaps),
        "actor_matrix_gaps": (evidence_summary.get("actor_matrix") or {}).get("gaps", [])[:8],
        "do_not_load": [
            "full skills/* tree",
            "full knowledge/cards/* tree",
            "generic technique catalogues and external reference indexes",
            "raw large recon logs, full JSONL, full HTML responses, or unrelated historical sessions",
            "raw browser capture requests/console/storage unless validating one exact replay path",
            "all finding evidence bodies; start from Store finding IDs and evidence refs",
        ],
        "write_back": _write_back_commands(repo, resolved_target),
        "ai_override": (
            "Claude selects and loads Skills through the native Skill tool. "
            "The pack does not prescribe a Skill route; record evidence and tested dimensions "
            "through their domain commands."
        ),
        "source_summary": {
            "surface_available": bool(ranked.get("available")),
            "tech_stack": tech_stack,
            "p1": (ranked.get("stats") or {}).get("p1", 0),
            "p2": (ranked.get("stats") or {}).get("p2", 0),
            "workflow_leads": len(_json_list(ranked.get("workflow_leads"))),
            "observation_total": int((ranked.get("observation_inventory") or {}).get("total", 0) or 0),
            "observation_untouched": int((ranked.get("observation_inventory") or {}).get("untouched", 0) or 0),
            "observation_stale": int((ranked.get("observation_inventory") or {}).get("stale", 0) or 0),
            "coverage_gaps": len(gaps),
            "findings": finding_summary["counts"]["total"],
            "validation_runner_candidates": len(runner_candidates),
            "historical_patterns": len(historical_patterns),
            "viewstate_signal": viewstate_signal,
            "telerik_dialog_signal": telerik_dialog_signal,
            **_local_intel_source_summary(local_intel),
            **_ledger_source_summary(evidence_summary),
            "store_id": store_binding["store_id"],
            "store_revision": store_binding["revision"],
            "snapshot_status": "bound",
        },
    }
    return pack


def _format_list(lines: list[str]) -> list[str]:
    if not lines:
        return ["  - None"]
    return [f"  - {line}" for line in lines]


def format_target_experiences(experiences: dict) -> list[str]:
    """Render the bounded experience view without loading or changing its source."""
    experience_lines = []
    if experiences:
        experience_lines = [
            *format_current_handoff(experiences),
            "- Target experiences (bounded history; historical intents are not pending actions):",
            *_format_list([
                "[{id}/{kind}] {text} | conditions={conditions} | reopen_when={reopen} | "
                "next_intent={next_intent} | evidence={evidence}".format(
                    id=item.get("entry_id", ""),
                    kind=item.get("kind", ""),
                    text=json.dumps(item.get("text", ""), ensure_ascii=False),
                    conditions=json.dumps((item.get("structured") or {}).get("conditions") or "unknown", ensure_ascii=False),
                    reopen=json.dumps((item.get("structured") or {}).get("reopen_when") or "none", ensure_ascii=False),
                    next_intent=json.dumps((item.get("structured") or {}).get("next_intent") or "none", ensure_ascii=False),
                    evidence=", ".join(item.get("evidence_refs") or []) or "none",
                )
                for item in experiences.get("items", [])
            ]),
            f"  Showing {len(experiences.get('items', []))} of {experiences.get('total', 0)}; "
            f"{experiences.get('remaining', 0)} more.",
        ]
        if experiences.get("next_command"):
            experience_lines.append(f"  Next page: {experiences['next_command']}")
        if experiences.get("items"):
            experience_lines.append(f"  Expand: {experiences['expand_command']}")
    return experience_lines


def format_context_pack(pack: dict) -> str:
    lines = [
        "CONTEXT PACK",
        f"- Target: {pack['target']}",
        f"- Phase: {pack['phase']}",
        f"- Active goal: {pack.get('active_goal') or '-'}",
        f"- Current hypothesis: {pack.get('current_hypothesis') or '-'}",
        f"- Tech stack: {', '.join(pack.get('tech_stack') or []) or '-'}",
        "- Facts (from the target's goal memory):",
        *_format_list([
            "{text}".format(text=str(item.get("text") or item.get("fact") or ""))
            for item in pack.get("facts", [])
        ] if pack.get("facts") else ["-"]),
        *format_target_experiences(pack.get("target_experiences") or {}),
        "- Skill recommendation retired (S1 native loading): select and load skills on demand via the Claude Code Skill tool (the platform's skill listing is the routing surface).",
        "- Must read:",
        *_format_list(pack["must_read"]),
        "- Card selection retired (2026-09-13 native audit): the catalog below is the discovery surface; AI selects cards by information gap.",
        "- Knowledge card catalog:",
        *_format_list([
            "{file} — layer={layer}, load={load}, purpose={purpose}".format(
                file=item.get("file", ""),
                layer=item.get("layer", ""),
                load=item.get("load", ""),
                purpose=item.get("purpose", ""),
            )
            for item in pack.get("card_catalog", [])
        ]),
        "- Historical patterns (advisory; require current-target evidence):",
        *_format_list(pack.get("historical_patterns", [])),
        "- Required checks:",
        *_format_list(pack["required_checks"]),
        "- Evidence anchors:",
        *_format_list(pack["evidence_anchors"]),
        *format_source_queries(pack.get("source_queries") or {}),
        "- Validation runner candidate evidence (advisory; not report-ready):",
        *_format_list(format_validation_runner_candidate_lines(
            pack.get("validation_runner_candidates", []),
            limit=6,
        )),
        "- Unknowns:",
        *_format_list(pack["unknowns"]),
        "- Actor matrix gaps:",
        *_format_list([
            "{endpoint} x {vuln}: {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=item.get("endpoint", ""),
                vuln=item.get("vuln_class", ""),
                actor=item.get("actor", ""),
                scope=item.get("object_scope", ""),
                variant=item.get("variant", ""),
                expected=item.get("expected", ""),
                status=item.get("status", ""),
            )
            for item in pack.get("actor_matrix_gaps", [])
        ]),
        "- Contradictions:",
        *_format_list(pack["contradictions"]),
        "- Do not load:",
        *_format_list(pack["do_not_load"]),
        "- Write-back:",
        *_format_list(pack["write_back"]),
        f"- AI override: {pack['ai_override']}",
    ]
    return "\n".join(lines)


def format_source_queries(queries: dict) -> list[str]:
    """Anchors are previews, not pages; expansion starts from each full source."""
    lines = []
    surface = queries.get("surface") or {}
    continuation = surface.get("continuation") or {}
    if continuation.get("available") and continuation.get("command"):
        lines.extend([
            f"- Indexed URLs: {surface['row_count']}; anchors are a preview, including external context in the full query.",
            f"  Query from first page: {continuation['command']}",
        ])
    elif surface:
        lines.append(f"- Surface index: {surface.get('status', 'unavailable')}; no complete index query is available.")
    coverage = queries.get("coverage") or {}
    if coverage.get("command"):
        lines.extend([
            f"- Unresolved coverage cells: {coverage['total']}; order={coverage['order']}; anchors are a preview.",
            f"  Full coverage query: {coverage['command']}",
        ])
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a read-only Claude CLI context pack for one target."
    )
    parser.add_argument("args", nargs="*", help="optional target and/or focus words")
    parser.add_argument("--target", default="", help="target; defaults to active target memory")
    parser.add_argument("--focus", default="", help="focus such as api-idor, graphql, upload, race")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--memory-dir", default="")
    parser.add_argument("--json", action="store_true", help="output JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)
    target, focus = _resolve_cli_args(args, repo_root)
    pack = build_context_pack(
        repo_root,
        target=target,
        focus=focus,
        memory_dir=args.memory_dir or None,
    )
    if args.json:
        print(json.dumps(pack, ensure_ascii=False, indent=2))
    else:
        print(format_context_pack(pack))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
