#!/usr/bin/env python3
"""Bounded, read-only surface facts and knowledge-backed questions; never a router."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import islice
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

try:
    from tools.knowledge_registry import KnowledgeRegistryError, parse_knowledge_document
    from tools.experience_knowledge import capture_source, check_capture
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_registry import KnowledgeRegistryError, parse_knowledge_document
    from experience_knowledge import capture_source, check_capture


MAX_ITEMS = 16
MATERIAL_CARD = "surface-unknown-probes"


def _known_facts(item: dict) -> dict:
    methods, content_types, body_names = set(), set(), set()
    # Browser importers can default methods and infer MIME from body text.
    # Preserve those hints without promoting them to raw request facts.
    shapes = item.get("request_shapes")
    for shape in shapes if isinstance(shapes, list) else []:
        if not isinstance(shape, dict):
            continue
        method = str(shape.get("method") or "").strip().upper()
        if method:
            methods.add(method)
        body = shape.get("body") if isinstance(shape.get("body"), dict) else {}
        if body.get("content_type_hint"):
            content_types.add(str(body["content_type_hint"]).lower())
        names = body.get("parameter_names")
        if isinstance(names, list):
            body_names.update(str(name) for name in names if str(name))
    return {
        "request_shape_hints": {
            "methods": sorted(methods), "body_types": sorted(content_types),
            "body_parameter_names": sorted(body_names),
        },
        "method_and_content_type_status": "unverified; raw request inspection required",
        "query_parameter_names": sorted({key for key, _ in parse_qsl(urlparse(item["url"]).query, keep_blank_values=True)}),
        "side_effects": "unknown; HTTP method alone is not evidence",
        "source_names": list(item.get("source_names") or []),
        "evidence_refs": [str(ref) for ref in item.get("evidence_refs") or [] if str(ref)],
    }


def _surface_family(item: dict, facts: dict) -> str:
    hints = facts["request_shape_hints"]
    types = hints["body_types"]
    if any("multipart/" in value for value in types):
        return "multipart_request"
    if any("json" in value or "graphql" in value for value in types):
        return "structured_request"
    if facts["query_parameter_names"] or hints["body_parameter_names"]:
        return "parameterized_surface"
    if hints["methods"]:
        return "request_shape_hint"
    if item.get("scanner_findings"):
        return "scanner_signal"
    return "unobserved_request"


def _load_material(repo: Path) -> tuple[dict, dict]:
    captured = capture_source(repo, MATERIAL_CARD)
    if captured["status"] != "available":
        raise ValueError(f"surface advisory knowledge {captured['status']}: {captured.get('reason', '')}")
    # Parse the bytes already accepted by the common source owner. A second
    # filesystem read after review could consume a different publication.
    path = captured["file"]
    document = parse_knowledge_document(captured["files"][repo.absolute() / path][1].decode("utf-8"))
    if document.frontmatter_error or not document.metadata or document.metadata.get("id") != MATERIAL_CARD:
        raise ValueError("invalid surface advisory knowledge frontmatter")
    material = document.metadata.get("surface_advisory")
    if not isinstance(material, dict):
        raise ValueError("surface advisory knowledge material missing")
    for family in ("multipart_request", "structured_request", "parameterized_surface", "request_shape_hint", "scanner_signal", "unobserved_request"):
        entry = material.get(family)
        if not isinstance(entry, dict):
            raise ValueError(f"surface advisory family missing: {family}")
        for key in ("questions", "stop_conditions"):
            values = entry.get(key)
            if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v.strip() for v in values):
                raise ValueError(f"surface advisory {family}.{key} must contain text")
        if any(not isinstance(entry.get(key), str) or not entry[key].strip() for key in ("action", "why", "hint")):
            raise ValueError(f"surface advisory probe missing: {family}")
    check_capture(captured)
    return material, {"card_id": MATERIAL_CARD, "path": path, "section": "frontmatter.surface_advisory",
                      "review_state": "reviewed", **captured["binding"]}


def build_surface_advisory(
    candidates: Iterable[dict] | None, *, target: str, repo_root: str | Path | None = None,
) -> dict:
    """Project only the existing review window, preserving AI applicability judgment."""
    result = {
        "schema_version": 1, "target": target, "bounded": True, "limit": MAX_ITEMS,
        "network_requests": 0, "items": [],
        "contract": "advisory-only; shape labels are not vulnerability, risk or Skill decisions",
    }
    window = list(islice(iter(candidates or []), MAX_ITEMS + 1))
    result["has_more_candidates"] = len(window) > MAX_ITEMS
    window = window[:MAX_ITEMS]
    if not window:
        return {**result, "status": "empty"}
    try:
        material, source = _load_material(Path(repo_root or Path(__file__).resolve().parents[1]))
    except (OSError, ValueError, KnowledgeRegistryError) as exc:
        return {**result, "status": "unavailable", "reason": str(exc)[:300]}
    result["knowledge_source"] = source
    invalid_items = []
    for index, candidate in enumerate(window):
        if not isinstance(candidate, dict) or not isinstance(candidate.get("url"), str) or not candidate["url"].strip():
            invalid_items.append({"index": index, "reason": "missing surface URL"})
            continue
        try:
            parsed = urlparse(candidate["url"])
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("surface URL must be absolute HTTP(S)")
        except ValueError as exc:
            invalid_items.append({"index": index, "reason": str(exc)[:160]})
            continue
        facts = _known_facts(candidate)
        family = _surface_family(candidate, facts)
        entry = material[family]
        result["items"].append({
            "url": candidate["url"], "surface_family": family,
            "classification_basis": "heuristic request-shape hints and URL parameter names; defaults unverified; no value ranking",
            "known_facts": facts, "evidence_refs": facts["evidence_refs"],
            "unknown_questions": entry["questions"][:3],
            "smallest_safe_probe": {
                "action": entry["action"], "why": entry["why"], "hint": entry["hint"],
                "mode": "inspect_existing_material",
                "network_request": False,
                "requires": "existing raw evidence; missing evidence remains unknown, AI authors any live probe",
            },
            "stop_conditions": entry["stop_conditions"][:3],
            "knowledge_source": {**source, "family": family},
            "route_owner": "AI/native Skill selection", "queue_action": False,
        })
    return {
        **result, "status": "partial" if invalid_items else "ready" if result["items"] else "empty",
        "invalid_items": invalid_items,
    }
