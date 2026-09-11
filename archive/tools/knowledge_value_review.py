#!/usr/bin/env python3
"""生成并审计正式知识卡的全量价值/重叠复核矩阵。

矩阵是人工/Claude 复核的可追溯产物，不是 runtime 路由状态。工具只生成可复核的
职责、来源和重叠投影，并校验 active card ID 覆盖；处置结论必须由人明确给出。
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX_PATH = BASE_DIR / "knowledge" / "governance" / "value-review.json"
DISPOSITIONS = {"keep", "keep-draft", "merge", "downgrade", "archive", "ab-required"}
SPECIAL_REVIEWS: dict[str, dict[str, str]] = {
    "payment-callback-idempotency": {
        "unique_value": "把回调签名消费、事件归属、乱序重放和幂等键连成一条验证连接器",
        "reason": "与业务状态机、签名和 race 卡有交集，但组合顺序仍可作为按需连接器；当前没有 live A/B，保持 draft。",
    },
    "cicd-trust-boundaries": {
        "unique_value": "沿 workflow -> runner -> OIDC/secret -> deploy 连接器追踪信任边界",
        "reason": "与 cicd-security Skill 重叠较高，保留压缩的边界触发和停止条件，不宣称模型增量。",
    },
    "cloud-control-plane-pivots": {
        "unique_value": "把 SSRF/源码/CI 线索连接到 identity -> permission -> control-plane action",
        "reason": "来源指针不足且当前是 reference/signal-only；保持 draft，不伪造 case-router 或 proven。",
    },
    "dns-email-trust-boundaries": {
        "unique_value": "区分 DNS/email 记录常识与 recovery、SSO、sender-trust 连接器",
        "reason": "基础 SPF/DKIM/DMARC 常识可能已知，暂保留可迁移的身份恢复边界和停止条件，未做 live A/B。",
    },
}

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.knowledge_registry import (
        KnowledgeRegistryError,
        load_registry,
        parse_knowledge_document,
        parse_source_refs,
    )
    from tools.knowledge_lifecycle import review_card
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_registry import (  # type: ignore
        KnowledgeRegistryError,
        load_registry,
        parse_knowledge_document,
        parse_source_refs,
    )
    from knowledge_lifecycle import review_card  # type: ignore


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_section(body: str, heading: str) -> str:
    pattern = re.compile(
        rf"^##\s+{re.escape(heading)}\s*$\n(?P<body>.*?)(?=^##\s+|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(body)
    if not match:
        return ""
    return " ".join(line.strip(" -*") for line in match.group("body").splitlines() if line.strip())


def _overlap_graph(entries: list[dict[str, Any]]) -> dict[str, list[str]]:
    tags = {
        str(item["card_id"]): set(item.get("trigger_tags") or [])
        for item in entries
    }
    result: dict[str, list[str]] = {}
    for card_id, current in tags.items():
        candidates: list[tuple[int, str]] = []
        for other_id, other in tags.items():
            if card_id == other_id:
                continue
            score = len(current & other)
            if score:
                candidates.append((score, other_id))
        candidates.sort(key=lambda item: (-item[0], item[1]))
        result[card_id] = [item[1] for item in candidates[:5]]
    return result


def build_matrix(
    repo_root: Path | str = BASE_DIR,
    *,
    reviewer: str = "Codex",
    model_profile: str = "claude-cli/static-review/2026-07-13",
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    registry = load_registry(repo)
    entries: list[dict[str, Any]] = []
    for capability in registry.by_kind("card"):
        card_id = str(capability.get("id") or "")
        card_path = str(capability.get("file") or "")
        path = repo / card_path
        parsed = parse_knowledge_document(path.read_text(encoding="utf-8"))
        if parsed.metadata is None:
            raise KnowledgeRegistryError(f"{card_path}: frontmatter missing")
        metadata = parsed.metadata
        refs = parse_source_refs(metadata, source_path=card_path)
        tags = [str(item).strip().casefold() for item in metadata.get("trigger_tags", [])]
        unique = _extract_section(parsed.body, "能力定位")
        override = SPECIAL_REVIEWS.get(card_id, {})
        if override.get("unique_value"):
            unique = override["unique_value"]
        if not unique:
            unique = f"{capability.get('purpose', 'knowledge')} card for {', '.join(tags[:4]) or 'target evidence'}"
        layer = str(capability.get("layer") or "")
        source_strength = "case-pointers" if refs else "none"
        entries.append(
            {
                "card_id": card_id,
                "card_path": card_path,
                "layer": layer,
                "load": str(capability.get("load") or ""),
                "maturity": str(metadata.get("maturity") or ""),
                "trigger_tags": tags,
                "source_refs_count": len(refs),
                "source_strength": source_strength,
                "unique_value": unique[:500],
                "overlap_with": [],
                "ai_likely_known": "likely" if layer == "core" else "partial",
                "disposition": "keep-draft",
                "reason": override.get(
                    "reason",
                    "静态职责/边界复核通过；保留按需价值，但没有 live A/B 或正式增量证据，保持 draft。",
                ),
                "reviewer": reviewer,
                "model_profile": model_profile,
                "evidence_refs": [card_path],
                "ab_required": False,
                "ab_status": "not-required-static-review",
                "ab_success_criteria": "仅在争议或准备晋升时执行 hard-case baseline/enhanced A/B；本轮不声称 lift。",
            }
        )
    overlaps = _overlap_graph(entries)
    for item in entries:
        item["overlap_with"] = overlaps[item["card_id"]]
    return {
        "schema_version": 1,
        "generated_at": _now(),
        "reviewer": reviewer,
        "model_profile": model_profile,
        "dispositions": sorted(DISPOSITIONS),
        "cards": sorted(entries, key=lambda item: item["card_id"]),
    }


def write_matrix(matrix: dict[str, Any], path: Path | str = DEFAULT_MATRIX_PATH) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(destination)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
        raise
    return destination


def audit_matrix(
    repo_root: Path | str = BASE_DIR,
    *,
    matrix_path: Path | str = DEFAULT_MATRIX_PATH,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    path = Path(matrix_path)
    errors: list[str] = []
    try:
        matrix = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "errors": [f"cannot read value matrix: {exc}"], "cards": 0}
    if not isinstance(matrix, dict):
        return {"ok": False, "errors": ["value matrix root must be an object"], "cards": 0}
    if matrix.get("schema_version") != 1:
        errors.append("matrix.schema_version must be 1")
    for field in ("generated_at", "reviewer", "model_profile"):
        if not str(matrix.get(field) or "").strip():
            errors.append(f"matrix.{field} is required")
    dispositions = matrix.get("dispositions")
    if (
        not isinstance(dispositions, list)
        or any(not isinstance(value, str) for value in dispositions)
        or set(dispositions) != DISPOSITIONS
    ):
        errors.append("matrix.dispositions does not match the supported disposition set")
    try:
        registry_entries = {
            str(item["id"]): item for item in load_registry(repo).by_kind("card")
        }
        registry_ids = set(registry_entries)
    except (KnowledgeRegistryError, KeyError) as exc:
        return {"ok": False, "errors": [str(exc)], "cards": 0}
    rows = matrix.get("cards")
    if not isinstance(rows, list):
        return {"ok": False, "errors": ["matrix.cards must be a list"], "cards": 0}
    actual_id_list = [
        str(item.get("card_id") or "") for item in rows if isinstance(item, dict)
    ]
    duplicate_ids = sorted(
        card_id
        for card_id, count in Counter(actual_id_list).items()
        if card_id and count > 1
    )
    if duplicate_ids:
        errors.append(f"matrix contains duplicate card IDs: {duplicate_ids}")
    actual_ids = set(actual_id_list)
    if actual_ids != registry_ids:
        errors.append(f"matrix/card ID mismatch: missing={sorted(registry_ids - actual_ids)} extra={sorted(actual_ids - registry_ids)}")
    for item in rows:
        if not isinstance(item, dict):
            errors.append("matrix row must be an object")
            continue
        card_id = str(item.get("card_id") or "")
        if not card_id:
            errors.append("matrix row missing card_id")
            continue
        for field in (
            "card_path",
            "layer",
            "load",
            "maturity",
            "unique_value",
            "source_strength",
            "ai_likely_known",
            "disposition",
            "reason",
            "reviewer",
            "model_profile",
        ):
            if not str(item.get(field) or "").strip():
                errors.append(f"{card_id}: missing {field}")
        if item.get("disposition") not in DISPOSITIONS:
            errors.append(f"{card_id}: invalid disposition {item.get('disposition')!r}")
        if item.get("ai_likely_known") not in {"likely", "partial", "unknown"}:
            errors.append(f"{card_id}: invalid ai_likely_known")
        overlaps = item.get("overlap_with")
        if not isinstance(overlaps, list) or any(
            not isinstance(value, str) or not value for value in overlaps
        ):
            errors.append(f"{card_id}: overlap_with must be a card ID list")
        else:
            if len(overlaps) != len(set(overlaps)):
                errors.append(f"{card_id}: overlap_with contains duplicates")
            if card_id in overlaps:
                errors.append(f"{card_id}: overlap_with cannot reference itself")
            unknown_overlaps = sorted(set(overlaps) - registry_ids)
            if unknown_overlaps:
                errors.append(f"{card_id}: overlap_with references unknown cards {unknown_overlaps}")
        ab_required = item.get("ab_required")
        if not isinstance(ab_required, bool):
            errors.append(f"{card_id}: ab_required must be boolean")
        elif (item.get("disposition") == "ab-required") != ab_required:
            errors.append(f"{card_id}: disposition and ab_required disagree")
        for field in ("ab_status", "ab_success_criteria"):
            if not str(item.get(field) or "").strip():
                errors.append(f"{card_id}: missing {field}")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list) or not refs:
            errors.append(f"{card_id}: evidence_refs required")
        else:
            for ref in refs:
                target = str(ref).split("#", 1)[0]
                if not target or not (repo / target).is_file():
                    errors.append(f"{card_id}: evidence ref missing {ref}")
        registry_entry = registry_entries.get(card_id)
        if registry_entry is None:
            continue
        expected_path = str(registry_entry.get("file") or "")
        for field, expected in (
            ("card_path", expected_path),
            ("layer", str(registry_entry.get("layer") or "")),
            ("load", str(registry_entry.get("load") or "")),
        ):
            if item.get(field) != expected:
                errors.append(f"{card_id}: {field} differs from registry")
        try:
            parsed = parse_knowledge_document(
                (repo / expected_path).read_text(encoding="utf-8")
            )
            if parsed.frontmatter_error:
                raise KnowledgeRegistryError(parsed.frontmatter_error)
            if parsed.metadata is None:
                raise KnowledgeRegistryError("card frontmatter missing")
            source_refs = parse_source_refs(parsed.metadata, source_path=expected_path)
        except (OSError, UnicodeError, KnowledgeRegistryError) as exc:
            errors.append(f"{card_id}: cannot verify current card projection: {exc}")
            continue
        expected_tags = [
            str(value).strip().casefold()
            for value in parsed.metadata.get("trigger_tags", [])
        ]
        if item.get("trigger_tags") != expected_tags:
            errors.append(f"{card_id}: trigger_tags differ from card frontmatter")
        if item.get("maturity") != str(parsed.metadata.get("maturity") or ""):
            errors.append(f"{card_id}: maturity differs from card frontmatter")
        if item.get("source_refs_count") != len(source_refs):
            errors.append(f"{card_id}: source_refs_count differs from card frontmatter")
        expected_strength = "case-pointers" if source_refs else "none"
        if item.get("source_strength") != expected_strength:
            errors.append(f"{card_id}: source_strength differs from card frontmatter")
    return {
        "ok": not errors,
        "errors": list(dict.fromkeys(errors)),
        "cards": len(rows),
        "registry_cards": len(registry_ids),
    }


def apply_reviews(
    repo_root: Path | str = BASE_DIR,
    *,
    matrix_path: Path | str = DEFAULT_MATRIX_PATH,
    events_path: Path | str | None = None,
) -> dict[str, Any]:
    """将矩阵中的人工复核记录追加到正式卡治理日志；不改变卡片 verdict。"""
    repo = Path(repo_root).resolve()
    matrix = json.loads(Path(matrix_path).read_text(encoding="utf-8"))
    applied = 0
    skipped = 0
    errors: list[str] = []
    try:
        from tools.knowledge_lifecycle import replay_events
    except ImportError:  # pragma: no cover
        from knowledge_lifecycle import replay_events  # type: ignore
    states, replay_errors = replay_events(repo, events_path=events_path)
    if replay_errors:
        return {"ok": False, "applied": 0, "skipped": 0, "errors": replay_errors}
    for row in matrix.get("cards", []):
        card_id = str(row.get("card_id") or "")
        state = states.get(card_id)
        if state and state.get("last_event") == "reviewed":
            skipped += 1
            continue
        try:
            review_card(
                card_id,
                repo_root=repo,
                maturity="draft",
                reviewer=str(row.get("reviewer") or "Codex"),
                reason=str(row.get("reason") or "static value review"),
                model_profile=str(row.get("model_profile") or "static-review"),
                evidence_refs=row.get("evidence_refs") or [],
                events_path=events_path,
            )
            applied += 1
        except Exception as exc:  # preserve card-specific diagnostic and continue other rows
            errors.append(f"{card_id}: {exc}")
    return {"ok": not errors, "applied": applied, "skipped": skipped, "errors": errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=BASE_DIR)
    parser.add_argument("--matrix-path", type=Path, default=None)
    parser.add_argument("--events-path", type=Path, default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("generate", "audit", "apply"):
        item = sub.add_parser(name)
        item.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    repo = Path(args.repo_root).resolve()
    matrix_path = args.matrix_path or repo / "knowledge" / "governance" / "value-review.json"
    try:
        if args.command == "generate":
            value = build_matrix(repo)
            write_matrix(value, matrix_path)
            result = {"path": str(matrix_path), "cards": len(value["cards"])}
        elif args.command == "audit":
            result = audit_matrix(repo, matrix_path=matrix_path)
        else:
            result = apply_reviews(repo, matrix_path=matrix_path, events_path=args.events_path)
    except (OSError, ValueError, KnowledgeRegistryError) as exc:
        print(f"knowledge value review failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
