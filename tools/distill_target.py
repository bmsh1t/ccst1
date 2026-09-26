#!/usr/bin/env python3
"""Target-scoped knowledge distillation (direct-write, no state machine).

原生能力审计（2026-09-13）第 3 步：蒸馏的"出题→三元组→渲染"中转已退役。
三元组协议只有 pattern/trigger/action 三个正文必填字段，独立的前提/反例/
停止条件无法保留（实测），强制 Claude 在写 Markdown 之前先写一遍 JSON。

现行契约：
```
evidence  机器拉原始证据（ledger/findings/case_state）出有界视图
          AI 直接读视图，按 card-template.md 格式写完整草稿到
          knowledge/candidates/<slug>.md（maturity: draft）
```

机械保护（脱敏红线、target-owned refs 校验）已迁入 knowledge_audit 的
正式审计边界——草稿在晋升门（knowledge_promote → strict audit）被检查，
不再依赖已退役的 commit 中转。

人工审核即生命周期：knowledge_promote 是 promote，rm 是 reject。
git 历史就是治理审计。
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

try:
    from tools.current_truth import current_cell_projection
    from tools.target_paths import canonical_target_value
    from tools.target_store import ConflictError, runtime_store
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from current_truth import current_cell_projection  # type: ignore
    from target_paths import canonical_target_value  # type: ignore
    from target_store import ConflictError, runtime_store  # type: ignore


def _load_source_evidence(repo: Path, target: str) -> dict:
    """拉三类原始证据（机器事实，非 AI 回忆）。"""
    store = runtime_store(repo, target)
    revision = store.binding()["revision"]
    entries = list(current_cell_projection(repo, target)["records"])
    finding_page = store.finding_page(limit=10)
    findings = finding_page["items"]
    experience_page = store.experience_page(limit=10)
    experiences = experience_page["items"]
    windows = {
        name: {key: page[key] for key in ("total", "remaining", "has_more", "next_cursor",
                                         "store_id", "revision", "order")}
        for name, page in (("findings", finding_page), ("experiences", experience_page))
    }
    commands = {
        "findings": ["python3", "tools/target_store.py", "findings", "--repo-root", str(repo.resolve()),
                     "--limit", "10", "--target", target],
        "experiences": ["python3", "tools/experience_recall.py", "--repo-root", str(repo.resolve()),
                        "--json", "--limit", "10", "--target", target],
    }
    for name, command in commands.items():
        window = windows[name]
        window["next_command"] = (shlex.join([*command, "--cursor", window["next_cursor"]])
                                  if window["has_more"] else "")
        window["expand_command"] = shlex.join([*command, "--id", "FINDING_ID" if name == "findings" else "EXPERIENCE_ID"])
    case_state = store.case_state(include_hypotheses=False)
    if store.binding()["revision"] != revision:
        raise ConflictError("target changed during distillation view; retry")
    return {"target": target, "ledger": entries, "findings": findings, "experiences": experiences,
            "case_state": case_state, "windows": windows,
            "case_expand_command": shlex.join([
                "python3", "tools/target_store.py", "case", "--repo-root", str(repo.resolve()), "--target", target,
            ])}


def _bounded_evidence_view(evidence: dict, limit: int = 40) -> str:
    """把原始证据压成 AI 可读的有界视图。"""
    lines: list[str] = []
    entries = evidence["ledger"][-limit:]
    if entries:
        lines.append(f"## Evidence Ledger（最近 {len(entries)} 条，机器事实）")
        for e in entries:
            lines.append(
                "- {event} {method} {endpoint} [{cls}/{actor}/{variant}] result={result} ref={ref}".format(
                    event=str(e.get("event_id") or ""),
                    method=str(e.get("method") or "GET"),
                    endpoint=str(e.get("endpoint") or ""),
                    cls=str(e.get("vuln_class") or ""),
                    actor=str(e.get("actor") or ""),
                    variant=str(e.get("variant") or ""),
                    result=str(e.get("result") or ""),
                    ref=str(e.get("evidence_ref") or ""),
                )
            )
    findings = evidence["findings"][:10]
    if findings:
        lines.append(f"## Findings（前 {len(findings)} 条；claim 为最多 160 字预览，完整字段按 ID 展开）")
        for f in findings:
            assessment = f.get("assessment") or {}
            technical = assessment.get("verdict") or f.get("validation_status") or f.get("status") or "unassessed"
            deliveries = f.get("deliveries") or []
            lines.append(
                "- {id} [{cls}] {title} technical={status} endpoint={endpoint}".format(
                    id=str(f.get("id") or f.get("finding_id") or ""),
                    cls=str(f.get("family") or f.get("vuln_class") or f.get("type") or ""),
                    title=str(f.get("claim") or f.get("title") or f.get("summary") or "")[:160],
                    status=technical,
                    endpoint=str(f.get("endpoint") or f.get("url") or ""),
                )
            )
            if assessment:
                lines.append(f"  reason={assessment.get('reason') or ''} boundary={assessment.get('boundary') or ''}")
            for delivery in deliveries:
                lines.append(f"  delivery={delivery['destination']}:{delivery['status']} stale={bool(delivery['stale'])}")
            if f.get("evidence"):
                lines.append("  evidence=" + ", ".join(
                    f"{ref['operation_id']}:{ref['step']}" for ref in f["evidence"][:3]))
    experiences = evidence.get("experiences") or []
    if experiences:
        lines.append(f"## Target Experiences（最近 {len(experiences)} 条）")
        for item in experiences:
            lines.append(f"- {item['id']} [{item['kind']}] {item['statement']}")
            lines.append(f"  conditions={item['conditions']} reopen_when={item['reopen_when']} next_intent={item['next_intent']}")
            lines.append(f"  recorded_by={item['recorded_by']}")
            if item.get("evidence"):
                lines.append("  evidence=" + ", ".join(
                    f"{ref['operation_id']}:{ref['step']}" for ref in item["evidence"][:3]))
    for name, window in evidence.get("windows", {}).items():
        lines.append(f"## {name} window: total={window['total']} remaining={window['remaining']}; order={window['order']}")
        if window["next_command"]:
            lines.append(f"  next: {window['next_command']}")
        lines.append(f"  expand: {window['expand_command']}")
    case_state = evidence["case_state"]
    if case_state:
        actors = case_state.get("actors") or []
        objects = case_state.get("objects") or []
        lines.append("## Case State（角色/对象）")
        if actors:
            lines.append(f"- actors: {json.dumps(actors, ensure_ascii=False)[:400]}")
        if objects:
            lines.append(f"- objects: {json.dumps(objects, ensure_ascii=False)[:400]}")
        if evidence.get("case_expand_command"):
            lines.append(f"- Case preview; full context: {evidence['case_expand_command']}")
    return "\n".join(lines) if lines else "(no target-owned evidence found)"


def build_evidence_view(repo: Path, target: str) -> dict:
    """AI 直写草稿前的唯一机器步骤：有界证据视图。"""
    evidence = _load_source_evidence(repo, target)
    return {
        "schema_version": 2,
        "target": target,
        "view": _bounded_evidence_view(evidence),
        "evidence_counts": {
            "ledger": len(evidence["ledger"]),
            "findings": evidence.get("windows", {}).get("findings", {}).get("total", len(evidence["findings"])),
            "experiences": evidence.get("windows", {}).get("experiences", {}).get("total", len(evidence.get("experiences") or [])),
            "case_state": bool(evidence["case_state"]),
        },
        "windows": evidence.get("windows") or {},
        "case_expand_command": evidence.get("case_expand_command", ""),
        "next": (
            "AI 读视图后直接按 knowledge/card-template.md 写完整草稿到 "
            "knowledge/candidates/<slug>.md（maturity: draft，含前提/反例/"
            "停止条件等完整判断单元）；晋升走 "
            "python3 tools/knowledge_promote.py --id <slug>（脱敏与 target-owned "
            "refs 在 strict audit 检查）。"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Target-scoped distillation evidence view (AI writes the draft directly)."
    )
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("evidence", help="machine: pull bounded evidence for AI-side draft writing")
    p.add_argument("--target", required=True)
    p.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo_root)
    try:
        resolved = canonical_target_value(args.target)
        result = build_evidence_view(repo, resolved)
    except (OSError, ValueError, KeyError) as exc:
        print(f"distill failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
