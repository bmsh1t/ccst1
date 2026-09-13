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
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

try:
    from tools.evidence_ledger import load_entries
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from evidence_ledger import load_entries  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


def _load_source_evidence(repo: Path, target: str) -> dict:
    """拉三类原始证据（机器事实，非 AI 回忆）。"""
    key = target_storage_key(target)
    entries = load_entries(repo, target)
    findings: list[dict] = []
    findings_path = repo / "findings" / key / "findings.json"
    if findings_path.is_file():
        try:
            payload = json.loads(findings_path.read_text(encoding="utf-8", errors="replace"))
            findings = payload if isinstance(payload, list) else payload.get("findings") or []
        except (OSError, json.JSONDecodeError):
            findings = []
    case_state: dict = {}
    case_path = repo / "state" / key / "case_state.json"
    if case_path.is_file():
        try:
            case_state = json.loads(case_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            case_state = {}
    return {"ledger": entries, "findings": findings, "case_state": case_state}


def _bounded_evidence_view(evidence: dict, limit: int = 40) -> str:
    """把原始证据压成 AI 可读的有界视图。"""
    lines: list[str] = []
    entries = evidence["ledger"][-limit:]
    if entries:
        lines.append(f"## Evidence Ledger（最近 {len(entries)} 条，机器事实）")
        for e in entries:
            lines.append(
                "- {event} {method} {endpoint} [{cls}/{actor}/{variant}] result={result} ref={ref}".format(
                    event=str(e.get("event_id") or "")[:44],
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
        lines.append(f"## Findings（前 {len(findings)} 条）")
        for f in findings:
            lines.append(
                "- {id} [{cls}] {title} status={status} endpoint={endpoint}".format(
                    id=str(f.get("id") or f.get("finding_id") or "")[:24],
                    cls=str(f.get("vuln_class") or ""),
                    title=str(f.get("title") or "")[:80],
                    status=str(f.get("status") or ""),
                    endpoint=str(f.get("endpoint") or "")[:80],
                )
            )
    case_state = evidence["case_state"]
    if case_state:
        actors = case_state.get("actors") or []
        objects = case_state.get("objects") or []
        lines.append("## Case State（角色/对象）")
        if actors:
            lines.append(f"- actors: {json.dumps(actors, ensure_ascii=False)[:400]}")
        if objects:
            lines.append(f"- objects: {json.dumps(objects, ensure_ascii=False)[:400]}")
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
            "findings": len(evidence["findings"]),
            "case_state": bool(evidence["case_state"]),
        },
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
