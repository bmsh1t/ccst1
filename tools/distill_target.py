#!/usr/bin/env python3
"""Target-scoped knowledge distillation (straight-line, no state machine).

两段式出题-收卷协议：

```
prompt  机器拉原始证据（ledger/findings/case_state），按类型学出蒸馏题
commit  AI 提三元组回传 --triple-json，机器 scrub 脱敏 + 渲染草稿卡
        -> knowledge/candidates/<slug>.md（maturity: draft）
```

人工审核即生命周期：`mv` 进 knowledge/cards/ 是 promote，`rm` 是 reject。
git 历史就是治理审计，不再有第二个状态机（零-B 已删）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent

try:
    from tools.evidence_ledger import load_entries
    from tools.experience_schema import scrub_experience_text
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    sys.path.insert(0, str(BASE_DIR))
    from evidence_ledger import load_entries  # type: ignore
    from experience_schema import scrub_experience_text  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


# 类型学（vuln_memory /sub 的四类）：Pattern / Target→Vuln / 失败教训 / 绕过关系
TYPOLOGIES = {
    "pattern": {
        "label": "Pattern（可复用模式）",
        "prompt": (
            "从下面的原始证据里提炼一条可跨目标复用的模式：什么信号 → 什么验证路径 → "
            "什么停止条件。写成三元组 {pattern, trigger, action}，"
            "trigger 必须是可观察的证据形态（不是类别名），action 是最小验证动作。"
        ),
    },
    "target-vuln": {
        "label": "Target→Vuln（目标特征→漏洞倾向）",
        "prompt": (
            "从下面的原始证据里提炼一条\"这类目标/技术栈/接口形态上什么漏洞密度高\"的"
            "对应关系。写成三元组 {pattern, trigger, action}，pattern 是目标特征描述，"
            "trigger 是识别该特征的具体信号，action 是首选验证入口。"
        ),
    },
    "failure": {
        "label": "失败教训（误判/死路）",
        "prompt": (
            "从下面的原始证据里找出已验证的失败方向：什么信号看起来像漏洞但其实不是，"
            "或什么验证路径在此证据下不成立。写成三元组 {pattern, trigger, action}，"
            "pattern 必须包含误判边界（什么情况下它是死路）。"
        ),
    },
    "bypass": {
        "label": "绕过关系（A 失败 → B 绕过成立）",
        "prompt": (
            "从下面的原始证据里提炼绕过/链关系：某个直接路径被挡但有替代路径，或某个"
            "原语是另一个更高影响原语的跳板。写成三元组 {pattern, trigger, action}，"
            "pattern 说明 A→B 关系，action 是验证 B 的最小动作。"
        ),
    },
}

TRIPLE_REQUIRED_FIELDS = ("pattern", "trigger", "action")


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


def build_prompt(repo: Path, target: str, typology: str) -> dict:
    """出题：机器拉证据 + 类型学模板，返回给 AI 的蒸馏题。"""
    if typology not in TYPOLOGIES:
        raise ValueError(
            f"unknown typology {typology!r}; allowed: {', '.join(sorted(TYPOLOGIES))}"
        )
    evidence = _load_source_evidence(repo, target)
    view = _bounded_evidence_view(evidence)
    spec = TYPOLOGIES[typology]
    question = (
        f"# 蒸馏题：{spec['label']}\n\n目标：{target}\n\n{spec['prompt']}\n\n"
        f"返回 JSON：{{\"typology\": \"{typology}\", \"pattern\": \"...\", "
        "\"trigger\": \"...\", \"action\": \"...\", \"evidence_refs\": [\"...\"]}}\n"
        "evidence_refs 必须来自下方视图里的 ref/路径，不得编造。\n\n" + view
    )
    return {
        "schema_version": 1,
        "target": target,
        "typology": typology,
        "question": question,
        "evidence_counts": {
            "ledger": len(evidence["ledger"]),
            "findings": len(evidence["findings"]),
            "case_state": bool(evidence["case_state"]),
        },
        "next": (
            "AI 在当前会话读题并提三元组，然后执行："
            "python3 tools/distill_target.py commit --target <t> "
            "--triple-json /tmp/triple.json --json"
        ),
    }


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(text or "").strip().lower()).strip("-")
    return slug[:48] or "untitled"


def _scrub_triple(triple: dict) -> dict:
    """脱敏：email/token/IP/密钥不进卡是红线级 gate，命中即拒绝写入。"""
    joined = " ".join(str(triple.get(k) or "") for k in TRIPLE_REQUIRED_FIELDS)
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", joined):
        raise ValueError(
            "triple contains a bare IPv4 address; scrub it before commit "
            "(evidence_refs keep the machine path, prose stays de-sensitized)"
        )
    if re.search(r"\b(?:password|secret|api[_-]?key|token)\s*[:=]\s*\S+", joined, re.I):
        raise ValueError(
            "triple contains credential-shaped text; remove it before commit"
        )
    out = {k: scrub_experience_text(str(triple.get(k) or "").strip()) for k in TRIPLE_REQUIRED_FIELDS}
    out["typology"] = str(triple.get("typology") or "").strip() or "pattern"
    out["evidence_refs"] = [str(r).strip() for r in triple.get("evidence_refs") or [] if str(r).strip()]
    return out


def _validate_evidence_refs(repo: Path, target: str, refs: list[str]) -> list[str]:
    """refs 必须指向目标名下真实存在的文件（可溯源）。"""
    key = target_storage_key(target)
    allowed_prefixes = (f"evidence/{key}/", f"findings/{key}/", f"state/{key}/")
    resolved: list[str] = []
    for ref in refs:
        if not ref.startswith(allowed_prefixes):
            raise ValueError(
                f"evidence_ref {ref!r} is not target-owned (must start with one of "
                f"{allowed_prefixes})"
            )
        if not (repo / ref).exists():
            raise ValueError(f"evidence_ref {ref!r} does not exist on disk")
        resolved.append(ref)
    if not resolved:
        raise ValueError("at least one target-owned evidence_ref is required")
    return resolved


def render_candidate_card(target: str, triple: dict, refs: list[str]) -> str:
    """渲染 card-template.md 形态的草稿卡（maturity: draft）。"""
    typology = triple["typology"]
    evidence_lines = "\n".join(f"- `{r}`" for r in refs)
    # source_refs 必须满足 knowledge_registry 的 target-evidence 契约
    # （type/target/refs 列表形态）；旧的 json.dumps 内联形态 promote 后
    # 无法通过 audit（记忆复核断点 A，2026-09-12 修复）。
    ref_lines = "\n".join(f"      - {json.dumps(r, ensure_ascii=False)}" for r in refs)
    return f"""---
id: {triple['slug']}
type: technique-card
related_skills: []
trigger_tags:
  - {triple['slug']}
risk: low
maturity: draft
load_priority: low
source_refs:
  - type: target-evidence
    target: {canonical_target_value(target)}
    refs:
{ref_lines}
updated: {datetime.now(timezone.utc).date().isoformat()}
---

# {triple['pattern']}

蒸馏类型：{TYPOLOGIES.get(typology, TYPOLOGIES['pattern'])['label']}

## 触发信号

- {triple['trigger']}

## 思路分支 / 最小验证

- {triple['action']}

## 证据

- 来源目标：{canonical_target_value(target)}（脱敏后写入）
- 原始证据：
{evidence_lines}

## 人工审核（review 后改这里）

- mv 进 `knowledge/cards/` 即 promote；rm 即 reject；git log 即审计。
- promote 前检查：trigger 是否可观察、action 是否最小、误判边界是否写清。
"""


def commit_triple(
    repo: Path,
    target: str,
    triple_json: str,
    *,
    slug_hint: str = "",
) -> dict:
    """收卷：AI 三元组 → scrub → 渲染草稿卡 → knowledge/candidates/<slug>.md。"""
    try:
        triple = json.loads(Path(triple_json).read_text(encoding="utf-8")) if Path(triple_json).is_file() else json.loads(triple_json)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read --triple-json: {exc}") from exc
    if not isinstance(triple, dict):
        raise ValueError("--triple-json must be a JSON object")
    for field in TRIPLE_REQUIRED_FIELDS:
        if not str(triple.get(field) or "").strip():
            raise ValueError(
                f"triple field {field!r} is required and non-empty; "
                f"required: {', '.join(TRIPLE_REQUIRED_FIELDS)}"
            )
    scrubbed = _scrub_triple(triple)
    refs = _validate_evidence_refs(repo, target, scrubbed["evidence_refs"])
    slug = _slugify(slug_hint or scrubbed["pattern"])
    candidates_dir = repo / "knowledge" / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)
    path = candidates_dir / f"{slug}.md"
    serial = 2
    while path.exists():
        path = candidates_dir / f"{slug}-{serial}.md"
        serial += 1
    scrubbed["slug"] = path.stem
    path.write_text(render_candidate_card(target, scrubbed, refs), encoding="utf-8")
    return {
        "schema_version": 1,
        "status": "draft_written",
        "path": str(path.relative_to(repo)),
        "typology": scrubbed["typology"],
        "evidence_refs": refs,
        "review": (
            f"人工审核后 `mv {path.relative_to(repo)} knowledge/cards/{path.name}` 即 promote；"
            f"`rm` 即 reject。frontmatter 的 maturity 保持 draft 直到 promote。"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Target-scoped straight-line knowledge distillation.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_prompt = sub.add_parser("prompt", help="machine: pull evidence and emit the distillation question")
    p_prompt.add_argument("--target", required=True)
    p_prompt.add_argument(
        "--typology",
        default="pattern",
        choices=sorted(TYPOLOGIES),
        help="distillation typology (pattern / target-vuln / failure / bypass)",
    )
    p_prompt.add_argument("--json", action="store_true")
    p_commit = sub.add_parser("commit", help="machine: scrub AI triple and render the draft card")
    p_commit.add_argument("--target", required=True)
    p_commit.add_argument(
        "--triple-json",
        required=True,
        help="JSON object {typology, pattern, trigger, action, evidence_refs} or a path to it",
    )
    p_commit.add_argument("--slug-hint", default="", help="optional short slug override")
    p_commit.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo_root)
    try:
        resolved = canonical_target_value(args.target)
        if args.cmd == "prompt":
            result = build_prompt(repo, resolved, args.typology)
        else:
            result = commit_triple(repo, resolved, args.triple_json, slug_hint=args.slug_hint)
    except (OSError, ValueError, KeyError) as exc:
        print(f"distill failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
