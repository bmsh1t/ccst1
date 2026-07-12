#!/usr/bin/env python3
"""审计知识能力注册表、active 文档结构与项目内引用。"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Literal
from urllib.parse import unquote, urlparse

try:
    import yaml
except ImportError as exc:  # pragma: no cover - 由 requirements.txt 保证
    raise RuntimeError(
        "缺少 PyYAML；请先执行 `python3 -m pip install -r requirements.txt`"
    ) from exc

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.knowledge_registry import KnowledgeRegistry, KnowledgeRegistryError, load_registry
except ImportError:  # pragma: no cover - direct tools/ execution
    from knowledge_registry import (  # type: ignore
        KnowledgeRegistry,
        KnowledgeRegistryError,
        load_registry,
    )


Severity = Literal["error", "warning"]

REGISTRY_PATH = "knowledge/capabilities.yaml"
DOCUMENT_ROOTS = {
    "card": Path("knowledge/cards"),
    "payload-pack": Path("knowledge/payloads"),
    "playbook": Path("knowledge/playbooks"),
}
ALLOWED_KINDS = {*DOCUMENT_ROOTS, "workflow"}
KNOWN_LAYERS = {"core", "reference", "case-router", "payload-pack", "playbook"}
KNOWN_LOAD_MODES = {"default", "signal-or-default", "signal-only", "on-demand", "gated"}
ALLOWED_FRONTMATTER_TYPES = {
    "card": {
        "technique-card",
        "checklist-card",
        "dead-end-card",
        "product-card",
        "workflow-card",
    },
    "payload-pack": {"payload-pack"},
    "playbook": {"workflow-card"},
}
ALLOWED_RISKS = {"low", "low-to-medium", "medium", "medium-to-high", "high"}
ALLOWED_MATURITY = {"draft", "tested", "proven"}
ALLOWED_LOAD_PRIORITY = {"low", "medium", "high"}
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HEADING_RE = re.compile(r"^#{2,6}\s+(.+?)\s*$", re.MULTILINE)
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
FENCED_CODE_RE = re.compile(r"```.*?```|~~~.*?~~~", re.DOTALL)
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")

QUICK_RECALL = ("quick recall", "快速回忆")
CARD_SECTIONS = {
    "触发信号": ("触发信号", "适用场景", "适用边界", "signals", "triggers"),
    "验证或证据": ("最小验证", "检查要求", "证据要求", "验证", "evidence"),
    "误判或停止": ("常见误判", "停止条件", "死路", "收敛", "stop condition"),
    "下一步或晋升": ("推荐动作", "晋升到 skill", "下一步", "可晋升经验", "next action"),
}
PAYLOAD_SECTIONS = {
    "Probe/Payload 家族": ("probe 家族", "payload 家族", "推荐证明方式", "技巧家族"),
    "非默认或停止边界": ("不默认执行", "禁止默认化", "停止条件", "适用边界", "使用前条件"),
    "证据或记录要求": ("证据要求", "记录要求", "最小验证", "evidence"),
}
PLAYBOOK_SECTIONS = {
    "流程": ("流程", "workflow", "攻击链", "验证链"),
    "停止条件": ("停止条件", "stop condition"),
}


@dataclass(frozen=True)
class AuditIssue:
    severity: Severity
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


@dataclass
class AuditReport:
    capabilities: int = 0
    documents: int = 0
    issues: list[AuditIssue] = field(default_factory=list)

    @property
    def ordered_issues(self) -> list[AuditIssue]:
        severity_order = {"error": 0, "warning": 1}
        return sorted(
            self.issues,
            key=lambda item: (
                severity_order[item.severity],
                item.path,
                item.code,
                item.message,
            ),
        )

    @property
    def errors(self) -> int:
        return sum(issue.severity == "error" for issue in self.issues)

    @property
    def warnings(self) -> int:
        return sum(issue.severity == "warning" for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": self.capabilities,
            "documents": self.documents,
            "errors": self.errors,
            "warnings": self.warnings,
            "passed": self.errors == 0,
            "issues": [issue.to_dict() for issue in self.ordered_issues],
        }


def _add(
    report: AuditReport,
    severity: Severity,
    code: str,
    path: str,
    message: str,
) -> None:
    report.issues.append(AuditIssue(severity, code, path, message))


def _active_documents(repo_root: Path) -> dict[str, str]:
    documents: dict[str, str] = {}
    for kind, relative_root in DOCUMENT_ROOTS.items():
        root = repo_root / relative_root
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md")):
            documents[path.relative_to(repo_root).as_posix()] = kind
    return documents


def _valid_string_list(value: Any, *, allow_empty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (allow_empty or bool(value))
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def _contract_string_set(
    report: AuditReport,
    contracts: dict[str, Any],
    key: str,
    fallback: set[str],
) -> set[str]:
    value = contracts.get(key)
    if not _valid_string_list(value):
        _add(
            report,
            "error",
            "registry-contract-field",
            REGISTRY_PATH,
            f"contracts.{key} 必须是非空、无空值的字符串列表",
        )
        return fallback
    if len(value) != len(set(value)):
        _add(
            report,
            "error",
            "registry-contract-field",
            REGISTRY_PATH,
            f"contracts.{key} 不能包含重复值",
        )
    return set(value)


def _contract_budget(
    report: AuditReport,
    contracts: dict[str, Any],
    key: str,
) -> int | None:
    value = contracts.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _add(
            report,
            "error",
            "registry-contract-field",
            REGISTRY_PATH,
            f"contracts.{key} 必须是非负整数",
        )
        return None
    return value


def _entry_path(index: int) -> str:
    return f"{REGISTRY_PATH}#capabilities[{index}]"


def _required_string(
    report: AuditReport,
    entry: dict[str, Any],
    key: str,
    path: str,
) -> str | None:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        _add(
            report,
            "error",
            "capability-required-field",
            path,
            f"`{key}` 必须是非空字符串",
        )
        return None
    return value


def _is_portable_repo_path(value: str) -> bool:
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value == path.as_posix()


def _check_reference(
    report: AuditReport,
    repo_root: Path,
    source_path: str,
    target: str,
    *,
    code: str = "internal-reference-missing",
) -> None:
    if not _is_portable_repo_path(target):
        _add(
            report,
            "error",
            "internal-reference-path",
            source_path,
            f"项目内引用必须是 repo-relative path: {target!r}",
        )
        return
    if not (repo_root / target).exists():
        _add(
            report,
            "error",
            code,
            source_path,
            f"引用目标不存在: {target}",
        )


def _audit_registry(
    repo_root: Path,
    registry: KnowledgeRegistry,
    report: AuditReport,
    actual_documents: dict[str, str],
) -> list[dict[str, Any]]:
    data = registry.data
    if data.get("schema_version") != 1:
        _add(
            report,
            "error",
            "registry-schema-version",
            REGISTRY_PATH,
            "schema_version 必须为 1",
        )

    raw_contracts = data.get("contracts")
    if not isinstance(raw_contracts, dict):
        _add(
            report,
            "error",
            "registry-contracts",
            REGISTRY_PATH,
            "contracts 必须是映射",
        )
        contracts: dict[str, Any] = {}
    else:
        contracts = raw_contracts
    valid_layers = _contract_string_set(
        report, contracts, "card_layers", KNOWN_LAYERS
    )
    valid_loads = _contract_string_set(
        report, contracts, "load_modes", KNOWN_LOAD_MODES
    )
    unknown_layers = valid_layers - KNOWN_LAYERS
    if unknown_layers:
        _add(
            report,
            "error",
            "registry-contract-field",
            REGISTRY_PATH,
            f"contracts.card_layers 含未知值: {sorted(unknown_layers)}",
        )
    unknown_loads = valid_loads - KNOWN_LOAD_MODES
    if unknown_loads:
        _add(
            report,
            "error",
            "registry-contract-field",
            REGISTRY_PATH,
            f"contracts.load_modes 含未知值: {sorted(unknown_loads)}",
        )
    max_core = _contract_budget(report, contracts, "max_core_cards")
    max_default = _contract_budget(report, contracts, "default_cards_max")

    raw_capabilities = data.get("capabilities")
    if not isinstance(raw_capabilities, list):
        _add(
            report,
            "error",
            "registry-capabilities",
            REGISTRY_PATH,
            "capabilities 必须是列表",
        )
        return []
    report.capabilities = len(raw_capabilities)
    if not raw_capabilities:
        _add(
            report,
            "error",
            "registry-capabilities",
            REGISTRY_PATH,
            "capabilities 不能是空列表",
        )

    seen_ids: set[str] = set()
    seen_files: set[str] = set()
    registered_documents: set[str] = set()
    document_entries: list[dict[str, Any]] = []
    core_cards = 0
    default_cards = 0

    for index, raw_entry in enumerate(raw_capabilities):
        path = _entry_path(index)
        if not isinstance(raw_entry, dict):
            _add(
                report,
                "error",
                "capability-entry-type",
                path,
                "capability entry 必须是映射",
            )
            continue
        entry = raw_entry
        capability_id = _required_string(report, entry, "id", path)
        kind = _required_string(report, entry, "kind", path)
        layer = _required_string(report, entry, "layer", path)
        load_mode = _required_string(report, entry, "load", path)
        _required_string(report, entry, "purpose", path)

        if capability_id is not None:
            if not ID_RE.fullmatch(capability_id):
                _add(
                    report,
                    "error",
                    "capability-id-format",
                    path,
                    f"capability id 必须使用小写短横线格式: {capability_id!r}",
                )
            if capability_id in seen_ids:
                _add(
                    report,
                    "error",
                    "capability-duplicate-id",
                    path,
                    f"重复 capability id: {capability_id}",
                )
            seen_ids.add(capability_id)

        if kind is not None and kind not in ALLOWED_KINDS:
            _add(
                report,
                "error",
                "capability-invalid-kind",
                path,
                f"不支持的 kind: {kind}",
            )
        if layer is not None and layer not in valid_layers:
            _add(
                report,
                "error",
                "capability-invalid-layer",
                path,
                f"layer 未在 contracts.card_layers 中登记: {layer}",
            )
        if load_mode is not None and load_mode not in valid_loads:
            _add(
                report,
                "error",
                "capability-invalid-load",
                path,
                f"load 未在 contracts.load_modes 中登记: {load_mode}",
            )
        if not _valid_string_list(entry.get("triggers")):
            _add(
                report,
                "error",
                "capability-triggers",
                path,
                "triggers 必须是非空字符串列表",
            )

        if kind == "workflow":
            routes = entry.get("routes")
            if not _valid_string_list(routes):
                _add(
                    report,
                    "error",
                    "workflow-routes",
                    path,
                    "workflow routes 必须是非空字符串列表",
                )
            else:
                for route in routes:
                    _check_reference(report, repo_root, path, route)
            if layer != "reference" or load_mode != "on-demand":
                _add(
                    report,
                    "error",
                    "capability-kind-contract",
                    path,
                    "workflow 必须使用 layer=reference、load=on-demand",
                )
            continue

        if kind not in DOCUMENT_ROOTS:
            continue
        file_path = _required_string(report, entry, "file", path)
        if file_path is None:
            continue
        if file_path in seen_files:
            _add(
                report,
                "error",
                "capability-duplicate-file",
                path,
                f"重复 capability file: {file_path}",
            )
        seen_files.add(file_path)
        registered_documents.add(file_path)
        document_entries.append(entry)

        expected_root = DOCUMENT_ROOTS[kind].as_posix() + "/"
        if not _is_portable_repo_path(file_path) or not file_path.endswith(".md"):
            _add(
                report,
                "error",
                "capability-file-path",
                path,
                f"file 必须是 portable repo-relative Markdown path: {file_path!r}",
            )
        elif not file_path.startswith(expected_root):
            _add(
                report,
                "error",
                "capability-kind-path",
                path,
                f"kind={kind} 的文件必须位于 {expected_root}",
            )
        if not (repo_root / file_path).is_file():
            _add(
                report,
                "error",
                "capability-file-missing",
                path,
                f"registry 文件不存在: {file_path}",
            )
        if capability_id is not None and Path(file_path).stem != capability_id:
            _add(
                report,
                "error",
                "capability-id-file-mismatch",
                path,
                f"id={capability_id!r} 与文件名 {Path(file_path).stem!r} 不一致",
            )

        if kind == "card":
            if layer not in {"core", "reference", "case-router"}:
                _add(
                    report,
                    "error",
                    "capability-kind-contract",
                    path,
                    "card layer 只能是 core、reference 或 case-router",
                )
            if layer == "case-router" and load_mode != "on-demand":
                _add(
                    report,
                    "error",
                    "capability-kind-contract",
                    path,
                    "case-router card 必须使用 load=on-demand",
                )
            core_cards += layer == "core"
            default_cards += load_mode == "default"
        elif kind == "payload-pack" and (
            layer != "payload-pack" or load_mode != "gated"
        ):
            _add(
                report,
                "error",
                "capability-kind-contract",
                path,
                "payload-pack 必须使用 layer=payload-pack、load=gated",
            )
        elif kind == "playbook" and (layer != "playbook" or load_mode != "gated"):
            _add(
                report,
                "error",
                "capability-kind-contract",
                path,
                "playbook 必须使用 layer=playbook、load=gated",
            )

    if max_core is not None and core_cards > max_core:
        _add(
            report,
            "error",
            "budget-max-core",
            REGISTRY_PATH,
            f"core card 数量 {core_cards} 超过 max_core_cards={max_core}",
        )
    if max_default is not None and default_cards > max_default:
        _add(
            report,
            "error",
            "budget-default",
            REGISTRY_PATH,
            f"default card 数量 {default_cards} 超过 default_cards_max={max_default}",
        )

    for file_path in sorted(set(actual_documents) - registered_documents):
        _add(
            report,
            "error",
            "document-unregistered",
            file_path,
            "active knowledge 文档未在 capabilities.yaml 登记",
        )
    return document_entries


@dataclass(frozen=True)
class ParsedDocument:
    metadata: dict[str, Any] | None
    body: str
    frontmatter_error: str | None = None


def _parse_document(text: str) -> ParsedDocument:
    lines = text.lstrip("\ufeff").splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return ParsedDocument(metadata=None, body=text)
    closing = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing is None:
        return ParsedDocument(None, "", "frontmatter 缺少结束分隔符 `---`")
    raw_frontmatter = "".join(lines[1:closing])
    try:
        metadata = yaml.safe_load(raw_frontmatter)
    except yaml.YAMLError as exc:
        return ParsedDocument(None, "".join(lines[closing + 1 :]), str(exc))
    if not isinstance(metadata, dict):
        return ParsedDocument(
            None,
            "".join(lines[closing + 1 :]),
            "frontmatter 根节点必须是映射",
        )
    return ParsedDocument(metadata, "".join(lines[closing + 1 :]))


def _headings(body: str) -> list[str]:
    return [
        re.sub(r"[`*_]", "", heading).strip().casefold()
        for heading in HEADING_RE.findall(body)
    ]


def _has_heading(headings: Iterable[str], aliases: Iterable[str]) -> bool:
    lowered = tuple(alias.casefold() for alias in aliases)
    return any(alias in heading for heading in headings for alias in lowered)


def _missing_sections(kind: str, headings: list[str]) -> list[str]:
    missing: list[str] = []
    if not _has_heading(headings, QUICK_RECALL):
        missing.append("Quick Recall")
    groups = {
        "card": CARD_SECTIONS,
        "payload-pack": PAYLOAD_SECTIONS,
        "playbook": PLAYBOOK_SECTIONS,
    }[kind]
    for label, aliases in groups.items():
        if not _has_heading(headings, aliases):
            missing.append(label)
    return missing


def _audit_metadata_list(
    report: AuditReport,
    metadata: dict[str, Any],
    key: str,
    path: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    value = metadata.get(key)
    if not _valid_string_list(value, allow_empty=allow_empty):
        _add(
            report,
            "error",
            "frontmatter-list",
            path,
            f"frontmatter.{key} 必须是字符串列表",
        )
        return []
    return value


def _audit_frontmatter(
    report: AuditReport,
    repo_root: Path,
    entry: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    path = str(entry["file"])
    kind = str(entry["kind"])
    capability_id = str(entry["id"])
    if metadata.get("id") != capability_id:
        _add(
            report,
            "error",
            "frontmatter-id-mismatch",
            path,
            f"frontmatter.id 必须为 {capability_id!r}",
        )
    doc_type = metadata.get("type")
    if doc_type not in ALLOWED_FRONTMATTER_TYPES[kind]:
        allowed = ", ".join(sorted(ALLOWED_FRONTMATTER_TYPES[kind]))
        _add(
            report,
            "error",
            "frontmatter-type",
            path,
            f"kind={kind} 的 frontmatter.type 必须是: {allowed}",
        )

    related_skills = _audit_metadata_list(
        report, metadata, "related_skills", path
    )
    _audit_metadata_list(report, metadata, "trigger_tags", path)
    if kind == "card":
        references = _audit_metadata_list(
            report, metadata, "deep_refs", path, allow_empty=True
        )
    else:
        references = _audit_metadata_list(report, metadata, "related_cards", path)

    for key, allowed in (
        ("risk", ALLOWED_RISKS),
        ("maturity", ALLOWED_MATURITY),
        ("load_priority", ALLOWED_LOAD_PRIORITY),
    ):
        if metadata.get(key) not in allowed:
            _add(
                report,
                "error",
                "frontmatter-enum",
                path,
                f"frontmatter.{key} 必须是: {', '.join(sorted(allowed))}",
            )

    for skill in related_skills:
        skill_path = f"skills/{skill}/SKILL.md"
        if not (repo_root / skill_path).is_file():
            _add(
                report,
                "error",
                "related-skill-missing",
                path,
                f"related_skills 指向不存在的 Skill: {skill_path}",
            )
    for reference in references:
        if kind != "card" and not reference.startswith("knowledge/cards/"):
            _add(
                report,
                "error",
                "related-card-path",
                path,
                f"related_cards 必须指向 knowledge/cards/: {reference}",
            )
        _check_reference(report, repo_root, path, reference)


def _markdown_target(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<") and ">" in value:
        return value[1 : value.index(">")].strip()
    return value.split(maxsplit=1)[0] if value else ""


def _audit_markdown_links(
    report: AuditReport,
    repo_root: Path,
    document_path: Path,
    body: str,
) -> None:
    prose = INLINE_CODE_RE.sub("", FENCED_CODE_RE.sub("", body))
    display_path = document_path.relative_to(repo_root).as_posix()
    for raw_target in MARKDOWN_LINK_RE.findall(prose):
        target = unquote(_markdown_target(raw_target))
        if not target or target.startswith("#"):
            continue
        parsed = urlparse(target)
        if parsed.scheme in {"http", "https", "mailto", "data"} or parsed.netloc:
            continue
        clean_target = target.split("#", 1)[0].split("?", 1)[0]
        if not clean_target:
            continue
        resolved = (
            repo_root / clean_target.lstrip("/")
            if clean_target.startswith("/")
            else document_path.parent / clean_target
        )
        if not resolved.exists():
            _add(
                report,
                "error",
                "markdown-link-missing",
                display_path,
                f"Markdown 内部链接不存在: {target}",
            )


def _audit_document(
    report: AuditReport,
    repo_root: Path,
    entry: dict[str, Any],
) -> None:
    file_path = entry.get("file")
    kind = entry.get("kind")
    if not isinstance(file_path, str) or kind not in DOCUMENT_ROOTS:
        return
    path = repo_root / file_path
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        _add(
            report,
            "error",
            "document-read",
            file_path,
            f"无法读取知识文档: {exc}",
        )
        return
    parsed = _parse_document(text)
    if parsed.frontmatter_error:
        _add(
            report,
            "error",
            "frontmatter-invalid",
            file_path,
            parsed.frontmatter_error,
        )
        return

    headings = _headings(parsed.body)
    if not parsed.body.lstrip().startswith("# "):
        _add(
            report,
            "error",
            "document-h1",
            file_path,
            "正文必须以一级标题开始",
        )
    if parsed.metadata is None:
        if kind == "card":
            missing = _missing_sections("card", headings)
            detail = f"；迁移时补齐: {', '.join(missing)}" if missing else ""
            _add(
                report,
                "warning",
                "legacy-card",
                file_path,
                f"legacy card 缺少 v2 frontmatter{detail}",
            )
        else:
            _add(
                report,
                "error",
                "frontmatter-required",
                file_path,
                f"{kind} 文档必须使用 v2 frontmatter",
            )
    else:
        _audit_frontmatter(report, repo_root, entry, parsed.metadata)
        for label in _missing_sections(kind, headings):
            _add(
                report,
                "error",
                "document-section",
                file_path,
                f"v2 {kind} 缺少语义 section: {label}",
            )
        if kind == "playbook" and not re.search(
            r"(?:/validate|验证|evidence)", parsed.body, re.IGNORECASE
        ):
            _add(
                report,
                "error",
                "document-verification-exit",
                file_path,
                "playbook 必须说明验证或 evidence 出口",
            )
    _audit_markdown_links(report, repo_root, path, parsed.body)


def audit_repository(repo_root: Path | str = BASE_DIR) -> AuditReport:
    repo = Path(repo_root).resolve()
    report = AuditReport()
    actual_documents = _active_documents(repo)
    report.documents = len(actual_documents)
    try:
        registry = load_registry(repo)
    except KnowledgeRegistryError as exc:
        _add(report, "error", "registry-load", REGISTRY_PATH, str(exc))
        return report

    document_entries = _audit_registry(
        repo,
        registry,
        report,
        actual_documents,
    )
    audited: set[str] = set()
    for entry in document_entries:
        file_path = entry.get("file")
        if not isinstance(file_path, str) or file_path in audited:
            continue
        audited.add(file_path)
        _audit_document(report, repo, entry)
    return report


def format_report(report: AuditReport) -> str:
    lines = [
        "Knowledge audit: "
        f"capabilities={report.capabilities} documents={report.documents} "
        f"errors={report.errors} warnings={report.warnings}"
    ]
    for issue in report.ordered_issues:
        lines.append(
            f"[{issue.severity.upper()}] {issue.code} {issue.path}: {issue.message}"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(BASE_DIR),
        help="待审计仓库根目录",
    )
    parser.add_argument("--json", action="store_true", help="输出完整 JSON 报告")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="warnings 也返回非零退出码",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = audit_repository(args.repo_root)
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(format_report(report))
    return 1 if report.errors or (args.strict and report.warnings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
