#!/usr/bin/env python3
"""Shared helpers for structured finding follow-up summaries and rendering."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

try:
    from evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence
    from finding_index import verify_finalized_finding_owner_provenance
    from target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - package import path
    from tools.evidence_rubric import compact_evidence_rubric, evaluate_candidate_evidence
    from tools.finding_index import verify_finalized_finding_owner_provenance
    from tools.target_paths import canonical_target_value, target_storage_key


def _load_validation_summary_rubric(finding: dict) -> dict:
    """从 validation_runner 的 summary.json 读取已计算好的证据 rubric。

    validation_runner 已经基于原始请求/响应给出 lane-specific rubric；
    structured_findings 只看 findings.json 的精简行时会丢掉这些细节，导致
    已验证 finding 在 checkpoint 里又显示 needs-evidence。这里优先复用
    summary.json，避免用标题/URL 的弱文本重新推断证据质量。
    """
    candidates: list[Path] = []
    for field in ("validation_summary", "source_file"):
        value = str(finding.get(field) or "").strip()
        if not value:
            continue
        path = Path(value)
        candidates.append(path if path.is_absolute() else Path.cwd() / path)

    for path in candidates:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        rubric = payload.get("evidence_rubric")
        if isinstance(rubric, dict) and rubric:
            return rubric
    return {}


def _load_validation_summary_payload(finding: dict) -> tuple[dict, bool]:
    """Load validation_summary JSON and report whether a summary path was present."""
    value = str(finding.get("validation_summary") or "").strip()
    if not value:
        return {}, False
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_file():
        return {}, True
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, True
    return (payload if isinstance(payload, dict) else {}), True


def _relative_to_repo(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _runner_summary_is_candidate(payload: dict) -> bool:
    """Return whether validation_runner summary should be shown to Claude.

    这里不判断“可报告”，只判断这份 runner 证据是否值得 AI 复核。
    `/validate` 的 7-Question Gate / 4-gate 才能决定 report-ready。
    """
    if not isinstance(payload, dict) or not payload.get("lane"):
        return False
    result = str(payload.get("result") or "").strip().lower()
    rubric = payload.get("evidence_rubric") if isinstance(payload.get("evidence_rubric"), dict) else {}
    return bool(
        payload.get("candidate_ready") is True
        or result in {"tested_finding", "candidate"}
        or rubric.get("ready") is True
    )


def _compact_runner_summary(payload: dict, path: Path, repo_root: Path) -> dict:
    rubric = payload.get("evidence_rubric") if isinstance(payload.get("evidence_rubric"), dict) else {}
    ai_next = payload.get("ai_next") if isinstance(payload.get("ai_next"), dict) else {}
    return {
        "id": str(payload.get("finding_id") or path.parent.name or "").strip(),
        "lane": str(payload.get("lane") or "").strip(),
        "result": str(payload.get("result") or "").strip(),
        "candidate_ready": bool(payload.get("candidate_ready")),
        "url": str(payload.get("url") or "").strip(),
        "method": str(payload.get("method") or "").strip() or "GET",
        "generated_at": str(payload.get("generated_at") or "").strip(),
        "summary_path": _relative_to_repo(path, repo_root),
        "rubric_status": str(rubric.get("status") or "").strip(),
        "rubric_summary": str(rubric.get("summary") or "").strip(),
        "missing_evidence": list(rubric.get("missing_labels") or [])[:3],
        "next_action": str(ai_next.get("next_action") or "").strip(),
        "report_gate": "requires /validate seven-question + four validation gates before report",
    }


def _artifact_key(value: str, repo_root: Path) -> str:
    """Return a comparable repo-relative artifact path key."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    path = Path(raw)
    if path.is_absolute():
        return _relative_to_repo(path, repo_root)
    return raw


def _url_path_query(value: str) -> str:
    """Normalize a finding/candidate URL to path+query for final-state matching."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        return raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return raw
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


def _url_path_only(value: str) -> str:
    """Normalize to path only, matching evidence ledger endpoint granularity."""
    return _url_path_query(value).split("?", 1)[0]


def _runner_lane_type(lane: str) -> str:
    """Map runner lane names to structured finding type families."""
    lane_l = str(lane or "").strip().lower()
    if lane_l.startswith("authz_"):
        return "auth_bypass"
    if lane_l.startswith("idor_"):
        return "idor"
    if lane_l.startswith("sqli_"):
        return "sqli"
    if "ssrf" in lane_l:
        return "ssrf"
    if "xss" in lane_l:
        return "xss"
    return ""


def _runner_lane_vuln_class(lane: str) -> str:
    """Map runner lane names to evidence-ledger vulnerability classes."""
    lane_l = str(lane or "").strip().lower()
    if lane_l.startswith("authz_"):
        return "authz"
    if lane_l.startswith("idor_"):
        return "idor"
    if lane_l.startswith("sqli_"):
        return "sqli"
    if "ssrf" in lane_l:
        return "ssrf"
    if "xss" in lane_l:
        return "xss"
    return ""


def _finding_type_aliases(value: str) -> set[str]:
    """Return compatible type labels used by scanner, runner, and reports."""
    kind = str(value or "").strip().lower()
    aliases = {kind} if kind else set()
    if kind in {"authz", "authorization", "auth_bypass", "exposure"}:
        aliases.add("auth_bypass")
    return aliases


def _finalized_runner_candidate_keys(
    repo_root: Path,
    target_key: str,
    *,
    target: str,
) -> dict[str, set]:
    """Load already closed finding keys so runner evidence stops resurfacing.

    This is only a state-closure filter: it does not decide whether a fresh runner
    candidate is valuable. Rejected/generated findings are final enough to hide
    matching runner summaries from the Claude-facing review pool; runner-only
    validated rows without report closure stay visible for `/validate`.
    """
    findings_path = repo_root / "findings" / target_key / "findings.json"
    try:
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"ids": set(), "artifacts": set(), "url_types": set()}

    findings = payload.get("findings", []) if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        return {"ids": set(), "artifacts": set(), "url_types": set()}

    ids: set[str] = set()
    artifacts: set[str] = set()
    url_types: set[tuple[str, str]] = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        validation_status = str(item.get("validation_status") or "").strip().lower()
        report_status = str(item.get("report_status") or "").strip().lower()
        if validation_status != "rejected" and report_status != "generated":
            continue
        provenance = verify_finalized_finding_owner_provenance(
            findings_path.parent,
            item,
            target=target,
        )
        # An edited JSON row must not silently suppress fresh runner evidence.
        # Keep its raw candidate visible until an owner-backed lifecycle write
        # actually closes the finding.
        if not provenance.get("valid"):
            continue

        finding_id = str(item.get("id") or "").strip()
        if finding_id:
            ids.add(finding_id)

        for field in ("source_file", "validation_summary"):
            artifact = _artifact_key(str(item.get(field) or ""), repo_root)
            if artifact:
                artifacts.add(artifact)

        path_query = _url_path_query(str(item.get("url") or ""))
        for alias in _finding_type_aliases(str(item.get("type") or "")):
            if path_query and alias:
                url_types.add((path_query, alias))

    return {"ids": ids, "artifacts": artifacts, "url_types": url_types}


def _closed_ledger_runner_keys(repo_root: Path, target_key: str) -> set[tuple[str, str, str]]:
    """Return runner candidates closed by later AI/validate ledger evidence.

    validation_runner writes its own candidate/tested_finding rows; those rows
    must remain visible so Claude can review them. Later AI review, `/validate`,
    or manual ledger rows are the closure signal.
    """
    ledger_path = repo_root / "memory" / "evidence" / target_key / "ledger.jsonl"
    if not ledger_path.is_file():
        return set()

    final_results = {"tested_clean", "tested_finding", "dead_end", "blocked_redline", "not_applicable"}
    closed: set[tuple[str, str, str]] = set()
    try:
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        result = str(entry.get("result") or "").strip().lower()
        if result not in final_results:
            continue
        source = str(entry.get("source") or "").strip().lower()
        if source.startswith("validation-runner"):
            continue
        method = str(entry.get("method") or "GET").strip().upper() or "GET"
        endpoint = _url_path_only(str(entry.get("raw_endpoint") or entry.get("endpoint") or ""))
        vuln = str(entry.get("vuln_class") or "").strip().lower()
        if method and endpoint and vuln:
            closed.add((method, endpoint, vuln))
    return closed


def _runner_candidate_is_finalized(compact: dict, finalized: dict[str, set]) -> bool:
    """Return true when a runner summary is superseded by final finding state."""
    candidate_id = str(compact.get("id") or "").strip()
    if candidate_id and candidate_id in finalized.get("ids", set()):
        return True
    summary_path = str(compact.get("summary_path") or "").strip()
    if summary_path and summary_path in finalized.get("artifacts", set()):
        return True

    lane_type = _runner_lane_type(str(compact.get("lane") or ""))
    path_query = _url_path_query(str(compact.get("url") or ""))
    return bool(lane_type and path_query and (path_query, lane_type) in finalized.get("url_types", set()))


def _runner_candidate_is_closed_by_ledger(compact: dict, closed: set[tuple[str, str, str]]) -> bool:
    method = str(compact.get("method") or "GET").strip().upper() or "GET"
    endpoint = _url_path_only(str(compact.get("url") or ""))
    vuln = _runner_lane_vuln_class(str(compact.get("lane") or ""))
    return bool(method and endpoint and vuln and (method, endpoint, vuln) in closed)


def load_validation_runner_candidate_pool(
    repo_root: Path | str,
    target: str,
    *,
    limit: int = 12,
) -> list[dict]:
    """Load runner-produced candidate evidence as an AI review pool.

    validation_runner 负责 replay/diff/raw evidence 保存；本函数只把这些
    证据摘要暴露给 Claude 选择下一条 `/validate`，不会把它们升级成
    report-ready，也不会替 Claude 做价值排序。
    """
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    validation_dir = repo / "evidence" / target_key / "validation"
    if not validation_dir.is_dir():
        return []

    finalized = _finalized_runner_candidate_keys(
        repo,
        target_key,
        target=resolved_target,
    )
    closed_by_ledger = _closed_ledger_runner_keys(repo, target_key)
    candidates: list[tuple[float, str, dict]] = []
    for path in validation_dir.glob("*/summary.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not _runner_summary_is_candidate(payload):
            continue
        compact = _compact_runner_summary(payload, path, repo)
        if _runner_candidate_is_finalized(compact, finalized):
            continue
        if _runner_candidate_is_closed_by_ledger(compact, closed_by_ledger):
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        candidates.append((mtime, compact["summary_path"], compact))

    # 只按证据新鲜度和路径稳定排序；不按漏洞价值/优先级排序，避免工具替 AI 决策。
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)

    seen: set[tuple[str, str, str]] = set()
    pool: list[dict] = []
    for _, _, item in candidates:
        key = (
            str(item.get("lane") or ""),
            str(item.get("method") or ""),
            str(item.get("url") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        pool.append(item)
        if len(pool) >= limit:
            break
    return pool


def _validation_report_ready(finding: dict) -> bool | None:
    """Return report-readiness when validation_summary exists.

    `validation_runner` summaries prove lane evidence, but they are not the
    `/validate` report-readiness gate. If a validation_summary path exists and
    lacks the 7-question / 4-gate fields, keep the finding as a validation
    follow-up instead of reporting it.
    """
    payload, summary_present = _load_validation_summary_payload(finding)
    if not summary_present:
        return None
    gate_fields = {
        "all_gates_passed",
        "seven_question_gate_passed",
        "four_validation_gates_passed",
        "seven_question_gate_decision",
    }
    if not payload or not any(field in payload for field in gate_fields):
        return False
    if payload.get("all_gates_passed") is False:
        return False
    if payload.get("seven_question_gate_passed") is False:
        return False
    if payload.get("four_validation_gates_passed") is False:
        return False
    decision = str(payload.get("seven_question_gate_decision") or "").strip().lower()
    if decision in {"kill", "chain_required", "needs_review"}:
        return False
    return bool(payload.get("all_gates_passed") or payload.get("seven_question_gate_passed"))


def _validation_needs_draft_completion(finding: dict) -> bool:
    """Return whether validation evidence passed but the generated draft is incomplete.

    This is distinct from a failed evidence gate.  Sending it back through
    `/validate` would make a completed replay look incomplete merely because a
    report template still has `[INSERT ...]` placeholders.
    """
    payload, summary_present = _load_validation_summary_payload(finding)
    if not summary_present or not payload:
        return False
    if payload.get("validation_evidence_passed") is not True:
        return False
    draft = payload.get("report_draft") if isinstance(payload.get("report_draft"), dict) else {}
    status = str(draft.get("status") or payload.get("report_draft_status") or "").strip().lower()
    return status == "incomplete"


def _rubric_eval(finding: dict) -> dict:
    existing = finding.get("rubric") if isinstance(finding.get("rubric"), dict) else {}
    if existing:
        return existing
    existing = finding.get("evidence_rubric") if isinstance(finding.get("evidence_rubric"), dict) else {}
    if existing:
        return existing
    existing = _load_validation_summary_rubric(finding)
    if existing:
        return existing
    return evaluate_candidate_evidence(finding)


def finding_rank_key(finding: dict) -> tuple[int, int, int]:
    """Rank structured finding candidates by severity, confidence, and evidence quality."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    confidence_rank = {"confirmed": 4, "high": 3, "medium": 2, "needs_review": 1}
    severity = str(finding.get("severity", "") or "").lower()
    confidence = str(finding.get("confidence", "") or "").lower()
    rubric = _rubric_eval(finding)
    return (
        severity_rank.get(severity, 0),
        confidence_rank.get(confidence, 0),
        int(rubric.get("score", 0) or 0),
    )


def _is_actionable_validation_candidate(finding: dict) -> bool:
    """Return whether a pending finding should drive the next validation action.

    Generic弱线索仍保留在 pending/evidence gap 统计里，避免隐藏攻击面；但在
    缺少 ready 证据前不抢占 checkpoint 的下一步动作。这样 Claude 会优先处理
    已有明确 lane/rubric 的候选，而不是被普通 `/metrics` 之类信息泄露噪声牵引。
    """
    rubric = _rubric_eval(finding)
    if rubric.get("ready", False):
        return True
    if rubric.get("rubric_id") == "generic":
        return False
    return True


def compact_structured_finding(finding: dict, findings_dir: Path) -> dict:
    """Return the compact structured finding shape used by resume/autopilot."""
    rubric = compact_evidence_rubric(_rubric_eval(finding))
    compact = {
        "id": finding.get("id", ""),
        "type": finding.get("type", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", ""),
        "url": finding.get("url", ""),
        "validation_status": finding.get("validation_status", "unvalidated"),
        "report_status": finding.get("report_status", "not_generated"),
        "source_file": finding.get("source_file", ""),
        "findings_dir": str(findings_dir),
        "rubric": rubric,
        "rubric_status": rubric.get("status", ""),
        "missing_evidence": rubric.get("missing_labels", []),
    }
    # Incomplete root claims intentionally have no fabricated URL.  Preserve
    # their recovery identity and missing fields so Claude can collect the
    # endpoint/evidence and checkpoint the same canonical candidate.
    for key in (
        "claim_id",
        "claim_source_file",
        "claim_target",
        "claim_status",
        "incomplete_fields",
        "claimed_validation_status",
        "claimed_report_status",
    ):
        value = finding.get(key)
        if value not in (None, "", [], {}):
            compact[key] = value
    return compact


def _compact_draft_completion(finding: dict, findings_dir: Path) -> dict:
    """Project the precise report-completion handoff without reopening evidence."""
    compact = compact_structured_finding(finding, findings_dir)
    payload, _ = _load_validation_summary_payload(finding)
    draft = payload.get("report_draft") if isinstance(payload.get("report_draft"), dict) else {}
    compact["report_draft_path"] = str(
        finding.get("report_draft_path") or payload.get("report_path") or ""
    )
    compact["report_draft_status"] = str(
        draft.get("status") or payload.get("report_draft_status") or "incomplete"
    )
    compact["report_draft_placeholder_count"] = int(draft.get("placeholder_count", 0) or 0)
    return compact


def _compact_owner_revalidation(
    finding: dict,
    findings_dir: Path,
    provenance: dict,
) -> dict:
    """Project an untrusted finality claim as a candidate-only recovery action."""
    compact = compact_structured_finding(finding, findings_dir)
    compact["claimed_validation_status"] = compact.get("validation_status", "")
    compact["claimed_report_status"] = compact.get("report_status", "")
    compact["validation_status"] = "needs_owner_revalidation"
    compact["report_status"] = "not_generated"
    compact["lifecycle_status"] = "needs_owner_revalidation"
    compact["provenance_reason"] = str(provenance.get("reason") or "owner-provenance-invalid")
    compact["required_action"] = (
        "replay locatable raw evidence, then use /validate with the canonical finding id "
        "so finding_index records a new owner mutation"
    )
    return compact


def summarize_structured_findings(
    findings: list[dict],
    findings_dir: Path,
    *,
    target: str | None = None,
    enforce_owner_provenance: bool = False,
) -> dict:
    """Build validation/report follow-up state from structured findings.

    Runtime readers enable ``enforce_owner_provenance`` so a direct JSON edit
    that claims ``validated``/``generated`` is exposed as a candidate recovery
    item, never as a report or closure handoff.  The default remains useful for
    isolated pure-data callers that do not have an on-disk canonical index.
    """
    valid_findings = [
        item for item in findings
        if isinstance(item, dict) and item.get("id")
    ]
    if not valid_findings:
        return {
            "total": 0,
            "pending_validation": 0,
            "owner_revalidation_pending": 0,
            "draft_completion_pending": 0,
            "validated_pending_report": 0,
            "reported": 0,
            "findings_dir": str(findings_dir),
        }

    eligible_findings = []
    owner_revalidation_pending: list[tuple[dict, dict]] = []
    for item in valid_findings:
        if enforce_owner_provenance:
            provenance = verify_finalized_finding_owner_provenance(
                findings_dir,
                item,
                target=target,
            )
            if provenance.get("required") and not provenance.get("valid"):
                owner_revalidation_pending.append((item, provenance))
                continue
        eligible_findings.append(item)

    pending_validation = []
    draft_completion_pending = []
    for item in eligible_findings:
        validation_status = str(item.get("validation_status", "unvalidated") or "unvalidated")
        report_status = str(item.get("report_status", "not_generated") or "not_generated")
        if validation_status in {"unvalidated", "candidate", "partial", "needs_validation"}:
            pending_validation.append(item)
            continue
        if (
            validation_status == "validated"
            and report_status != "generated"
            and _validation_report_ready(item) is False
        ):
            if _validation_needs_draft_completion(item):
                draft_completion_pending.append(item)
            else:
                pending_validation.append(item)
    validated_pending_report = [
        item for item in eligible_findings
        if (
            str(item.get("validation_status", "") or "") == "validated"
            and str(item.get("report_status", "not_generated") or "not_generated") != "generated"
            and _validation_report_ready(item) is not False
        )
    ]
    reported = [
        item for item in eligible_findings
        if str(item.get("report_status", "") or "") == "generated"
    ]

    pending_validation.sort(key=finding_rank_key, reverse=True)
    owner_revalidation_pending.sort(key=lambda item: finding_rank_key(item[0]), reverse=True)
    draft_completion_pending.sort(key=finding_rank_key, reverse=True)
    validated_pending_report.sort(key=finding_rank_key, reverse=True)
    actionable_pending_validation = [
        item for item in pending_validation
        if _is_actionable_validation_candidate(item)
    ]
    evidence_gap_count = len(owner_revalidation_pending)
    secret_followup_count = 0
    for item in pending_validation:
        rubric = _rubric_eval(item)
        if not rubric.get("ready", False):
            evidence_gap_count += 1
        if rubric.get("rubric_id") == "secret":
            secret_followup_count += 1

    result = {
        "total": len(valid_findings),
        "pending_validation": len(pending_validation),
        "owner_revalidation_pending": len(owner_revalidation_pending),
        "draft_completion_pending": len(draft_completion_pending),
        "validated_pending_report": len(validated_pending_report),
        "reported": len(reported),
        "evidence_gap_count": evidence_gap_count,
        "secret_followup_count": secret_followup_count,
        "findings_dir": str(findings_dir),
    }
    if actionable_pending_validation:
        result["next_validation"] = compact_structured_finding(actionable_pending_validation[0], findings_dir)
    if owner_revalidation_pending:
        finding, provenance = owner_revalidation_pending[0]
        result["next_owner_revalidation"] = _compact_owner_revalidation(
            finding,
            findings_dir,
            provenance,
        )
    if draft_completion_pending:
        result["next_draft_completion"] = _compact_draft_completion(
            draft_completion_pending[0],
            findings_dir,
        )
    if validated_pending_report:
        result["next_report"] = compact_structured_finding(validated_pending_report[0], findings_dir)
    return result


def format_structured_findings_lines(
    structured_findings: dict,
    *,
    header: str | None = None,
    inline_header: bool = False,
    indent: str = "",
    next_validation_label: str = "Next validation",
    next_report_label: str = "Next report",
) -> list[str]:
    """Render compact structured finding summary lines for human output."""
    if not structured_findings.get("total"):
        return []

    lines: list[str] = []
    if header and not inline_header:
        lines.append(f"{indent}{header}")
    summary = (
        "total={total}, pending_validation={pending_validation}, owner_revalidation_pending={owner_revalidation_pending}, draft_completion_pending={draft_completion_pending}, "
        "validated_pending_report={validated_pending_report}, reported={reported}, "
        "evidence_gaps={evidence_gap_count}".format(
            total=structured_findings.get("total", 0),
            pending_validation=structured_findings.get("pending_validation", 0),
            owner_revalidation_pending=structured_findings.get("owner_revalidation_pending", 0),
            draft_completion_pending=structured_findings.get("draft_completion_pending", 0),
            validated_pending_report=structured_findings.get("validated_pending_report", 0),
            reported=structured_findings.get("reported", 0),
            evidence_gap_count=structured_findings.get("evidence_gap_count", 0),
        )
    )
    if header and inline_header:
        lines.append(f"{indent}{header} {summary}")
    else:
        lines.append(f"{indent}{summary}")

    next_validation = structured_findings.get("next_validation") or {}
    if next_validation:
        rubric = next_validation.get("rubric") if isinstance(next_validation.get("rubric"), dict) else {}
        rubric_suffix = ""
        if rubric.get("status"):
            missing = ", ".join(str(item) for item in (rubric.get("missing_labels") or [])[:2])
            rubric_suffix = f" rubric={rubric.get('status')}"
            if missing:
                rubric_suffix += f" missing={missing}"
        lines.append(
            "{indent}{label}: {id} [{severity}/{confidence}] {type} {url}{rubric_suffix}".format(
                indent=indent,
                label=next_validation_label,
                id=next_validation.get("id", "-"),
                severity=next_validation.get("severity", "-"),
                confidence=next_validation.get("confidence", "-"),
                type=next_validation.get("type", "-"),
                url=next_validation.get("url", ""),
                rubric_suffix=rubric_suffix,
            )
        )

    next_owner_revalidation = structured_findings.get("next_owner_revalidation") or {}
    if next_owner_revalidation:
        lines.append(
            "{indent}Owner revalidation: {id} claimed={validation}/{report} reason={reason}; "
            "treat as candidate until /validate records owner provenance.".format(
                indent=indent,
                id=next_owner_revalidation.get("id", "-"),
                validation=next_owner_revalidation.get("claimed_validation_status", "-"),
                report=next_owner_revalidation.get("claimed_report_status", "-"),
                reason=next_owner_revalidation.get("provenance_reason", "owner-provenance-invalid"),
            )
        )

    next_report = structured_findings.get("next_report") or {}
    if next_report:
        lines.append(
            "{indent}{label}: {id} [{severity}/{confidence}] {type} {url}".format(
                indent=indent,
                label=next_report_label,
                id=next_report.get("id", "-"),
                severity=next_report.get("severity", "-"),
                confidence=next_report.get("confidence", "-"),
                type=next_report.get("type", "-"),
                url=next_report.get("url", ""),
            )
        )
    next_draft_completion = structured_findings.get("next_draft_completion") or {}
    if next_draft_completion:
        lines.append(
            "{indent}Report draft completion: {id} status={status} placeholders={count} path={path}".format(
                indent=indent,
                id=next_draft_completion.get("id", "-"),
                status=next_draft_completion.get("report_draft_status", "incomplete"),
                count=next_draft_completion.get("report_draft_placeholder_count", 0),
                path=next_draft_completion.get("report_draft_path", ""),
            )
        )
    return lines


def format_validation_runner_candidate_lines(
    candidates: list[dict],
    *,
    header: str | None = None,
    indent: str = "",
    limit: int = 6,
) -> list[str]:
    """Render runner candidate evidence without implying report readiness."""
    if not candidates:
        return []
    lines: list[str] = []
    if header:
        lines.append(f"{indent}{header}")
    for item in candidates[:limit]:
        missing = ", ".join(str(value) for value in (item.get("missing_evidence") or [])[:2])
        missing_suffix = f" missing={missing}" if missing else ""
        rubric = str(item.get("rubric_status") or "").strip()
        rubric_suffix = f" rubric={rubric}" if rubric else ""
        lines.append(
            "{indent}{id} [{lane}/{result}] {method} {url}{rubric_suffix}{missing_suffix}; "
            "evidence={summary_path}; gate={gate}".format(
                indent=indent,
                id=item.get("id", "-"),
                lane=item.get("lane", "-"),
                result=item.get("result", "-"),
                method=item.get("method", "GET"),
                url=item.get("url", ""),
                rubric_suffix=rubric_suffix,
                missing_suffix=missing_suffix,
                summary_path=item.get("summary_path", ""),
                gate=item.get("report_gate", "requires /validate before report"),
            )
        )
    return lines
