#!/usr/bin/env python3
"""目标级 Intel v2：组件版本、advisory 新鲜度、适用性与可追溯投影。

`/intel` 通过本模块读取统一技术清单，查询 OSV/GitHub Advisory/NVD，使用
CISA KEV、EPSS 和已有本地 CVE template 信号富化，最后原子发布
`recon/<target>/intel.json`。分数只用于 review 顺序，不创建 finding。
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Import learn.py functions (same repo)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE_DIR)
sys.path.insert(0, BASE_DIR)

# 与 Osmedeus 01-osint.yaml 的 toolsDir 约定对齐，默认复用 $HOME/Tools。
SHARED_TOOLS_DIR = os.environ.get(
    "BBHUNT_TOOLS_DIR",
    os.environ.get("OSMEDEUS_TOOLS_DIR", os.path.join(os.path.expanduser("~"), "Tools")),
)

from learn import severity_order
try:
    from tools.intel_artifact import INTEL_SCHEMA_VERSION, IntelArtifactError, write_intel_artifact
    from tools.intel_sources import fetch_advisory_sources, fetch_epss, fetch_json, fetch_kev
    from tools.intelligence_extractor import merge_managed_section
    from tools.target_paths import canonical_target_value, target_storage_key
    from tools.technology_inventory import (
        component_labels,
        load_or_build_inventory,
        split_component_label,
        TechnologyInventoryError,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from intel_artifact import INTEL_SCHEMA_VERSION, IntelArtifactError, write_intel_artifact  # type: ignore
    from intel_sources import fetch_advisory_sources, fetch_epss, fetch_json, fetch_kev  # type: ignore
    from intelligence_extractor import merge_managed_section  # type: ignore
    from target_paths import canonical_target_value, target_storage_key
    from technology_inventory import (  # type: ignore
        TechnologyInventoryError,
        component_labels,
        load_or_build_inventory,
        split_component_label,
    )

# ─── Color codes ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def load_memory_context(memory_dir: str, target: str) -> dict:
    """Load hunt memory context for a target.

    Returns:
        Dict with tested_endpoints, findings, tech_stack, last_hunted, patterns.
    """
    context = {
        "tested_endpoints": [],
        "findings": [],
        "tech_stack": [],
        "last_hunted": None,
        "hunt_sessions": 0,
        "patterns": [],
        "tested_cves": [],
    }

    if not memory_dir or not os.path.isdir(memory_dir):
        return context

    resolved_target = canonical_target_value(target)

    # Load target profile
    targets_dir = os.path.join(memory_dir, "targets")
    if os.path.isdir(targets_dir):
        # Normalize target name to filename
        target_file = (
            resolved_target.replace(".", "-").replace("/", "-").replace("\\", "-")
            + ".json"
        )
        target_path = os.path.join(targets_dir, target_file)
        if os.path.isfile(target_path):
            try:
                with open(target_path) as f:
                    profile = json.load(f)
                context["tested_endpoints"] = profile.get("tested_endpoints", [])
                context["findings"] = profile.get("findings", [])
                context["tech_stack"] = profile.get("tech_stack", [])
                context["last_hunted"] = profile.get("last_hunted")
                context["hunt_sessions"] = profile.get("hunt_sessions", 0)
            except (json.JSONDecodeError, OSError):
                pass

    # Load journal entries for this target to find tested CVEs
    journal_path = os.path.join(memory_dir, "journal.jsonl")
    if os.path.isfile(journal_path):
        try:
            with open(journal_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if canonical_target_value(str(entry.get("target") or "")) == resolved_target:
                            # Check if any tag looks like a CVE
                            for tag in entry.get("tags", []):
                                if tag.upper().startswith("CVE-"):
                                    context["tested_cves"].append(tag.upper())
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    # Load patterns
    patterns_path = os.path.join(memory_dir, "patterns.jsonl")
    if os.path.isfile(patterns_path):
        try:
            with open(patterns_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        pattern = json.loads(line)
                        context["patterns"].append(pattern)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

    return context


def dedupe_tech_stack(items: list[str]) -> list[str]:
    """Normalize and dedupe tech names while preserving order."""
    deduped = []
    seen = set()
    for item in items:
        value = item.strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def load_recon_tech_stack(
    target: str,
    limit: int = 12,
    *,
    repo_root: str | Path | None = None,
) -> list[str]:
    """从共享组件清单读取目标级技术名称。"""
    inventory = load_or_build_inventory(repo_root or REPO_ROOT, target)
    return component_labels(inventory, include_versions=True, limit=limit)


def resolve_tech_stack(
    target: str,
    cli_techs: list[str],
    memory: dict,
    limit: int = 12,
    *,
    repo_root: str | Path | None = None,
) -> list[str]:
    """Resolve effective tech stack from CLI, then memory, then recon fallback."""
    techs = dedupe_tech_stack(cli_techs)

    if memory.get("tech_stack"):
        techs = dedupe_tech_stack(techs + list(memory["tech_stack"]))

    if techs:
        return techs[:limit]

    return load_recon_tech_stack(target, limit=limit, repo_root=repo_root)


def _run_command(cmd: list[str], output_path: str, timeout: int) -> bool:
    """运行外部情报工具并把 stdout/stderr 合并写入文件，失败不抛出。"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8", errors="replace") as handle:
            completed = subprocess.run(
                cmd,
                stdout=handle,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        with open(output_path, "a", encoding="utf-8", errors="replace") as handle:
            handle.write(f"[tool-error] {' '.join(cmd)}: {exc}\n")
        return False


def _line_count(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _resolve_emailfinder() -> list[str] | None:
    """解析 emailfinder：优先复用 Osmedeus toolsDir，缺失时再走 PATH。"""
    script = os.path.join(SHARED_TOOLS_DIR, "emailfinder", "emailfinder.py")
    if os.path.isfile(script):
        return [sys.executable, script]

    binary = shutil.which("emailfinder")
    if binary:
        return [binary]
    return None


def _resolve_leaksearch() -> list[str] | None:
    """解析 LeakSearch：按 Osmedeus toolsDir/LeakSearch 约定复用 venv。"""
    script = os.path.join(SHARED_TOOLS_DIR, "LeakSearch", "LeakSearch.py")
    if not os.path.isfile(script):
        return None

    python_bin = os.path.join(SHARED_TOOLS_DIR, "LeakSearch", "venv", "bin", "python3")
    if not os.path.exists(python_bin):
        python_bin = sys.executable
    return [python_bin, script]


def run_identity_intel(target: str, timeout: int = 180, *, repo_root: str | Path | None = None) -> dict:
    """运行轻量身份/凭据情报采集。

    这不是 finding，也不会尝试登录或撞库；结果仅作为 /intel 假设燃料。
    """
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    resolved_repo_root = str(repo_root or REPO_ROOT)
    out_dir = os.path.join(resolved_repo_root, "evidence", target_key, "identity_intel")
    os.makedirs(out_dir, exist_ok=True)

    emails_path = os.path.join(out_dir, "emails.txt")
    leaksearch_path = os.path.join(out_dir, "leaksearch.txt")
    summary_path = os.path.join(out_dir, "summary.md")

    emailfinder_status = "missing"
    emailfinder_cmd = _resolve_emailfinder()
    if emailfinder_cmd:
        emailfinder_status = "ok" if _run_command(
            emailfinder_cmd + ["-d", resolved_target],
            emails_path,
            timeout=min(timeout, 120),
        ) else "partial"
    else:
        open(emails_path, "w", encoding="utf-8").close()

    leaksearch_status = "missing"
    leaksearch_cmd = _resolve_leaksearch()
    if leaksearch_cmd:
        leaksearch_status = "ok" if _run_command(
            leaksearch_cmd + ["-k", resolved_target, "-o", leaksearch_path],
            leaksearch_path,
            timeout=timeout,
        ) else "partial"
    else:
        open(leaksearch_path, "w", encoding="utf-8").close()

    email_count = _line_count(emails_path)
    leak_line_count = _line_count(leaksearch_path)
    summary = [
        f"# Identity Intel — {resolved_target}",
        "",
        "这些是身份/凭据情报，不是漏洞结论；用于指导 SSO、找回密码、邀请流、租户枚举等后续假设。",
        "",
        f"- emailfinder: {emailfinder_status} ({email_count} non-empty lines)",
        f"- LeakSearch: {leaksearch_status} ({leak_line_count} non-empty lines)",
        f"- emails: `{os.path.relpath(emails_path, resolved_repo_root)}`",
        f"- leaksearch: `{os.path.relpath(leaksearch_path, resolved_repo_root)}`",
        "",
        "Next hypotheses:",
        "- 检查登录/SSO/找回密码是否存在账号枚举或租户枚举。",
        "- 若 LeakSearch 有命中，只做最小化验证和归属确认，不做自动登录/撞库。",
        "- 将邮箱模式与邀请流、OAuth/SAML、support/admin 面结合验证。",
        "",
    ]
    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(summary))

    intelligence_path = Path(resolved_repo_root) / "evidence" / target_key / "intelligence.md"
    intelligence_path.parent.mkdir(parents=True, exist_ok=True)
    existing = intelligence_path.read_text(encoding="utf-8", errors="replace") if intelligence_path.is_file() else ""
    intelligence_path.write_text(
        merge_managed_section(
            existing,
            "identity-intel",
            "\n".join(summary),
            legacy_heading_prefix="# Identity Intel",
        ),
        encoding="utf-8",
    )

    return {
        "emailfinder_status": emailfinder_status,
        "leaksearch_status": leaksearch_status,
        "email_count": email_count,
        "leak_line_count": leak_line_count,
        "artifact_dir": out_dir,
        "summary_path": summary_path,
        "emails_path": emails_path,
        "leaksearch_path": leaksearch_path,
    }


def prioritize_intel(results: list[dict], memory: dict) -> dict:
    """Prioritize intel against memory context.

    Returns:
        Dict with categorized alerts: critical, high, info, memory_context.
    """
    tested_endpoints = set(memory.get("tested_endpoints", []))
    tested_cves = set(memory.get("tested_cves", []))

    critical = []
    high = []
    info = []

    for r in results:
        sev = r.get("severity", "UNKNOWN").upper()
        cve_id = r.get("id", "")

        # Check if this CVE was already tested
        already_tested = cve_id.upper() in tested_cves if cve_id.startswith("CVE") else False

        entry = {
            **r,
            "already_tested": already_tested,
        }

        if already_tested:
            entry["note"] = "Already tested in a previous hunt session."
            info.append(entry)
        elif sev in ("CRITICAL",):
            entry["note"] = "Untested critical vulnerability. Hunt candidate."
            critical.append(entry)
        elif sev in ("HIGH",):
            entry["note"] = "Untested high-severity finding. Priority target."
            high.append(entry)
        else:
            info.append(entry)

    # Sort each category by severity
    critical.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))
    high.sort(key=lambda x: severity_order(x.get("severity", "UNKNOWN")))

    memory_context = {}
    if memory.get("last_hunted"):
        memory_context["last_hunted"] = memory["last_hunted"]
    if memory.get("tech_stack"):
        memory_context["tech_stack"] = memory["tech_stack"]
    if memory.get("hunt_sessions"):
        memory_context["hunt_sessions"] = memory["hunt_sessions"]
    memory_context["tested_endpoints_count"] = len(tested_endpoints)
    memory_context["tested_cves_count"] = len(tested_cves)

    # Find matching patterns from other targets
    matching_patterns = []
    target_tech = set(t.lower() for t in memory.get("tech_stack", []))
    for pattern in memory.get("patterns", []):
        pattern_tech = set(t.lower() for t in pattern.get("tech_stack", []))
        if target_tech & pattern_tech:
            matching_patterns.append({
                "target": pattern.get("target", ""),
                "technique": pattern.get("technique", ""),
                "vuln_class": pattern.get("vuln_class", ""),
                "payout": pattern.get("payout", 0),
            })
    if matching_patterns:
        memory_context["matching_patterns"] = matching_patterns

    return {
        "critical": critical,
        "high": high,
        "info": info,
        "memory_context": memory_context,
        "total": len(results),
    }


SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
APPLICABILITY_RANK = {"not_affected": 0, "unknown": 1, "likely": 2, "affected": 3}


def _severity(value: object) -> str:
    text = str(value or "UNKNOWN").upper()
    if text == "MODERATE":
        text = "MEDIUM"
    return text if text in SEVERITY_RANK else "UNKNOWN"


def _component_key(component: dict) -> tuple[str, str]:
    return (
        str(component.get("name") or "").strip().lower(),
        str(component.get("version") or "").strip(),
    )


def _identifiers(item: dict) -> set[str]:
    values = {
        str(item.get("id") or "").strip().upper(),
        *(str(value).strip().upper() for value in item.get("aliases") or []),
    }
    return {value for value in values if value}


def _canonical_identifier(values: set[str]) -> str:
    cves = sorted(value for value in values if value.startswith("CVE-"))
    if cves:
        return cves[0]
    ghsas = sorted(value for value in values if value.startswith("GHSA-"))
    if ghsas:
        return ghsas[0]
    return sorted(values)[0] if values else ""


def _merge_unique_strings(*groups: object) -> list[str]:
    result = []
    seen = set()
    for group in groups:
        for value in group if isinstance(group, list) else []:
            text = str(value or "").strip()
            if text and text not in seen:
                seen.add(text)
                result.append(text)
    return result


def _merge_component(left: dict, right: dict) -> dict:
    merged = {**left, **{key: value for key, value in right.items() if value not in (None, "", [], {})}}
    merged["hosts"] = _merge_unique_strings(left.get("hosts"), right.get("hosts"))
    merged["urls"] = _merge_unique_strings(left.get("urls"), right.get("urls"))
    return merged


def _source_ref_key(ref: dict) -> tuple[str, str, str]:
    return (
        str(ref.get("source") or ""),
        str(ref.get("id") or ""),
        str(ref.get("url") or ""),
    )


def _merge_unique_objects(*groups: object) -> list[dict]:
    result: list[dict] = []
    seen: set[str] = set()
    for group in groups:
        for value in group if isinstance(group, list) else []:
            if not isinstance(value, dict):
                continue
            key = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if key not in seen:
                seen.add(key)
                result.append(value)
    return result


def _normalize_advisory(raw: dict) -> dict | None:
    identifiers = _identifiers(raw)
    component = raw.get("component") if isinstance(raw.get("component"), dict) else {}
    component_name, _component_version = _component_key(component)
    if not identifiers or not component_name:
        return None
    item = dict(raw)
    item["id"] = _canonical_identifier(identifiers)
    item["aliases"] = sorted(identifiers)
    item["component"] = dict(component)
    item["severity"] = _severity(item.get("severity"))
    item["applicability"] = (
        item.get("applicability")
        if item.get("applicability") in APPLICABILITY_RANK
        else "unknown"
    )
    source = str(item.get("source") or "").strip()
    item["source_names"] = [source] if source else []
    item["source_refs"] = [
        ref for ref in item.get("source_refs") or [] if isinstance(ref, dict)
    ]
    item["fixed_versions"] = _merge_unique_strings(item.get("fixed_versions"))
    item["affected_ranges"] = _merge_unique_objects(item.get("affected_ranges"))
    return item


def _merge_advisory_record(current: dict, incoming: dict) -> dict:
    all_identifiers = _identifiers(current) | _identifiers(incoming)
    current["id"] = _canonical_identifier(all_identifiers)
    current["aliases"] = sorted(all_identifiers)
    current["component"] = _merge_component(
        current.get("component") or {}, incoming.get("component") or {}
    )
    incoming_severity = _severity(incoming.get("severity"))
    if SEVERITY_RANK[incoming_severity] > SEVERITY_RANK[_severity(current.get("severity"))]:
        current["severity"] = incoming_severity
    incoming_applicability = str(incoming.get("applicability") or "unknown")
    if APPLICABILITY_RANK.get(incoming_applicability, 1) > APPLICABILITY_RANK.get(
        str(current.get("applicability") or "unknown"), 1
    ):
        current["applicability"] = incoming_applicability
    try:
        incoming_cvss = float(incoming.get("cvss")) if incoming.get("cvss") is not None else None
    except (TypeError, ValueError):
        incoming_cvss = None
    try:
        current_cvss = float(current.get("cvss")) if current.get("cvss") is not None else None
    except (TypeError, ValueError):
        current_cvss = None
    if incoming_cvss is not None and (current_cvss is None or incoming_cvss > current_cvss):
        current["cvss"] = incoming_cvss
    if not current.get("summary") and incoming.get("summary"):
        current["summary"] = incoming["summary"]
    current["published"] = min(
        [
            value
            for value in (
                str(current.get("published") or ""),
                str(incoming.get("published") or ""),
            )
            if value
        ],
        default="",
    )
    current["modified"] = max(
        [
            value
            for value in (
                str(current.get("modified") or ""),
                str(incoming.get("modified") or ""),
            )
            if value
        ],
        default="",
    )
    current["fixed_versions"] = _merge_unique_strings(
        current.get("fixed_versions"), incoming.get("fixed_versions")
    )
    current["affected_ranges"] = _merge_unique_objects(
        current.get("affected_ranges"), incoming.get("affected_ranges")
    )
    current["poc_available"] = bool(
        current.get("poc_available") or incoming.get("poc_available")
    )
    current["source_names"] = _merge_unique_strings(
        current.get("source_names"), incoming.get("source_names")
    )
    refs = {
        _source_ref_key(ref): ref
        for ref in current.get("source_refs") or []
        if isinstance(ref, dict)
    }
    for ref in incoming.get("source_refs") or []:
        if isinstance(ref, dict):
            refs.setdefault(_source_ref_key(ref), ref)
    current["source_refs"] = list(refs.values())
    return current


def merge_advisory_items(source_envelopes: list[dict]) -> list[dict]:
    """按 component + CVE/GHSA alias closure 合并多来源 advisory。"""
    grouped: dict[tuple[str, str], list[dict]] = {}
    for envelope in source_envelopes:
        for raw in envelope.get("items") or []:
            if not isinstance(raw, dict):
                continue
            item = _normalize_advisory(raw)
            if item is None:
                continue
            component_key = _component_key(item.get("component") or {})
            candidates = grouped.setdefault(component_key, [])
            matches = [
                index
                for index, existing in enumerate(candidates)
                if _identifiers(existing) & _identifiers(item)
            ]
            if not matches:
                candidates.append(item)
                continue
            base_index = matches[0]
            base = _merge_advisory_record(candidates[base_index], item)
            # 一个新 alias 可能把此前分离的 GHSA-only/CVE-only cluster 连起来。
            for index in reversed(matches[1:]):
                base = _merge_advisory_record(base, candidates[index])
                candidates.pop(index)
            candidates[base_index] = base
    merged = [item for candidates in grouped.values() for item in candidates]
    return sorted(
        merged,
        key=lambda item: (
            _component_key(item.get("component") or {}),
            str(item.get("id") or ""),
        ),
    )


_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def load_local_advisory_signals(repo_root: str | Path, target: str) -> dict:
    """从 canonical finding index 读取显式 CVE/Nuclei 线索，不扫描或改写状态。"""
    try:
        from tools.finding_index import load_finding_index
    except ImportError:  # pragma: no cover - direct tools/ execution
        from finding_index import load_finding_index  # type: ignore

    resolved_target = canonical_target_value(target)
    findings_dir = Path(repo_root) / "findings" / target_storage_key(resolved_target)
    path = findings_dir / "findings.json"
    if not path.is_file():
        return {
            "source": "local_nuclei",
            "status": "unavailable",
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cached": True,
            "stale": False,
            "error": "canonical findings artifact is missing",
            "items": {},
            "stats": {"item_count": 0},
        }
    try:
        raw_payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw_payload, (dict, list)):
            raise ValueError("canonical findings artifact must be an object or legacy list")
        payload = load_finding_index(findings_dir, migrate_legacy=False)
    except Exception as exc:  # 可选本地来源失败只降级该 source envelope。
        return {
            "source": "local_nuclei",
            "status": "error",
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cached": True,
            "stale": False,
            "error": str(exc),
            "items": {},
            "stats": {"item_count": 0},
        }

    index: dict[str, list[dict]] = {}
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        searchable = " ".join(
            str(finding.get(key) or "")
            for key in ("template_id", "id", "raw", "summary")
        )
        cve_ids = sorted({value.upper() for value in _CVE_ID_RE.findall(searchable)})
        if not cve_ids:
            continue
        reference = {
            "finding_id": str(finding.get("id") or ""),
            "template_id": str(finding.get("template_id") or ""),
            "source_file": str(finding.get("source_file") or ""),
            "validation_status": str(finding.get("validation_status") or "unvalidated"),
        }
        for cve_id in cve_ids:
            if reference not in index.setdefault(cve_id, []):
                index[cve_id].append(reference)
    return {
        "source": "local_nuclei",
        "status": "ok",
        "fetched_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "cached": True,
        "stale": False,
        "error": "",
        "items": index,
        "stats": {"item_count": sum(len(items) for items in index.values())},
    }


def enrich_advisories(
    advisories: list[dict],
    kev: dict,
    epss: dict,
    local_signals: dict | None = None,
) -> list[dict]:
    kev_index = kev.get("items") if isinstance(kev.get("items"), dict) else {}
    epss_index = epss.get("items") if isinstance(epss.get("items"), dict) else {}
    local_index = (
        local_signals.get("items")
        if isinstance(local_signals, dict) and isinstance(local_signals.get("items"), dict)
        else {}
    )
    enriched = []
    for advisory in advisories:
        item = dict(advisory)
        identifiers = _identifiers(item)
        cve_id = next((value for value in sorted(identifiers) if value.startswith("CVE-")), "")
        kev_detail = kev_index.get(cve_id) if cve_id else None
        epss_detail = epss_index.get(cve_id) if cve_id else None
        nuclei_refs = local_index.get(cve_id) if cve_id else []
        nuclei_refs = [ref for ref in nuclei_refs or [] if isinstance(ref, dict)]
        item["kev"] = bool(kev_detail)
        item["kev_detail"] = kev_detail or {}
        item["epss"] = epss_detail.get("score") if isinstance(epss_detail, dict) else None
        item["epss_percentile"] = (
            epss_detail.get("percentile") if isinstance(epss_detail, dict) else None
        )
        item["epss_date"] = epss_detail.get("date") if isinstance(epss_detail, dict) else ""
        item["nuclei_templates"] = _merge_unique_strings(
            [str(ref.get("template_id") or "") for ref in nuclei_refs]
        )
        item["local_evidence_refs"] = nuclei_refs
        enriched.append(item)
    return enriched


def _age_days(value: str, now: datetime) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(text[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, (now.astimezone(timezone.utc) - parsed.astimezone(timezone.utc)).days)


def score_advisory(item: dict, *, now: datetime | None = None) -> tuple[int, list[str]]:
    """生成可解释的 advisory review hint；该分数不是漏洞结论。"""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    score = 0
    reasons: list[str] = []
    applicability = str(item.get("applicability") or "unknown")
    applicability_scores = {"affected": 40, "likely": 25, "unknown": 0, "not_affected": -100}
    delta = applicability_scores.get(applicability, 0)
    score += delta
    reasons.append(f"applicability={applicability} ({delta:+d})")

    component = item.get("component") if isinstance(item.get("component"), dict) else {}
    if component.get("version") and applicability in {"affected", "likely"}:
        score += 15
        reasons.append("observed exact version (+15)")
    elif not component.get("version"):
        score -= 10
        reasons.append("version unknown (-10)")
    if component.get("hosts") or component.get("urls"):
        score += 10
        reasons.append("target-observed component (+10)")

    if item.get("kev"):
        score += 50
        reasons.append("CISA KEV (+50)")
    try:
        epss = float(item.get("epss")) if item.get("epss") is not None else None
    except (TypeError, ValueError):
        epss = None
    if epss is not None:
        if epss >= 0.7:
            score += 30
            reasons.append("EPSS>=0.7 (+30)")
        elif epss >= 0.3:
            score += 15
            reasons.append("EPSS>=0.3 (+15)")
        elif epss >= 0.1:
            score += 5
            reasons.append("EPSS>=0.1 (+5)")
    if item.get("poc_available"):
        score += 15
        reasons.append("public POC/reference signal (+15)")
    if item.get("nuclei_templates"):
        score += 12
        reasons.append("local Nuclei/CVE template signal (+12)")

    try:
        cvss = float(item.get("cvss")) if item.get("cvss") is not None else None
    except (TypeError, ValueError):
        cvss = None
    if cvss is not None:
        if cvss >= 9.0:
            score += 15
            reasons.append("CVSS>=9 (+15)")
        elif cvss >= 7.0:
            score += 10
            reasons.append("CVSS>=7 (+10)")
    else:
        severity = _severity(item.get("severity"))
        if severity == "CRITICAL":
            score += 15
            reasons.append("critical severity (+15)")
        elif severity == "HIGH":
            score += 10
            reasons.append("high severity (+10)")

    age = _age_days(str(item.get("published") or ""), current)
    if age is not None:
        if age <= 30:
            score += 20
            reasons.append("published<=30d (+20)")
        elif age <= 90:
            score += 15
            reasons.append("published<=90d (+15)")
        elif age <= 365:
            score += 8
            reasons.append("published<=365d (+8)")
    if item.get("source_names") == ["nvd"] and applicability == "unknown":
        score -= 10
        reasons.append("NVD keyword-only relevance (-10)")
    return score, reasons


def prioritize_advisories(advisories: list[dict], memory: dict, *, now: datetime | None = None) -> dict:
    tested_cves = {str(value).upper() for value in memory.get("tested_cves", [])}
    critical: list[dict] = []
    high: list[dict] = []
    info: list[dict] = []
    for advisory in advisories:
        item = dict(advisory)
        identifiers = _identifiers(item)
        item["already_tested"] = bool(identifiers & tested_cves)
        score, reasons = score_advisory(item, now=now)
        item["score_hint"] = score
        item["score_reasons"] = reasons
        if item["already_tested"]:
            item["note"] = "Already tested in target memory; keep for history, not first review."
            info.append(item)
        elif item.get("applicability") == "not_affected":
            item["note"] = "Observed version is outside the affected set reported by the source."
            info.append(item)
        elif score >= 90:
            item["note"] = "High-confidence advisory lead; verify affected route and runtime reachability."
            critical.append(item)
        elif score >= 55:
            item["note"] = "Prioritized advisory lead; confirm version and reachable code path."
            high.append(item)
        else:
            item["note"] = "Advisory context only; applicability or exploitability remains incomplete."
            info.append(item)

    sort_key = lambda item: (-int(item.get("score_hint") or 0), str(item.get("id") or ""))
    critical.sort(key=sort_key)
    high.sort(key=sort_key)
    info.sort(key=sort_key)
    all_advisories = sorted([*critical, *high, *info], key=sort_key)
    return {
        "advisories": all_advisories,
        "critical": critical,
        "high": high,
        "info": info,
    }


def _memory_projection(memory: dict) -> dict:
    return prioritize_intel([], memory).get("memory_context", {})


def _synthetic_components(techs: list[str], target: str) -> list[dict]:
    components = []
    for tech in techs:
        name, display_name, version = split_component_label(tech)
        if not name:
            continue
        components.append({
            "name": name,
            "display_name": display_name,
            "version": version,
            "raw_label": tech,
            "url": "",
            "host": target,
            "source": "declared_tech_stack",
            "confidence": "declared",
        })
    return components


def _merge_components(primary: list[dict], fallback: list[dict]) -> list[dict]:
    result = []
    seen = set()
    primary_versioned_names = {
        str(item.get("name") or "").strip().lower()
        for item in primary
        if str(item.get("name") or "").strip() and str(item.get("version") or "").strip()
    }
    primary_identities = {
        (
            str(item.get("name") or "").strip().lower(),
            str(item.get("version") or "").strip(),
        )
        for item in primary
        if str(item.get("name") or "").strip()
    }
    for item in [*primary, *fallback]:
        name = str(item.get("name") or "").strip().lower()
        version = str(item.get("version") or "").strip()
        if item.get("source") == "declared_tech_stack":
            if (name, version) in primary_identities:
                continue
            if not version and name in primary_versioned_names:
                # 已观测到精确版本时，不让 memory/CLI 的无版本兼容标签新增模糊查询。
                continue
        key = (
            name,
            version,
            str(item.get("host") or "").strip(),
        )
        if not key[0] or key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _source_status(envelope: dict) -> dict:
    return {
        key: value
        for key, value in envelope.items()
        if key != "items"
    }


def _coverage_status(sources: list[dict]) -> str:
    advisory_sources = [source for source in sources if source.get("source") in {"osv", "github_advisory", "nvd"}]
    statuses = {str(source.get("status") or "") for source in advisory_sources}
    if statuses & {"ok", "partial"}:
        return "partial" if statuses & {"partial", "error"} else "ready"
    if statuses == {"unavailable"} or not statuses:
        return "unavailable"
    return "error"


def build_target_intel(
    repo_root: str | Path,
    target: str,
    *,
    techs: list[str],
    memory: dict,
    program: str = "",
    fetcher=fetch_json,
    identity_runner=None,
    include_identity: bool = True,
    now: datetime | None = None,
) -> dict:
    """构建、富化并原子发布一个目标的 Intel v2 artifact。"""
    # `program` 仅保留调用兼容；披露报告由 disclosure_search owner 管理。
    _ = program
    resolved_target = canonical_target_value(target)
    identity_runner = identity_runner or run_identity_intel
    inventory = load_or_build_inventory(repo_root, resolved_target)
    components = _merge_components(
        list(inventory.get("components") or []),
        _synthetic_components(techs, resolved_target),
    )
    source_envelopes = fetch_advisory_sources(components, repo_root, fetcher=fetcher, now=now)
    advisories = merge_advisory_items(source_envelopes)
    kev = fetch_kev(repo_root, fetcher=fetcher, now=now)
    cve_ids = [
        value
        for advisory in advisories
        for value in _identifiers(advisory)
        if value.startswith("CVE-")
    ]
    epss = fetch_epss(cve_ids, repo_root, fetcher=fetcher, now=now)
    local_signals = load_local_advisory_signals(repo_root, resolved_target)
    advisories = enrich_advisories(advisories, kev, epss, local_signals)
    prioritized = prioritize_advisories(advisories, memory, now=now)
    advisories = prioritized["advisories"]
    source_envelopes.extend([kev, epss, local_signals])

    identity = {}
    if include_identity:
        try:
            identity = identity_runner(resolved_target, repo_root=repo_root)
        except Exception as exc:  # 身份情报是独立可恢复来源，不能抹掉 advisory 结果。
            identity = {"status": "error", "error": str(exc)}
    generated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "schema_version": INTEL_SCHEMA_VERSION,
        "target": resolved_target,
        "generated_at": generated_at,
        "coverage_status": _coverage_status(source_envelopes),
        "inventory": {
            "status": inventory.get("status", "unavailable"),
            "generated_at": inventory.get("generated_at", ""),
            "source": inventory.get("source", {}),
            "components": components,
            "hosts": inventory.get("hosts", []),
            "stats": inventory.get("stats", {}),
        },
        "sources": [_source_status(source) for source in source_envelopes],
        "advisories": advisories,
        "critical": prioritized["critical"],
        "high": prioritized["high"],
        "info": prioritized["info"],
        "memory_context": _memory_projection(memory),
        "identity_intel": identity,
        "total": len(advisories),
        "stats": {
            "component_count": len(components),
            "advisory_count": len(advisories),
            "affected_count": sum(1 for item in advisories if item.get("applicability") == "affected"),
            "likely_count": sum(1 for item in advisories if item.get("applicability") == "likely"),
            "unknown_count": sum(1 for item in advisories if item.get("applicability") == "unknown"),
            "kev_count": sum(1 for item in advisories if item.get("kev")),
            "epss_count": sum(1 for item in advisories if item.get("epss") is not None),
            "nuclei_signal_count": sum(1 for item in advisories if item.get("nuclei_templates")),
        },
    }
    write_intel_artifact(repo_root, resolved_target, payload)
    return payload


def format_output(target: str, intel: dict) -> str:
    """格式化人类可读输出；所有条目仍只是待复核 advisory lead。"""
    lines = [
        "",
        f"{BOLD}INTEL: {target}{RESET}",
        f"{'═' * 50}",
        "",
    ]

    coverage = str(intel.get("coverage_status") or "legacy")
    components = (intel.get("inventory") or {}).get("components") or []
    component_labels_display = []
    for component in components[:12]:
        if not isinstance(component, dict):
            continue
        name = str(component.get("display_name") or component.get("name") or "").strip()
        version = str(component.get("version") or "").strip()
        if name:
            component_labels_display.append(f"{name}@{version}" if version else name)
    lines.append(f"Coverage: {coverage}")
    if component_labels_display:
        lines.append(f"Components: {', '.join(component_labels_display)}")

    sources = [item for item in intel.get("sources") or [] if isinstance(item, dict)]
    if sources:
        lines.extend(["", f"{BOLD}SOURCES:{RESET}"])
        for source in sources:
            cached = " cached" if source.get("cached") else ""
            stale = " stale" if source.get("stale") else ""
            fetched = str(source.get("fetched_at") or "-")
            lines.append(
                f"  [{source.get('status', 'unknown')}] {source.get('source', 'unknown')}"
                f"{cached}{stale} @ {fetched}"
            )
            if source.get("error"):
                lines.append(f"    → {str(source['error'])[:240]}")
        lines.append("")

    def append_advisory(item: dict, label: str, color: str) -> None:
        summary = str(item.get("summary") or "").strip()
        lines.append(f"  {color}[{label}]{RESET} {item.get('id', '')} — {summary}")
        component = item.get("component") if isinstance(item.get("component"), dict) else {}
        component_name = str(component.get("display_name") or component.get("name") or "unknown")
        version = str(component.get("version") or "unknown")
        epss = item.get("epss")
        epss_text = f"{float(epss):.3f}" if isinstance(epss, (int, float)) else "-"
        lines.append(
            f"    component={component_name}@{version} "
            f"applicability={item.get('applicability', 'unknown')} "
            f"score={item.get('score_hint', 0)} kev={bool(item.get('kev'))} epss={epss_text}"
        )
        if item.get("nuclei_templates"):
            lines.append(f"    local templates: {', '.join(item['nuclei_templates'][:5])}")
        if item.get("note"):
            lines.append(f"    → {item['note']}")

    if intel["critical"]:
        lines.append(f"{BOLD}ALERTS:{RESET}")
        for item in intel["critical"]:
            append_advisory(item, "CRITICAL", RED)
        lines.append("")

    if intel["high"]:
        if not intel["critical"]:
            lines.append(f"{BOLD}ALERTS:{RESET}")
        for item in intel["high"]:
            append_advisory(item, "HIGH", YELLOW)
        lines.append("")

    if intel["info"]:
        info_count = len(intel["info"])
        tested = sum(1 for i in intel["info"] if i.get("already_tested"))
        lines.append(
            f"  {GREEN}[INFO]{RESET} {info_count} additional advisory leads "
            f"({tested} already tested)"
        )
        lines.append("")
    elif not intel["critical"] and not intel["high"]:
        lines.append("No advisory leads returned for the observed components.")
        lines.append("")

    # Memory context
    mc = intel.get("memory_context", {})
    if mc:
        lines.append(f"{BOLD}MEMORY CONTEXT:{RESET}")
        if mc.get("last_hunted"):
            lines.append(f"  Last hunted: {mc['last_hunted']}")
        if mc.get("hunt_sessions"):
            lines.append(f"  Hunt sessions: {mc['hunt_sessions']}")
        if mc.get("tech_stack"):
            lines.append(f"  Tech stack: {', '.join(mc['tech_stack'])}")
        lines.append(f"  Tested endpoints: {mc.get('tested_endpoints_count', 0)}")
        lines.append(f"  Tested CVEs: {mc.get('tested_cves_count', 0)}")

        if mc.get("matching_patterns"):
            lines.append(f"  {CYAN}Cross-target patterns:{RESET}")
            for p in mc["matching_patterns"][:3]:
                payout = f" (${p['payout']})" if p.get("payout") else ""
                lines.append(f"    • {p['target']}: {p['technique']} [{p['vuln_class']}]{payout}")

    lines.append("")

    identity = intel.get("identity_intel") or {}
    if identity:
        artifact_dir = identity.get("artifact_dir", "")
        if artifact_dir:
            artifact_dir = os.path.relpath(artifact_dir, REPO_ROOT)
        lines.append(f"{BOLD}IDENTITY INTEL:{RESET}")
        lines.append(
            f"  emailfinder: {identity.get('emailfinder_status', 'unknown')} "
            f"({identity.get('email_count', 0)} lines)"
        )
        lines.append(
            f"  LeakSearch: {identity.get('leaksearch_status', 'unknown')} "
            f"({identity.get('leak_line_count', 0)} lines)"
        )
        if artifact_dir:
            lines.append(f"  Artifacts: {artifact_dir}/")
        lines.append("")

    lines.append(
        f"{DIM}Total: {intel.get('total', 0)} advisory leads; "
        f"review order only, not validated findings{RESET}"
    )
    lines.append("")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="On-demand intel for a target")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--tech", default="", help="Comma-separated tech stack")
    parser.add_argument(
        "--program",
        default="",
        help="Compatibility program hint; disclosure research is handled separately",
    )
    parser.add_argument("--memory-dir", default="", help="Path to hunt-memory directory")
    parser.add_argument("--repo-root", default=REPO_ROOT, help="Repository root for target artifacts")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of formatted text")
    return parser


def _emit_cli_error(*, target: str, message: str, json_mode: bool, code: int) -> int:
    print(f"intel error: {message}", file=sys.stderr)
    if json_mode:
        print(json.dumps({"status": "error", "target": target, "error": message}, ensure_ascii=False))
    return code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        resolved_target = canonical_target_value(args.target)
    except ValueError as exc:
        return _emit_cli_error(target=str(args.target), message=str(exc), json_mode=args.json, code=1)

    techs = [t.strip() for t in args.tech.split(",") if t.strip()] if args.tech else []

    # Load memory context before enforcing --tech so standalone /intel can reuse prior recon/hunt state.
    memory = load_memory_context(args.memory_dir, resolved_target)
    try:
        techs = resolve_tech_stack(resolved_target, techs, memory, repo_root=args.repo_root)
    except (OSError, TechnologyInventoryError, ValueError) as exc:
        return _emit_cli_error(
            target=resolved_target,
            message=f"technology inventory failed: {exc}",
            json_mode=args.json,
            code=1,
        )

    if not techs:
        return _emit_cli_error(
            target=resolved_target,
            message="no technology components available; run recon or pass --tech",
            json_mode=args.json,
            code=1,
        )

    print(
        f"intel: target={resolved_target} components={len(techs)}",
        file=sys.stderr,
    )
    if args.program:
        print(
            "intel: --program is retained for compatibility; disclosed-report research uses disclosure_search.py",
            file=sys.stderr,
        )

    try:
        intel = build_target_intel(
            args.repo_root,
            resolved_target,
            techs=techs,
            memory=memory,
            program=args.program,
        )
    except (OSError, ValueError, TechnologyInventoryError, IntelArtifactError) as exc:
        return _emit_cli_error(
            target=resolved_target,
            message=str(exc),
            json_mode=args.json,
            code=1,
        )

    if args.json:
        print(json.dumps(intel, ensure_ascii=False, indent=2))
    else:
        print(format_output(resolved_target, intel))
    return 0 if intel.get("coverage_status") in {"ready", "partial"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
