#!/usr/bin/env python3
"""Publish AI-authored, owner-bound reports and rebuild their current index."""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path

try:
    from tools.artifact_io import write_text_atomic as _write_text_atomic
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_text_atomic as _write_text_atomic

try:
    from finding_index import _finding_backend_context
    from target_paths import target_storage_key
    from target_store import (
        ConflictError, StoreError, TargetStore, read_report_asset, report_attachment_refs,
        runtime_store, target_mutation_lock, target_switch_lock,
    )
except ImportError:  # pragma: no cover - package import path
    from tools.finding_index import _finding_backend_context
    from tools.target_paths import target_storage_key
    from tools.target_store import (
        ConflictError, StoreError, TargetStore, read_report_asset, report_attachment_refs,
        runtime_store, target_mutation_lock, target_switch_lock,
    )

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Preserve historical index type aliases, not category-based report narratives.


REPORT_VULN_TYPE_ALIASES = {
    "authentication_bypass": "auth_bypass",
    "auth_bypass": "auth_bypass",
    "authorization_bypass": "auth_bypass",
    # closure 词汇（validation_runner/closure_resolver 用 Authz 归一）；
    # 词汇统一（310c9ef）后 canonical type 可能为 Authz——报告模板同义。
    "authz": "auth_bypass",
    "authorization": "auth_bypass",
    "access_control": "auth_bypass",
    "remote_code_execution": "rce",
    "command_injection": "rce",
    "os_command_injection": "rce",
    "unsafe_deserialization": "deserialization",
    "deserialisation": "deserialization",
    "xml_external_entity": "xxe",
    "xml_injection": "xxe",
    "pathtraversal": "path_traversal",
    "directory_traversal": "path_traversal",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "xsrf": "csrf",
    "race_condition": "race",
    "toctou": "race",
}


def _report_vuln_type(finding):
    """Preserve an open-ended family in the report index."""
    raw_type = str(finding.get("type") or finding.get("category") or "unknown").strip()
    normalized = raw_type.lower().replace("-", "_")
    return REPORT_VULN_TYPE_ALIASES.get(normalized, normalized)


def declared_report_severity(content: str) -> dict:
    """Read only explicit Severity fields outside fenced examples."""
    values = []
    pending = False
    fence = ""
    for line in content.splitlines():
        raw = line.strip()
        if raw.startswith(("```", "~~~")):
            marker = raw[:3]
            fence = "" if fence == marker else (fence or marker)
            continue
        if fence:
            continue
        text = raw.replace("**", "").replace("`", "")
        if re.fullmatch(r"#{1,6}\s+Severity\s*:? *", text, re.I):
            pending = True
            continue
        field = re.match(r"(?:[-*]\s+)?Severity\s*:\s*(.*)$", text, re.I)
        if field or (pending and text):
            value = field.group(1) if field else text
            match = re.match(r"(critical|high|medium|low|info|unknown)(?=$|\s|[(:—–-])", value, re.I)
            values.append(match.group(1).lower() if match else "invalid")
            pending = False
    if pending:
        values.append("invalid")
    if not values:
        return {"severity": "unknown", "reason": "no explicit severity declaration"}
    if "invalid" in values or len(set(values)) != 1:
        return {"severity": "unknown", "reason": "invalid or conflicting severity declarations"}
    return {"severity": values[0], "reason": "explicit report declaration"}


def _is_reportable_structured_finding(finding):
    """Require a confirmed assessment and its current eligible delivery."""
    if not isinstance(finding, dict) or not finding.get("url"):
        return False
    assessment = finding.get("assessment") or {}
    return assessment.get("verdict") == "confirmed" and any(
        item.get("status") == "eligible" and not item.get("stale")
        and item.get("assessment_id") == assessment.get("id")
        for item in finding.get("deliveries", [])
    )


def _publish_bytes(report_file, data):
    """Publish complete bytes without overwrite; retry only identical bytes."""
    path = Path(report_file)
    if path.is_symlink():
        raise StoreError("report output must not be a symlink")
    if path.exists() and not path.is_file():
        raise StoreError("report output must be a regular file")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != data:
                raise FileExistsError(f"report already exists with different bytes: {path}")
            return "reused"
        return "created"
    finally:
        if temporary is not None:
            temporary.unlink()


def _read_report_body(body_file):
    path = Path(body_file)
    if not path.is_file():
        raise ValueError("report body must be a regular UTF-8 file")
    content = path.read_bytes().decode("utf-8")
    if not content.strip():
        raise ValueError("report body must be non-empty UTF-8 text")
    return content


def _primary_findings(store: TargetStore) -> list[dict]:
    """Project Store findings into the report renderer's read-only shape."""
    findings = []
    page = store.finding_page(limit=1000)
    while True:
        for item in page.get("items", []):
            if not isinstance(item, dict):
                continue
            finding = item
            assessment = finding.get("assessment") or {}
            reports = finding.get("reports") or []
            report = next((item for item in reversed(reports) if not item.get("stale")), {})
            artifact_ref = str(report.get("artifact_ref") or "").strip()
            report_file = str(store.root / artifact_ref) if artifact_ref else ""
            findings.append({
                "id": finding["id"],
                "type": finding["family"],
                "category": finding["family"],
                "title": finding["title"],
                "summary": finding["claim"],
                "url": finding["endpoint"],
                "method": finding["method"],
                "severity": "unknown",
                "confidence": assessment.get("verdict", ""),
                "validation_status": "validated" if assessment.get("verdict") == "confirmed" else "",
                "report_status": "generated" if report_file else "not_generated",
                "report_id": report.get("id", ""),
                "report_file": report_file,
                "raw": finding["claim"],
                "assessment": assessment,
                "deliveries": finding.get("deliveries", []),
                "reports": reports,
                "evidence": finding.get("evidence", []),
            })
        if not page.get("has_more"):
            break
        page = store.finding_page(limit=1000, cursor=page.get("next_cursor"))
    return findings


def _publish_authored_report(store, report_dir, *, finding_id, assessment_id, delivery_id, body_file):
    """Bind explicitly submitted text to the current assessment and destination."""
    finding = store.finding(finding_id)
    assessment = finding.get("assessment") or {}
    delivery = next((item for item in finding.get("deliveries", []) if item["id"] == delivery_id), None)
    if (assessment.get("id") != assessment_id or assessment.get("verdict") != "confirmed"
            or not delivery or delivery["assessment_id"] != assessment_id
            or delivery["status"] != "eligible" or delivery["stale"]):
        raise StoreError("report publication requires the current confirmed assessment and eligible delivery")
    # Query projections already check integrity; recheck the bound execution at publication.
    for operation_id in {ref["operation_id"] for ref in assessment["evidence"]}:
        store.verify_operation(operation_id)
    content = _read_report_body(body_file)
    binding = json.dumps([store.target, finding_id, assessment_id, delivery_id])
    report_id = "report_" + hashlib.sha256(binding.encode("utf-8")).hexdigest()
    report_file = Path(report_dir) / f"{report_id}.md"
    registered = next((item for item in finding["reports"] if item["id"] == report_id), None)
    if registered and registered["stale"]:
        raise StoreError("registered report is stale or damaged; publication cannot repair it")
    if registered and report_file.read_bytes() != content.encode("utf-8"):
        raise FileExistsError(f"report already exists with different bytes: {report_file}")
    if not registered:
        # Only unregistered publications may create files, including on interrupted retry.
        for ref in report_attachment_refs(content.encode("utf-8")):
            source = Path(body_file).resolve().parent / ref
            data, _ = read_report_asset(source, source.name[:64])
            destination = Path(report_dir) / ref
            if destination.parent != destination.parent.resolve():
                raise StoreError("report screenshot directory must not be a symlink")
            destination.parent.mkdir(exist_ok=True)
            _publish_bytes(destination, data)
        _publish_bytes(report_file, content.encode("utf-8"))
    return store.register_report(
        command_id=f"report:{report_id}", report_id=report_id, finding_id=finding_id,
        assessment_id=assessment_id, delivery_id=delivery_id, artifact=str(report_file),
        actor="report-generator",
    )


def _process_primary_reports(store, report_dir, target_name):
    """Index registered bodies and expose missing drafts without inventing content."""
    source_binding = store.binding()
    as_of = datetime.now(timezone.utc).isoformat()
    entries, pending_drafts = [], []
    for finding in _primary_findings(store):
        if _is_reportable_structured_finding(finding):
            assessment_id = finding["assessment"]["id"]
            registered_pairs = {(r["assessment_id"], r["delivery_id"]) for r in finding["reports"]}
            for delivery in finding["deliveries"]:
                if (delivery["status"] == "eligible" and not delivery["stale"]
                        and delivery["assessment_id"] == assessment_id
                        and (assessment_id, delivery["id"]) not in registered_pairs):
                    pending_drafts.append({
                        "finding_id": finding["id"], "assessment_id": assessment_id,
                        "delivery_id": delivery["id"], "destination": delivery["destination"],
                        "status": "needs_draft",
                    })
        for report in finding["reports"]:
            if report["stale"]:
                continue
            report_bytes = (store.root / report["artifact_ref"]).read_bytes()
            if hashlib.sha256(report_bytes).hexdigest() != report["artifact_sha256"]:
                raise StoreError("registered report changed while reading severity; retry after evidence repair")
            severity = declared_report_severity(report_bytes.decode("utf-8"))
            entries.append({
                "id": report["id"], "finding_id": finding["id"],
                "title": finding["title"], "severity": severity["severity"],
                "severity_reason": severity["reason"],
                "url": finding["url"], "file": str(store.root / report["artifact_ref"]),
                "type": _report_vuln_type(finding), "family": finding["type"], "confidence": finding["confidence"],
                "assessment_id": report["assessment_id"], "delivery_id": report["delivery_id"],
                "destination": report["destination"], "artifact_sha256": report["artifact_sha256"],
                "queue_sync": {"status": "skipped", "reason": "primary store owns report lifecycle"},
                "canonical_lifecycle": True,
            })
    return write_report_index(report_dir, target_name, len(entries), entries, write_empty=True,
                              store=store, source_binding=source_binding, as_of=as_of,
                              pending_drafts=pending_drafts)


def process_findings_dir(findings_dir, *, finding_id="", assessment_id="", delivery_id="", body_file=None):
    """Publish optional authored text, then rebuild the target's bound report index."""
    submission = (finding_id, assessment_id, delivery_id, body_file)
    if any(submission) and not all(submission):
        raise ValueError("publication requires finding_id, assessment_id, delivery_id and body_file together")
    repo_root, target = _finding_backend_context(findings_dir)
    runtime_store(repo_root, target)
    with target_switch_lock(repo_root, target):
        _finding_backend_context(findings_dir, target)
        store = runtime_store(repo_root, target)
        report_dir = store.root / "reports" / store.key
        if report_dir != report_dir.resolve():
            raise StoreError(f"report output does not match directory owner: {report_dir}")
        report_dir.mkdir(parents=True, exist_ok=True)
        if body_file is not None:
            _publish_authored_report(store, report_dir, finding_id=finding_id,
                                    assessment_id=assessment_id, delivery_id=delivery_id, body_file=body_file)
        return _process_primary_reports(store, str(report_dir), store.key)


def write_report_index(report_dir, target_name, total_reports, report_index, *, write_empty=False,
                       store, source_binding, as_of, pending_drafts=()):
    """Publish the index only while its source snapshot is still current."""
    with target_mutation_lock(store.root, store.target):
        if store.binding() != source_binding:
            raise ConflictError("report index source snapshot changed; regenerate reports")
        return _write_report_index(report_dir, target_name, total_reports, report_index,
                                   write_empty=write_empty, source_binding=source_binding, as_of=as_of, pending_drafts=pending_drafts)


def _write_report_index(report_dir, target_name, total_reports, report_index, *, write_empty=False,
                        source_binding=None, as_of=None, pending_drafts=()):
    if report_index or write_empty:
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        report_index.sort(key=lambda x: severity_order.get(x["severity"], 5))

        index_file = os.path.join(report_dir, "INDEX.json")
        _write_text_atomic(
            index_file,
            json.dumps(
                {
                    "target": target_name,
                    "generated_at": datetime.now().isoformat(),
                    "total_reports": total_reports,
                    "reports": report_index,
                    "pending_drafts": list(pending_drafts),
                    **({"source_binding": source_binding, "as_of": as_of} if source_binding else {}),
                },
                indent=2,
            )
            + "\n",
        )

        # Also generate a summary markdown
        summary_file = os.path.join(report_dir, "SUMMARY.md")
        summary_lines = [
            f"# Bug Bounty Report Summary — {target_name}\n",
            "\n",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "\n",
            f"Total findings: {total_reports}\n",
            f"Awaiting authored drafts: {len(pending_drafts)}\n",
            "\n",
            "| # | Severity | Type | Title | URL |\n",
            "|---|----------|------|-------|-----|\n",
        ]
        if source_binding:
            summary_lines[1:1] = [f"Snapshot as of: {as_of}; store {source_binding['store_id']}; "
                                  f"revision {source_binding['revision']}\n"]
        summary_lines.extend(
            f"| {r['id']} | {r['severity'].upper()} | {r['type']} | "
            f"{r['title'][:50]} | {r['url'][:60]} |\n"
            for r in report_index
        )
        if pending_drafts:
            summary_lines.append("\n## Awaiting authored drafts\n\n")
            summary_lines.extend(
                f"- {item['finding_id']} → {item['destination']} "
                f"(assessment `{item['assessment_id']}`, delivery `{item['delivery_id']}`)\n"
                for item in pending_drafts
            )
        _write_text_atomic(summary_file, "".join(summary_lines))

    return total_reports, report_index


def create_manual_report(vuln_type, url, param=None, evidence=None, *, body_file=None):
    """Create an unregistered editable draft from supplied text or recorded inputs."""
    if not str(vuln_type).strip() or not str(url).strip():
        raise ValueError("manual draft requires type and URL")
    if body_file is not None:
        content = _read_report_body(body_file)
    else:
        content = f"# Manual notes: {vuln_type}\n\nAffected URL: {url}\n"
        if param:
            content += f"\nParameter: {param}\n"
        if evidence:
            content += f"\n## Supplied evidence (unassessed)\n\n{evidence}\n"
    content = "> Manual draft — not assessed, registered, or submitted.\n\n" + content
    report_dir = Path(REPORTS_DIR) / target_storage_key(url) / "drafts"
    if report_dir != report_dir.resolve():
        raise StoreError("manual draft directory must not be a symlink")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / f"manual_{uuid.uuid4().hex}.md"
    _publish_bytes(report_file, content.encode("utf-8"))
    print(f"[+] Manual draft saved: {report_file}")
    return str(report_file)


def attach_poc_images(report_file, image_paths):
    """Attach collision-safe images only to an editable manual draft."""
    report = Path(os.path.abspath(report_file))
    if report != report.resolve() or not report.is_file() or report.stat().st_nlink != 1:
        raise StoreError("manual draft must be a regular single-link file without symlinks")
    reports_root = Path(REPORTS_DIR).resolve()
    if report.parent.name != "drafts" or report.parent.parent.parent != reports_root:
        raise ValueError("attach images to a manual draft before publication")
    repo_root, key = reports_root.parent, report.parent.parent.name
    state_dir = repo_root / "state" / key
    store = None
    if state_dir.exists() or state_dir.is_symlink():
        _, target = _finding_backend_context(repo_root / "findings" / key)
        store = runtime_store(repo_root, target)
    with target_mutation_lock(repo_root, store.target) if store else nullcontext():
        if store and any(
            store.root / item["artifact_ref"] == report
            for finding in _primary_findings(store) for item in finding["reports"]
        ):
            raise StoreError("registered report must not be edited; attach images before publication")
        _attach_draft_images(report, image_paths)


def _attach_draft_images(report, image_paths):
    if not report.read_text(encoding="utf-8").startswith(
        "> Manual draft — not assessed, registered, or submitted."
    ):
        raise ValueError("attach images to a manual draft before publication")
    poc_dir = report.parent / "poc_screenshots"
    if poc_dir != poc_dir.resolve():
        raise StoreError("draft screenshot directory must not be a symlink")
    poc_dir.mkdir(exist_ok=True)
    lines = ["\n\n## PoC Screenshots\n"]
    for i, image_path in enumerate(image_paths, 1):
        image = Path(image_path)
        if not image.is_file():
            raise ValueError(f"screenshot must be a regular file: {image}")
        data = image.read_bytes()
        if not data:
            raise ValueError(f"empty screenshot: {image}")
        filename = hashlib.sha256(data).hexdigest() + image.suffix.lower()
        _publish_bytes(poc_dir / filename, data)
        lines.append(f"\n### Screenshot {i}: {image.name}\n![PoC {i}](poc_screenshots/{filename})\n")
    with report.open("a", encoding="utf-8") as handle:
        handle.write("".join(lines))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bug Bounty Report Generator")
    parser.add_argument("findings_dir", nargs="?", help="Directory containing scan findings")
    parser.add_argument("--manual", action="store_true", help="Create manual report")
    parser.add_argument("--type", type=str, help="Vulnerability type (xss, ssrf, takeover, etc.)")
    parser.add_argument("--url", type=str, help="Affected URL (for manual reports)")
    parser.add_argument("--param", type=str, help="Affected parameter (for manual reports)")
    parser.add_argument("--evidence", type=str, help="Evidence/PoC text (for manual reports)")
    parser.add_argument("--poc-images", type=str, nargs="+", help="PoC screenshot PNG files to attach")
    parser.add_argument("--body-file", help="AI-authored UTF-8 Markdown; published bytes are not rewritten")
    parser.add_argument("--finding-id", default="", help="Exact Store Finding ID for publication")
    parser.add_argument("--assessment-id", default="", help="Expected current confirmed assessment ID")
    parser.add_argument("--delivery-id", default="", help="Expected current eligible destination decision ID")
    args = parser.parse_args(argv)
    if args.manual and (args.finding_id or args.assessment_id or args.delivery_id or args.findings_dir):
        parser.error("manual drafts cannot register Store judgments or accept a findings directory")
    if not args.manual and args.poc_images:
        parser.error("attach images to a manual draft before publication, not to an immutable report")

    print("=============================================")
    print("  Bug Bounty Report Generator")
    print("=============================================")

    if args.manual:
        if not args.type or not args.url:
            print("[-] Manual mode requires --type and --url")
            print("    Types: xss, ssrf, takeover, cors, redirect, exposure, cve, misconfig, idor, auth_bypass, info_disclosure")
            sys.exit(1)
        try:
            report_file = create_manual_report(args.type, args.url, args.param, args.evidence, body_file=args.body_file)
            if args.poc_images:
                attach_poc_images(report_file, args.poc_images)
        except (OSError, ValueError, StoreError) as exc:
            parser.error(str(exc))
        return

    if not args.findings_dir:
        print("[-] Please provide a findings directory or use --manual mode")
        print("    Usage: python3 report_generator.py <findings_dir>")
        print("    Usage: python3 report_generator.py --manual --type xss --url https://example.com/search?q=test")
        sys.exit(1)

    if not os.path.isdir(args.findings_dir):
        print(f"[-] Not a directory: {args.findings_dir}")
        sys.exit(1)

    try:
        total, index = process_findings_dir(args.findings_dir, finding_id=args.finding_id,
                                           assessment_id=args.assessment_id, delivery_id=args.delivery_id,
                                           body_file=args.body_file)
        repo_root, target = _finding_backend_context(args.findings_dir)
        report_dir = repo_root / "reports" / target_storage_key(target)
        pending = json.loads((report_dir / "INDEX.json").read_text(encoding="utf-8"))["pending_drafts"]
    except (OSError, ValueError, StoreError) as exc:
        parser.error(str(exc))

    print(f"\n[+] Indexed {total} current reports")
    if index:
        print("\nFindings by severity:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for r in index if r["severity"] == sev)
            if count > 0:
                print(f"  {sev.upper()}: {count}")

    print(f"\nAwaiting authored drafts: {len(pending)}")
    print(f"Index: {report_dir}/INDEX.json")
    print(f"Summary: {report_dir}/SUMMARY.md")


if __name__ == "__main__":
    main()
