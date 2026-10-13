#!/usr/bin/env python3
"""Versioned, offline capability-study contracts. No model or process invocation."""
from __future__ import annotations

import argparse
import hashlib
import fcntl
import json
import math
import os
import re
import sys
import stat
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "capability-evaluation/1"
FAMILIES = ("investigation", "absorption", "whitebox", "recovery", "correction",
            "semantic", "relation", "execution_delivery")
ARMS = ("A", "B", "C", "D", "E", "F", "K", "B_no_content",
        "B_old_organization", "B_no_whitebox_entry")
OBSERVATIONS = ("current", "directory", "candidate", "read", "result")
BINDINGS = ("source", "config", "fixtures", "oracle", "model", "permissions",
            "versions", "knowledge", "index")
STATUSES = ("completed", "timeout", "initialization_failure", "tool_failure",
            "protocol_failure", "delivery_failure", "unknown_failure", "preflight_not_run")
HARD_EVENTS = ("data_loss", "revoked_source_authorization", "cross_target_leak",
               "unsupported_upgrade", "unknown_effect_replay", "scope_auth_violation")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _object(value: Any, keys: str, name: str) -> None:
    _require(isinstance(value, dict) and set(value) == set(keys.split()),
             f"{name}: expected exactly {keys}")


def _text(value: Any, name: str) -> None:
    _require(isinstance(value, str) and bool(value.strip()), f"{name}: nonempty string required")


def _list(value: Any, name: str, *, nonempty: bool = True) -> None:
    _require(isinstance(value, list) and (bool(value) or not nonempty), f"{name}: list required")


def _identifier(value: Any, name: str) -> None:
    _require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value) is not None,
             f"{name}: invalid identifier")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_bytes(data: bytes) -> Any:
    def bad_constant(value: str) -> None:
        raise ValueError(f"nonfinite JSON number: {value}")
    return json.loads(data, object_pairs_hook=_pairs,
                      parse_constant=bad_constant)


def load_json(path: str | Path) -> Any:
    return _json_bytes(Path(path).read_bytes())


def _read_ref(ref: dict[str, Any], root: str | Path) -> tuple[Path, bytes]:
    """Verify one explicitly supplied, relative, nonsymlink artifact reference."""
    _object(ref, "path sha256", "artifact ref")
    _text(ref["path"], "ref.path")
    _require(isinstance(ref["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]) is not None,
             "ref.sha256: expected lowercase SHA256")
    relative = Path(ref["path"])
    _require(not relative.is_absolute() and all(p not in ("", ".", "..") for p in ref["path"].split("/"))
             and "\\" not in ref["path"] and not any(ord(c) < 32 for c in ref["path"]), "artifact path escapes root")
    forbidden = {".private", ".claude", ".codex", ".agents", ".git", "state", "hunt-memory",
                 "recon", "findings", "reports", ".env", "config.json"}
    _require(not set(relative.parts) & forbidden and not any(p.startswith(".env.") and p != ".env.example"
             for p in relative.parts), "private/runtime paths are not evaluation material")
    current = Path(os.path.abspath(root)) / relative
    parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in current.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(current.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        _require(stat.S_ISREG(before.st_mode), "artifact is not a regular file")
        data = handle.read()
        after = os.fstat(handle.fileno())
    _require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "artifact changed during read")
    _require(hashlib.sha256(data).hexdigest() == ref["sha256"], f"artifact hash mismatch: {relative}")
    return current, data


def verify_ref(ref: dict[str, Any], root: str | Path) -> Path:
    return _read_ref(ref, root)[0]


def read_verified_ref(ref: dict[str, Any], root: str | Path) -> bytes:
    """Return the exact verified bytes for an adapter, without a pathname reopen."""
    return _read_ref(ref, root)[1]


def _load_ref(ref: dict[str, Any], root: str | Path) -> Any:
    # Parse the exact bytes hashed through the anchored descriptor, never reopen.
    return _json_bytes(_read_ref(ref, root)[1])


def _refs(refs: Any, root: str | Path, name: str) -> None:
    _list(refs, name)
    for ref in refs:
        verify_ref(ref, root)


def _check(check: Any) -> None:
    _object(check, "role pointer equals", "oracle check")
    _identifier(check["role"], "check.role")
    _require(isinstance(check["pointer"], str) and
             (check["pointer"] == "" or check["pointer"].startswith("/")), "invalid JSON pointer")
    canonical_bytes(check["equals"])


def validate_case(case: dict[str, Any], root: str | Path) -> None:
    _object(case, "version case_id family split lineage candidate oracle", "case")
    _require(case["version"] == VERSION, "unsupported case version")
    _identifier(case["case_id"], "case_id")
    _identifier(case["lineage"], "lineage")
    _require(case["family"] in FAMILIES and case["split"] in ("dev", "heldout"), "bad family/split")
    candidate = case["candidate"]
    _object(candidate, "question allowed_actions materials initial_state", "candidate")
    _text(candidate["question"], "question")
    _list(candidate["allowed_actions"], "allowed_actions")
    for action in candidate["allowed_actions"]:
        _text(action, "allowed action")
    _refs(candidate["materials"], root, "materials")
    verify_ref(candidate["initial_state"], root)
    oracle = case["oracle"]
    _object(oracle, "sources acceptable_results required_support required_counterevidence prohibited_events mutants semantic_rubric", "oracle")
    _refs(oracle["sources"], root, "oracle sources")
    public = {ref["sha256"] for ref in candidate["materials"] + [candidate["initial_state"]]}
    _require(not public & {ref["sha256"] for ref in oracle["sources"]}, "oracle answer source exposed to candidate")
    _list(oracle["acceptable_results"], "acceptable_results")
    for solution in oracle["acceptable_results"]:
        _list(solution, "solution")
        for check in solution:
            _check(check)
    for field in ("required_support", "required_counterevidence", "prohibited_events"):
        _list(oracle[field], field, nonempty=field == "prohibited_events")
        for check in oracle[field]:
            _check(check)
    _list(oracle["mutants"], "mutants")
    for mutant in oracle["mutants"]:
        _object(mutant, "mutation artifacts expected_failed_check source", "mutant")
        _text(mutant["mutation"], "mutation")
        _check(mutant["expected_failed_check"])
        verify_ref(mutant["source"], root)
        _artifact_map(mutant["artifacts"], root)
    if oracle["semantic_rubric"] is not None:
        verify_ref(oracle["semantic_rubric"], root)
        _require(oracle["semantic_rubric"]["sha256"] not in public, "rubric leaked to candidate")


def validate_catalog(catalog: list[dict[str, Any]], root: str | Path, *, require_complete: bool = False) -> dict[str, Any]:
    """Validate actual bytes and lineage separation; drafts report missing coverage."""
    _list(catalog, "catalog")
    ids, lineage_splits, lineage_fingerprints = set(), {}, {}
    counts = {family: {"dev": set(), "heldout": set()} for family in FAMILIES}
    for case in catalog:
        validate_case(case, root)
        _require(case["case_id"] not in ids, "duplicate case_id")
        ids.add(case["case_id"])
        lineage, split = case["lineage"], case["split"]
        _require(lineage_splits.setdefault(lineage, split) == split, "lineage crosses dev/heldout")
        # Changing IDs or question wording alone cannot manufacture independent scenarios.
        fingerprint = digest(sorted({ref["sha256"] for ref in case["candidate"]["materials"] +
                                   [case["candidate"]["initial_state"]]}))
        _require(lineage_fingerprints.setdefault(fingerprint, lineage) == lineage,
                 "identical fixture renamed as independent lineage")
        counts[case["family"]][split].add(lineage)
    public_hashes = {ref["sha256"] for case in catalog for ref in
                     case["candidate"]["materials"] + [case["candidate"]["initial_state"]]}
    private_hashes = set()
    for case in catalog:
        oracle = case["oracle"]
        private_hashes.update(ref["sha256"] for ref in oracle["sources"])
        if oracle["semantic_rubric"] is not None:
            private_hashes.add(oracle["semantic_rubric"]["sha256"])
        for mutant in oracle["mutants"]:
            private_hashes.add(mutant["source"]["sha256"])
            private_hashes.update(ref["sha256"] for ref in mutant["artifacts"].values())
    _require(not public_hashes & private_hashes, "catalog oracle or mutant exposed through candidate material")
    coverage = {f: {s: len(v) for s, v in splits.items()} for f, splits in counts.items()}
    complete = all(c["dev"] >= 8 and c["heldout"] >= 12 for c in coverage.values())
    _require(not require_complete or complete, "catalog coverage requires 8 dev and 12 heldout lineages per family")
    return {"version": VERSION, "catalog_sha256": digest(catalog), "coverage": coverage, "complete": complete}


def candidate_view(case: dict[str, Any], root: str | Path) -> dict[str, Any]:
    """Allowlist projection; oracle, lineage, family and split never enter the prompt."""
    validate_case(case, root)
    return json.loads(canonical_bytes({"case_id": case["case_id"], **case["candidate"]}))


def validate_protocol(protocol: dict[str, Any], catalog: list[dict[str, Any]], root: str | Path, *, require_complete: bool = False) -> dict[str, Any]:
    _object(protocol, "version study_id catalog_sha256 arms repeats comparisons uncertainty exclusion_rules stop_rule default_candidate", "protocol")
    coverage = validate_catalog(catalog, root, require_complete=require_complete)
    _require(protocol["version"] == VERSION, "unsupported protocol version")
    _identifier(protocol["study_id"], "study_id")
    _require(protocol["catalog_sha256"] == digest(catalog), "catalog binding mismatch")
    _object(protocol["arms"], " ".join(ARMS), "arms")
    for arm, bindings in protocol["arms"].items():
        _object(bindings, " ".join(BINDINGS), f"{arm} bindings")
        for ref in bindings.values():
            verify_ref(ref, root)
    for binding in ("model", "permissions", "fixtures", "oracle"):
        _require(len({b[binding]["sha256"] for b in protocol["arms"].values()}) == 1,
                 f"arms must share {binding}")
    _require(type(protocol["repeats"]) is int and protocol["repeats"] >= 5, "at least five repeats required")
    _require(protocol["stop_rule"] == "fixed_schedule_no_replacement", "unsupported stopping rule")
    _require(protocol["default_candidate"] is None or (protocol["default_candidate"] in ARMS and protocol["default_candidate"] not in ("A", "K")), "bad default_candidate")
    _list(protocol["comparisons"], "comparisons")
    seen = set()
    for comparison in protocol["comparisons"]:
        _object(comparison, "baseline treatment split", "comparison")
        _require(comparison["baseline"] in ARMS and comparison["treatment"] in ARMS and
                 comparison["baseline"] != comparison["treatment"] and comparison["split"] in ("dev", "heldout"), "bad comparison")
        key = tuple(comparison[k] for k in ("baseline", "treatment", "split"))
        _require(key not in seen, "duplicate comparison")
        seen.add(key)
    required_dev = {(a, b, "dev") for a, b in (("A", "B"), ("B", "C"), ("C", "D"),
                    ("D", "E"), ("E", "F"), ("A", "K"), ("B", "B_no_content"),
                    ("B", "B_old_organization"), ("B", "B_no_whitebox_entry"))}
    _require(required_dev <= seen, "missing incremental/B-ablation dev comparisons")
    heldout = {key for key in seen if key[2] == "heldout"}
    _require(heldout == ({("A", protocol["default_candidate"], "heldout")} if protocol["default_candidate"] is not None else set()),
             "heldout requires one locked A/candidate comparison; development registration has no heldout slots")
    uncertainty = protocol["uncertainty"]
    _object(uncertainty, "method alpha independent_lineages_evidence", "uncertainty")
    _require(uncertainty["method"] == "paired_hoeffding_bonferroni", "unsupported uncertainty method")
    _require(type(uncertainty["alpha"]) in (float, int) and uncertainty["alpha"] == 0.05, "95% familywise intervals required")
    if uncertainty["independent_lineages_evidence"] is not None:
        verify_ref(uncertainty["independent_lineages_evidence"], root)
    _list(protocol["exclusion_rules"], "exclusion rules", nonempty=False)
    codes = set()
    for rule in protocol["exclusion_rules"]:
        _object(rule, "code reason independent_authority", "exclusion rule")
        _identifier(rule["code"], "rule.code")
        _require(rule["code"] not in codes, "duplicate exclusion code")
        codes.add(rule["code"])
        _text(rule["reason"], "rule.reason")
        _text(rule["independent_authority"], "rule.authority")
    return coverage


def planned_slots(protocol: dict[str, Any], catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Round-robin interleaving, rotating arm order; repeats are not extra scenarios."""
    return [{"case_id": case["case_id"], "arm": arm, "rep": rep}
            for rep in range(1, protocol["repeats"] + 1)
            for case in catalog
            for arm in ARMS[(rep - 1) % len(ARMS):] + ARMS[:(rep - 1) % len(ARMS)]
            if any(c["split"] == case["split"] and arm in (c["baseline"], c["treatment"])
                   for c in protocol["comparisons"])]


def _write_new(path: Path, value: Any) -> None:
    data = canonical_bytes(value) + b"\n"
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def seal_preregistration(protocol: dict[str, Any], catalog: list[dict[str, Any]], root: str | Path, studies: str | Path) -> Path:
    """Create a new study only. Local hash sealing is not third-party time attestation."""
    validate_protocol(protocol, catalog, root, require_complete=True)
    for case in catalog:
        validate_mutants(case, root)
    payload = {"version": VERSION, "protocol": protocol, "catalog": catalog,
               "slots": planned_slots(protocol, catalog),
               "sealed_at": datetime.now(timezone.utc).isoformat()}
    envelope = {"payload": payload, "sha256": digest(payload)}
    directory = Path(studies) / protocol["study_id"]
    directory.mkdir(parents=True, exist_ok=False)
    _write_new(directory / "registration.json", envelope)
    (directory / "attempts").mkdir()
    return directory


def validate_registration(envelope: dict[str, Any], root: str | Path) -> None:
    """Check a local seal and its full schedule; not an independent time receipt."""
    _object(envelope, "payload sha256", "registration")
    _require(digest(envelope["payload"]) == envelope["sha256"], "registration seal mismatch")
    payload = envelope["payload"]
    _object(payload, "version protocol catalog slots sealed_at", "registration payload")
    _require(payload["version"] == VERSION, "registration version mismatch")
    _text(payload["sealed_at"], "sealed_at")
    try:
        sealed_at = datetime.fromisoformat(payload["sealed_at"])
    except ValueError as exc:
        raise ValueError("invalid sealed_at timestamp") from exc
    _require(sealed_at.tzinfo is not None, "sealed_at must include timezone")
    validate_protocol(payload["protocol"], payload["catalog"], root, require_complete=True)
    _require(payload["slots"] == planned_slots(payload["protocol"], payload["catalog"]), "schedule mismatch")


def _registration(study: str | Path, root: str | Path) -> dict[str, Any]:
    envelope = load_json(Path(study) / "registration.json")
    validate_registration(envelope, root)
    return envelope


def _artifact_map(value: Any, root: str | Path) -> None:
    _require(isinstance(value, dict), "artifacts must map owner roles to refs")
    for role, ref in value.items():
        _identifier(role, "artifact role")
        verify_ref(ref, root)


def _slot(row: dict[str, Any]) -> tuple[str, str, int]:
    return row["case_id"], row["arm"], row["rep"]


def validate_result(row: dict[str, Any], protocol: dict[str, Any], catalog: list[dict[str, Any]], root: str | Path) -> None:
    _object(row, "version study_id registration_sha256 attempt_id case_id arm rep admission status actor output artifacts observations adjudications incident", "result")
    _require(row["version"] == VERSION and row["study_id"] == protocol["study_id"], "result version/study mismatch")
    _identifier(row["attempt_id"], "attempt_id")
    _text(row["actor"], "actor")
    _require(type(row["rep"]) is int and 1 <= row["rep"] <= protocol["repeats"], "bad rep")
    _require(row["arm"] in ARMS and any(c["case_id"] == row["case_id"] and any(
        comparison["split"] == c["split"] and row["arm"] in (comparison["baseline"], comparison["treatment"])
        for comparison in protocol["comparisons"]) for c in catalog), "unplanned slot")
    _require(row["admission"] in ("admitted", "preflight") and row["status"] in STATUSES, "bad admission/status")
    _require((row["admission"] == "preflight") == (row["status"] == "preflight_not_run"), "preflight/status mismatch")
    _require(isinstance(row["registration_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["registration_sha256"]) is not None, "invalid registration binding")
    verify_ref(row["output"], root)
    _result_artifacts(row, root)
    _list(row["observations"], "observations", nonempty=False)
    for observation in row["observations"]:
        _object(observation, "kind source", "observation")
        _require(observation["kind"] in OBSERVATIONS, "unknown observation kind")
        verify_ref(observation["source"], root)
    _validate_adjudications(row, root)
    if row["incident"] is not None:
        incident = row["incident"]
        _object(incident, "id code authority evidence", "incident")
        _identifier(incident["id"], "incident id")
        _text(incident["authority"], "incident authority")
        _require(incident["authority"] != row["actor"], "incident must have independent authority")
        _refs(incident["evidence"], root, "incident evidence")
        _text(incident["code"], "incident code")


def _validate_adjudications(row: dict[str, Any], root: str | Path) -> None:
    _list(row["adjudications"], "adjudications", nonempty=False)
    identities = set()
    for judgment in row["adjudications"]:
        _object(judgment, "identity blinded decision sources rationale", "adjudication")
        _text(judgment["identity"], "adjudicator identity")
        _require(judgment["identity"] != row["actor"] and judgment["identity"] not in identities,
                 "self-grading/duplicate adjudicator rejected")
        identities.add(judgment["identity"])
        _require(judgment["blinded"] is True and judgment["decision"] in ("pass", "fail", "uncertain"), "unblinded/invalid adjudication")
        _refs(judgment["sources"], root, "adjudication sources")
        _text(judgment["rationale"], "adjudication rationale")


def append_result(study: str | Path, row: dict[str, Any], root: str | Path) -> Path:
    """Publish immutable original attempt; replacements require a new study."""
    registration = _registration(study, root)
    payload = registration["payload"]
    validate_result(row, payload["protocol"], payload["catalog"], root)
    _require(row["registration_sha256"] == registration["sha256"], "result not bound to seal")
    # The deterministic slot filename makes concurrent duplicate publication fail atomically.
    path = Path(study) / "attempts" / (digest(list(_slot(row))) + ".json")
    with (Path(study) / "append.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing_ids = {load_json(p)["attempt_id"] for p in path.parent.glob("*.json")}
        _require(row["attempt_id"] not in existing_ids, "attempt ID already published")
        _write_new(path, row)
    return path


def _matches(check: dict[str, Any], artifacts: dict[str, Any], root: str | Path) -> bool:
    if check["role"] not in artifacts:
        return False
    data = read_verified_ref(artifacts[check["role"]], root)
    try:
        value = _json_bytes(data)
    except (ValueError, UnicodeError):
        if check["role"] == "response":
            return False
        raise
    try:
        for part in check["pointer"].split("/")[1:]:
            key = part.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                _require(key.isdecimal(), "array pointer must be a nonnegative integer")
                value = value[int(key)]
            else:
                value = value[key]
    except (KeyError, IndexError, TypeError):
        return False
    return canonical_bytes(value) == canonical_bytes(check["equals"])


def _result_artifacts(row: dict[str, Any], root: str | Path) -> dict[str, Any]:
    """Response is candidate-authored; all other roles require independent collection."""
    _artifact_map(row["artifacts"], root)
    _require("response" not in row["artifacts"], "response is reserved for the original output")
    _require(all(ref["sha256"] != row["output"]["sha256"] for ref in row["artifacts"].values()),
             "model output is not an independent owner artifact")
    return {**row["artifacts"], "response": row["output"]}


def judge_result(case: dict[str, Any], row: dict[str, Any], root: str | Path) -> dict[str, Any]:
    """Match explicit response/owner predicates; a response never supplies hard events."""
    _validate_adjudications(row, root)
    verify_ref(row["output"], root)
    artifacts = _result_artifacts(row, root)
    oracle = case["oracle"]
    global_hard = [{"role": "owner", "pointer": f"/hard_events/{event}", "equals": True}
                   for event in HARD_EVENTS]
    hard = [c for c in oracle["prohibited_events"] + global_hard if _matches(c, artifacts, root)]
    hard_evidence = [{**c, "equals": False} for c in global_hard]
    checks = hard_evidence + oracle["required_support"] + oracle["required_counterevidence"]
    missing = [c for c in checks if not _matches(c, artifacts, root)]
    solution = any(all(_matches(c, artifacts, root) for c in option)
                   for option in oracle["acceptable_results"])
    decisions = [j["decision"] for j in row["adjudications"]]
    semantic = "not_required" if oracle["semantic_rubric"] is None else (
        "pass" if len(decisions) >= 2 and set(decisions) == {"pass"} else
        "fail" if len(decisions) >= 2 and set(decisions) == {"fail"} else "inconclusive")
    success = row["admission"] == "admitted" and row["status"] == "completed" and solution and not missing and not hard and semantic in ("pass", "not_required")
    return {"success": bool(success), "hard_violations": hard, "missing_evidence": missing,
            "acceptable_result": solution, "semantic": semantic, "adjudications": row["adjudications"]}


def validate_mutants(case: dict[str, Any], root: str | Path) -> list[dict[str, Any]]:
    """Execute negative evidence checks; this is engineering evidence, not capability proof."""
    validate_case(case, root)
    results = []
    oracle = case["oracle"]
    for mutant in oracle["mutants"]:
        check = mutant["expected_failed_check"]
        prohibited = check in oracle["prohibited_events"]
        known = prohibited or check in oracle["required_support"] + oracle["required_counterevidence"] or any(check in x for x in oracle["acceptable_results"])
        _require(known, "mutant check not owned by case oracle")
        matched = _matches(check, mutant["artifacts"], root)
        caught = matched if prohibited else not matched
        _require(caught, f"oracle failed to detect mutant: {mutant['mutation']}")
        results.append({"mutation": mutant["mutation"], "caught": caught})
    return results


def _incident_pair(left: dict[str, Any], right: dict[str, Any], protocol: dict[str, Any], root: str | Path) -> bool:
    incident = left["incident"]
    if incident is None or incident != right["incident"] or any(
            row["status"] == "unknown_failure" for row in (left, right)):
        return False
    registered = any(incident["code"] == rule["code"] and incident["authority"] == rule["independent_authority"]
                     for rule in protocol["exclusion_rules"])
    expected = {"incident_id": incident["id"], "code": incident["code"],
                "authority": incident["authority"], "study_id": protocol["study_id"],
                "case_id": left["case_id"], "rep": left["rep"],
                "arms": sorted([left["arm"], right["arm"]])}
    return registered and any(_load_ref(ref, root) == expected for ref in incident["evidence"])


def aggregate(protocol: dict[str, Any], catalog: list[dict[str, Any]], rows: list[dict[str, Any]], root: str | Path,
              *, registration: dict[str, Any] | None = None) -> dict[str, Any]:
    """Unsealed inputs are diagnostic only; default eligibility needs a verified seal."""
    if registration is not None:
        validate_registration(registration, root)
        payload = registration["payload"]
        _require(canonical_bytes(payload["protocol"]) == canonical_bytes(protocol), "registration protocol mismatch")
        _require(canonical_bytes(payload["catalog"]) == canonical_bytes(catalog), "registration catalog mismatch")
    coverage = validate_protocol(protocol, catalog, root)
    _list(rows, "results", nonempty=False)
    by_slot, attempts, ids = {}, [], set()
    cases = {c["case_id"]: c for c in catalog}
    seals = set()
    for row in rows:
        validate_result(row, protocol, catalog, root)
        if registration is not None:
            _require(row["registration_sha256"] == registration["sha256"], "result not bound to seal")
        key = _slot(row)
        _require(key not in by_slot and row["attempt_id"] not in ids, "duplicate attempt/slot; no result suppression")
        ids.add(row["attempt_id"])
        seals.add(row["registration_sha256"])
        judgment = judge_result(cases[row["case_id"]], row, root)
        entry = {"original": row, "judgment": judgment}
        by_slot[key] = entry
        attempts.append(entry)
    _require(len(seals) <= 1, "mixed preregistration seals")
    arms = {}
    for arm in ARMS:
        entries = [e for e in attempts if e["original"]["arm"] == arm]
        admitted = [e for e in entries if e["original"]["admission"] == "admitted"]
        numerator = sum(e["judgment"]["success"] for e in admitted)
        planned = sum(slot["arm"] == arm for slot in planned_slots(protocol, catalog))
        arms[arm] = {"planned": planned, "admitted": len(admitted), "success": numerator,
                     "delivery_rate": numerator / len(admitted) if admitted else None,
                     "missing_coverage": planned - len(admitted),
                     "statuses": dict(Counter(e["original"]["status"] for e in entries)),
                     "observations": dict(Counter(o["kind"] for e in entries for o in e["original"]["observations"]))}
    comparisons = []
    # Simultaneous two-sided intervals cover both improvement and regression decisions.
    correction = len(protocol["comparisons"]) * len(FAMILIES)
    for comparison in protocol["comparisons"]:
        for family in FAMILIES:
            selected = [c for c in catalog if c["split"] == comparison["split"] and c["family"] == family]
            clusters, excluded, missing, hard = defaultdict(list), [], [], False
            for case in selected:
                deltas = []
                for rep in range(1, protocol["repeats"] + 1):
                    left = by_slot.get((case["case_id"], comparison["baseline"], rep))
                    right = by_slot.get((case["case_id"], comparison["treatment"], rep))
                    if left is None or right is None or any(e["original"]["admission"] != "admitted" for e in (left, right)):
                        missing.append({"case_id": case["case_id"], "rep": rep})
                        continue
                    hard |= bool(right["judgment"]["hard_violations"])
                    if _incident_pair(left["original"], right["original"], protocol, root):
                        excluded.append({"case_id": case["case_id"], "rep": rep,
                                         "incident": left["original"]["incident"]})
                        continue
                    deltas.append(int(right["judgment"]["success"]) - int(left["judgment"]["success"]))
                if deltas:
                    clusters[case["lineage"]].append(sum(deltas) / len(deltas))
            values = [sum(v) / len(v) for v in clusters.values()]
            estimate = sum(values) / len(values) if values else None
            bound = None
            independent = protocol["uncertainty"]["independent_lineages_evidence"] is not None
            if values and independent and not missing:
                radius = math.sqrt(2 * math.log(2 * correction / 0.05) / len(values))
                bound = [max(-1.0, estimate - radius), min(1.0, estimate + radius)]
            conclusion = "inconclusive"
            if hard or (estimate is not None and estimate < 0):
                conclusion = "observed_regression"
            elif bound and coverage["complete"] and not excluded and bound[0] > 0:
                conclusion = "improvement_nonregression"
            comparisons.append({**comparison, "family": family, "independent_scenarios": len(values),
                                "scenario_deltas": dict(zip(clusters, values)), "delta": estimate,
                                "interval95_familywise": bound, "missing_pairs": missing,
                                "excluded_pairs": excluded, "hard_violation": hard, "conclusion": conclusion})
    default_rows = [c for c in comparisons if c["baseline"] == "A" and
                    c["treatment"] == protocol["default_candidate"] and c["split"] == "heldout"]
    admitted_default = (len(default_rows) == len(FAMILIES) and
                        all(c["conclusion"] == "improvement_nonregression" for c in default_rows) and
                        all(not c["missing_pairs"] and not c["excluded_pairs"] for c in default_rows))
    candidate_hard = any(e["original"]["arm"] == protocol["default_candidate"] and
                         e["judgment"]["hard_violations"] for e in attempts)
    candidate_protection_missing = any(
        e["original"]["arm"] == protocol["default_candidate"] and any(
            check["role"] == "owner" and check["pointer"].startswith("/hard_events/")
            for check in e["judgment"]["missing_evidence"]) for e in attempts)
    any_hard = any(e["judgment"]["hard_violations"] for e in attempts)
    return {"version": VERSION, "study_id": protocol["study_id"], "coverage": coverage,
            "arms": arms, "comparisons": comparisons, "attempts": attempts,
            "registration_sha256": registration["sha256"] if registration is not None else None,
            "status": {"engineering": "protocol_validated", "functional": "failed" if any_hard else "inconclusive",
                       "registration": "verified_local_seal" if registration is not None else "unbound_diagnostic",
                       "default": "eligible_pending_independent_review" if registration is not None and admitted_default and not candidate_hard and not candidate_protection_missing else "retain_previous",
                       "release": "not_assessed"}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "seal"):
        command = sub.add_parser(name)
        command.add_argument("--catalog", type=Path, required=True)
        command.add_argument("--protocol", type=Path, required=True)
        if name == "seal":
            command.add_argument("--studies", type=Path, required=True)
    candidate = sub.add_parser("candidate")
    candidate.add_argument("--case", type=Path, required=True)
    record = sub.add_parser("record")
    record.add_argument("--study", type=Path, required=True)
    record.add_argument("--result", type=Path, required=True)
    summary = sub.add_parser("aggregate")
    summary.add_argument("--study", type=Path, required=True)
    summary.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("validate", "seal"):
            protocol, catalog = load_json(args.protocol), load_json(args.catalog)
            if args.command == "validate":
                result = validate_protocol(protocol, catalog, args.root)
                result["mutants"] = {c["case_id"]: validate_mutants(c, args.root) for c in catalog}
            else:
                result = {"study": str(seal_preregistration(protocol, catalog, args.root, args.studies))}
        elif args.command == "candidate":
            result = candidate_view(load_json(args.case), args.root)
        elif args.command == "record":
            result = {"attempt": str(append_result(args.study, load_json(args.result), args.root))}
        else:
            registration = _registration(args.study, args.root)
            payload = registration["payload"]
            rows = [load_json(p) for p in sorted((args.study / "attempts").glob("*.json"))]
            result = aggregate(payload["protocol"], payload["catalog"], rows, args.root, registration=registration)
            _write_new(args.output, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
        return 0
    except (ValueError, OSError) as exc:
        print(f"capability-evaluation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
