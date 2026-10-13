"""Synthetic contract tests; these are not the study's capability case catalog."""
import copy
import hashlib
import importlib.util
import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

MODULE = Path(__file__).parent / "skill-validator" / "capability_evaluation.py"
spec = importlib.util.spec_from_file_location("capability_evaluation", MODULE)
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)


def ref(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def case(root, name="dev-one", family="recovery", split="dev"):
    material = ref(root, f"materials/{name}.json", {"fixture": name, "requests": ["/x?a=1", "/x?a=2"]})
    truth = ref(root, f"oracles/{name}.json", {"current_intent": "new", "original_requests_distinct": True})
    mutant = ref(root, f"mutants/{name}.json", {"current_intent": "old"})
    check = {"role": "owner", "pointer": "/current_intent", "equals": "new"}
    return {"version": e.VERSION, "case_id": name, "family": family, "split": split,
            "lineage": name, "candidate": {"question": "Recover current work from the owner.",
            "allowed_actions": ["read owner"], "materials": [material], "initial_state": material},
            "oracle": {"sources": [truth], "acceptable_results": [[check]], "required_support": [check],
            "required_counterevidence": [], "prohibited_events": [{"role": "owner", "pointer": "/replayed", "equals": True}],
            "mutants": [{"mutation": "restore obsolete intent", "artifacts": {"owner": mutant},
                         "expected_failed_check": check, "source": truth}], "semantic_rubric": None}}


def protocol(root, catalog, repeats=6):
    binding = ref(root, "bindings.json", {"synthetic_test_binding": True})
    pairs = [("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "F"), ("A", "K"),
             ("B", "B_no_content"), ("B", "B_old_organization"), ("B", "B_no_whitebox_entry")]
    return {"version": e.VERSION, "study_id": "synthetic-contract-test", "catalog_sha256": e.digest(catalog),
            "arms": {arm: {key: binding for key in e.BINDINGS} for arm in e.ARMS}, "repeats": repeats,
            "comparisons": [{"baseline": a, "treatment": b, "split": "dev"} for a, b in pairs] +
                           [{"baseline": "A", "treatment": "B", "split": "heldout"}],
            "uncertainty": {"method": "stratified_sign_flip_permutation", "alpha": 0.05,
                            "independent_lineages_evidence": binding},
            "exclusion_rules": [{"code": "lab_outage", "reason": "independent fixture service interruption",
                                 "independent_authority": "lab-monitor"}],
            "stop_rule": "fixed_schedule_no_replacement", "default_candidate": "B"}


def row(root, c, arm, rep, status="completed"):
    output = ref(root, f"outputs/{c['case_id']}-{arm}-{rep}.json", {"text": "validated"})
    owner = ref(root, f"owners/{c['case_id']}-{arm}-{rep}.json",
                {"current_intent": "new", "hard_events": {name: False for name in e.HARD_EVENTS}})
    return {"version": e.VERSION, "study_id": "synthetic-contract-test", "registration_sha256": "a" * 64,
            "attempt_id": f"{c['case_id']}-{arm}-{rep}", "case_id": c["case_id"], "arm": arm, "rep": rep,
            "admission": "preflight" if status == "preflight_not_run" else "admitted", "status": status,
            "actor": "candidate-model", "output": output, "artifacts": {"owner": owner},
            "observations": [{"kind": "directory", "source": output}], "adjudications": [], "incident": None}


def test_partial_catalog_and_candidate_no_answers(tmp_path):
    c = case(tmp_path)
    p = protocol(tmp_path, [c])
    assert e.validate_protocol(p, [c], tmp_path)["complete"] is False
    assert set(e.candidate_view(c, tmp_path)) == {"case_id", "question", "allowed_actions", "materials", "initial_state"}
    assert e.validate_mutants(c, tmp_path)[0]["caught"]
    with pytest.raises(ValueError, match="coverage"):
        e.seal_preregistration(p, [c], tmp_path, tmp_path / "studies")
    c["candidate"]["materials"] = c["oracle"]["sources"]
    with pytest.raises(ValueError, match="exposed"):
        e.validate_case(c, tmp_path)


def test_lineage_and_renamed_fixture_leakage(tmp_path):
    first = case(tmp_path)
    second = case(tmp_path, "heldout-two", split="heldout")
    second["lineage"] = first["lineage"]
    with pytest.raises(ValueError, match="lineage crosses"):
        e.validate_catalog([first, second], tmp_path)
    second["lineage"] = "other"
    second["candidate"] = copy.deepcopy(first["candidate"])
    with pytest.raises(ValueError, match="renamed"):
        e.validate_catalog([first, second], tmp_path)


def test_eight_success_four_timeouts_remain_twelve(tmp_path):
    catalog = [case(tmp_path), case(tmp_path, "dev-two")]
    p = protocol(tmp_path, catalog)
    rows = [row(tmp_path, c, "B", rep, "completed" if rep <= 4 else "timeout")
            for c in catalog for rep in range(1, 7)]
    summary = e.aggregate(p, catalog, rows, tmp_path)
    assert summary["arms"]["B"]["success"] == 8
    assert summary["arms"]["B"]["admitted"] == 12
    assert summary["arms"]["B"]["delivery_rate"] == 8 / 12
    assert len(summary["attempts"]) == 12
    assert summary["arms"]["B"]["observations"] == {"directory": 12}
    assert summary["status"]["default"] == "retain_previous"


def _fail_owner(root, name):
    return ref(root, f"fail-owners/{name}.json",
               {"current_intent": "old", "hard_events": {event: False for event in e.HARD_EVENTS}})


def test_primary_exact_permutation_matches_brute_force(tmp_path):
    deltas = {("recovery", "held-r1"): 2, ("recovery", "held-r2"): -1,
              ("semantic", "held-s1"): 1, ("semantic", "held-s2"): 1}
    catalog = [case(tmp_path, name, family, "heldout") for family, name in deltas]
    p = protocol(tmp_path, catalog, repeats=5)
    rows = []
    for c in catalog:
        d = deltas[(c["family"], c["case_id"])]
        for rep in range(1, 6):
            for arm in ("A", "B"):
                r = row(tmp_path, c, arm, rep)
                if (arm == "A" and d > rep - 1) or (arm == "B" and -d > rep - 1):
                    r["artifacts"]["owner"] = _fail_owner(tmp_path, f"{c['case_id']}-{arm}-{rep}")
                rows.append(r)
    primary = e.aggregate(p, catalog, rows, tmp_path)["primary"]
    assert (primary["S_obs"], primary["N"]) == (3, 4)
    brute = sum(1 for signs in itertools.product((1, -1), repeat=4)
                if sum(s * d for s, d in zip(signs, deltas.values())) >= 3)
    assert primary["p_exact"] == [brute, 16]
    assert primary["p_value"] == brute / 16
    assert primary["conclusion"] == "inconclusive"  # p = 0.25


def test_primary_lineage_level_exclusion(tmp_path):
    clean = case(tmp_path, "held-clean", "recovery", "heldout")
    outage = case(tmp_path, "held-outage", "recovery", "heldout")
    partial = case(tmp_path, "held-partial", "recovery", "heldout")
    catalog = [clean, outage, partial]
    p = protocol(tmp_path, catalog, repeats=5)
    rows = []
    for rep in range(1, 6):
        a = row(tmp_path, clean, "A", rep)
        a["artifacts"]["owner"] = _fail_owner(tmp_path, f"clean-A-{rep}")
        rows += [a, row(tmp_path, clean, "B", rep)]
        if rep != 2:
            rows += [row(tmp_path, partial, arm, rep) for arm in ("A", "B")]
        left = row(tmp_path, outage, "A", rep, "tool_failure")
        right = row(tmp_path, outage, "B", rep, "tool_failure")
        if rep == 3:
            incident = {"id": "outage-two", "code": "lab_outage", "authority": "lab-monitor",
                        "evidence": [ref(tmp_path, "outage.json", {"incident_id": "outage-two", "code": "lab_outage",
                          "authority": "lab-monitor", "study_id": p["study_id"], "case_id": outage["case_id"],
                          "rep": 3, "arms": ["A", "B"]})]}
            left["incident"] = right["incident"] = incident
        rows += [left, right]
    summary = e.aggregate(p, catalog, rows, tmp_path)
    family = next(f for f in summary["primary"]["families"] if f["family"] == "recovery")
    assert family["lineages_included"] == 1
    by_lineage = {x["lineage"]: x for x in family["excluded_lineages"]}
    assert by_lineage["held-partial"]["missing_pairs"] == [{"case_id": "held-partial", "rep": 2}]
    assert len(by_lineage["held-outage"]["excluded_pairs"]) == 1
    primary = summary["primary"]
    assert (primary["N"], primary["S_obs"], primary["p_exact"]) == (1, 5, [1, 2])
    assert primary["conclusion"] == "inconclusive"  # p = 0.5
    p["uncertainty"]["independent_lineages_evidence"] = None
    degraded = e.aggregate(p, catalog, rows, tmp_path)
    assert degraded["primary"]["p_value"] is None
    assert degraded["status"]["default"] == "retain_previous"


def test_descriptive_wilson_intervals(tmp_path):
    c = case(tmp_path, "dev-w")
    p = protocol(tmp_path, [c], repeats=5)
    rows = []
    for rep in range(1, 6):
        rows.append(row(tmp_path, c, "B", rep))
        a = row(tmp_path, c, "A", rep)
        if rep > 3:  # baseline fails two of five
            a["artifacts"]["owner"] = _fail_owner(tmp_path, f"w-A-{rep}")
        rows.append(a)
    result = e.aggregate(p, [c], rows, tmp_path)["comparisons"][3]
    assert result["inferential"] is False
    assert result["conclusion"] == "descriptive_not_inferential"
    assert (result["baseline"]["successes"], result["baseline"]["admitted"]) == (3, 5)
    assert result["baseline"]["rate"] == 0.6
    assert result["baseline"]["wilson95"] == pytest.approx([0.230724281276, 0.882379225767], abs=1e-9)
    assert (result["treatment"]["successes"], result["treatment"]["admitted"]) == (5, 5)
    assert result["treatment"]["rate"] == 1.0
    assert result["treatment"]["wilson95"] == pytest.approx([0.565517535217, 1.0], abs=1e-9)
    assert result["delta"] == pytest.approx(0.4)


def test_v1_uncertainty_method_rejected(tmp_path):
    c = case(tmp_path)
    p = protocol(tmp_path, [c])
    p["uncertainty"]["method"] = "paired_hoeffding_bonferroni"
    with pytest.raises(ValueError, match="unsupported uncertainty method"):
        e.validate_protocol(p, [c], tmp_path)


def test_preflight_unknown_and_pair_symmetric_exclusion(tmp_path):
    c = case(tmp_path)
    p = protocol(tmp_path, [c])
    left, right = row(tmp_path, c, "A", 1), row(tmp_path, c, "B", 1, "unknown_failure")
    incident = {"id": "outage-one", "code": "lab_outage", "authority": "lab-monitor",
                "evidence": [ref(tmp_path, "outage.json", {"incident_id": "outage-one", "code": "lab_outage", "authority": "lab-monitor",
                  "study_id": p["study_id"], "case_id": c["case_id"], "rep": 1, "arms": ["A", "B"]})]}
    right["incident"] = incident
    result = e.aggregate(p, [c], [left, right], tmp_path)["comparisons"][3]
    assert not result["excluded_pairs"]
    assert result["delta"] == -1
    left["incident"] = incident
    unknown = e.aggregate(p, [c], [left, right], tmp_path)
    assert not unknown["comparisons"][3]["excluded_pairs"]
    right["status"] = "tool_failure"
    result = e.aggregate(p, [c], [left, right], tmp_path)
    assert len(result["comparisons"][3]["excluded_pairs"]) == 1
    assert result["arms"]["B"]["admitted"] == 1
    preflight = row(tmp_path, c, "B", 2, "preflight_not_run")
    result = e.aggregate(p, [c], [left, right, preflight], tmp_path)
    assert result["arms"]["B"]["admitted"] == 1
    assert result["arms"]["B"]["missing_coverage"] == 5


def test_owner_truth_hard_gates_and_independent_semantics(tmp_path):
    c = case(tmp_path)
    p = protocol(tmp_path, [c])
    r = row(tmp_path, c, "B", 1)
    r["artifacts"] = {}
    assert not e.judge_result(c, r, tmp_path)["success"]
    r = row(tmp_path, c, "B", 1)
    c["oracle"]["semantic_rubric"] = ref(tmp_path, "rubric.json", {"evaluate": "current intent reasoning"})
    judgment = {"identity": "reviewer-one", "blinded": True, "decision": "pass",
                "sources": c["oracle"]["sources"], "rationale": "owner agrees"}
    r["adjudications"] = [judgment, {**judgment, "identity": "reviewer-two", "decision": "fail"}]
    assert e.judge_result(c, r, tmp_path)["semantic"] == "inconclusive"
    r["adjudications"][1]["decision"] = "pass"
    assert e.judge_result(c, r, tmp_path)["success"]
    r["adjudications"][0]["identity"] = r["actor"]
    with pytest.raises(ValueError, match="self-grading"):
        e.validate_result(r, p, [c], tmp_path)
    with pytest.raises(ValueError, match="self-grading"):
        e.judge_result(c, r, tmp_path)
    r["adjudications"][0]["identity"] = "reviewer-one"
    r["artifacts"]["owner"] = ref(tmp_path, "violating-owner.json", {"current_intent": "new",
                  "hard_events": {k: k == "unknown_effect_replay" for k in e.HARD_EVENTS}})
    assert e.judge_result(c, r, tmp_path)["hard_violations"]


def test_hash_drift_duplicate_json_bad_version(tmp_path):
    c = case(tmp_path)
    (tmp_path / c["candidate"]["initial_state"]["path"]).write_text("changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        e.validate_case(c, tmp_path)
    path = tmp_path / "bad.json"
    path.write_text('{"a":1,"a":2}')
    with pytest.raises(ValueError, match="duplicate JSON"):
        e.load_json(path)
    path.write_text('{"a":NaN}')
    with pytest.raises(ValueError, match="nonfinite"):
        e.load_json(path)


def test_complete_synthetic_schema_seals_and_never_replaces(tmp_path):
    catalog = [case(tmp_path, f"{family}-{split}-{i}", family, split) for family in e.FAMILIES
               for split, count in (("dev", 8), ("heldout", 12)) for i in range(count)]
    p = protocol(tmp_path, catalog, repeats=5)
    study = e.seal_preregistration(p, catalog, tmp_path, tmp_path / "studies")
    original = (study / "registration.json").read_bytes()
    with pytest.raises(FileExistsError):
        e.seal_preregistration(p, catalog, tmp_path, tmp_path / "studies")
    r = row(tmp_path, catalog[0], "A", 1)
    r["registration_sha256"] = e.load_json(study / "registration.json")["sha256"]
    result_path = e.append_result(study, r, tmp_path)
    saved = result_path.read_bytes()
    with pytest.raises(ValueError, match="already published"):
        e.append_result(study, r, tmp_path)
    assert result_path.read_bytes() == saved
    assert (study / "registration.json").read_bytes() == original


def test_real_cli_draft_validation(tmp_path):
    c = case(tmp_path)
    p = protocol(tmp_path, [c])
    catalog = tmp_path / "catalog.json"
    protocol_path = tmp_path / "protocol.json"
    catalog.write_text(json.dumps([c]))
    protocol_path.write_text(json.dumps(p))
    completed = subprocess.run([sys.executable, str(MODULE), "--root", str(tmp_path), "validate",
                               "--catalog", str(catalog), "--protocol", str(protocol_path)],
                              capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["complete"] is False
    protocol_path.write_text('{"broken":true}')
    failed = subprocess.run([sys.executable, str(MODULE), "--root", str(tmp_path), "validate",
                            "--catalog", str(catalog), "--protocol", str(protocol_path)], capture_output=True, text=True)
    assert failed.returncode == 2


@pytest.mark.parametrize('name', ['nested/config.json', 'nested/.env', 'nested/.env.local', '../outside.json', 'a//b.json'])
def test_private_and_noncanonical_refs_rejected_before_read(tmp_path, monkeypatch, name):
    def no_open(*args, **kwargs):
        pytest.fail('rejected path reached filesystem open')
    monkeypatch.setattr(e.os, 'open', no_open)
    with pytest.raises(ValueError):
        e.verify_ref({'path': name, 'sha256': 'a' * 64}, tmp_path)


def test_ref_symlink_ancestor_and_hash_reopen_rejected(tmp_path, monkeypatch):
    c = case(tmp_path)
    r = row(tmp_path, c, 'B', 1)
    alias = tmp_path / 'alias'
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        e.verify_ref(r['output'], alias)
    def no_reopen(*args, **kwargs):
        pytest.fail('checked artifact was reopened by pathname')
    monkeypatch.setattr(e, 'load_json', no_reopen)
    assert e.judge_result(c, r, tmp_path)['success']


def test_direct_judging_rejects_self_reported_owner(tmp_path):
    c = case(tmp_path)
    r = row(tmp_path, c, 'B', 1)
    r['output'] = r['artifacts']['owner']
    with pytest.raises(ValueError, match='independent owner'):
        e.judge_result(c, r, tmp_path)


def test_development_registration_does_not_unlock_heldout(tmp_path):
    catalog = [case(tmp_path), case(tmp_path, 'hidden', split='heldout')]
    p = protocol(tmp_path, catalog)
    p['default_candidate'] = None
    p['comparisons'] = [c for c in p['comparisons'] if c['split'] == 'dev']
    e.validate_protocol(p, catalog, tmp_path)
    slots = e.planned_slots(p, catalog)
    assert {slot['case_id'] for slot in slots} == {'dev-one'}
    with pytest.raises(ValueError, match='unplanned slot'):
        e.validate_result(row(tmp_path, catalog[1], 'B', 1), p, catalog, tmp_path)
    p['default_candidate'] = 'B'
    p['comparisons'].append({'baseline': 'A', 'treatment': 'B', 'split': 'heldout'})
    e.validate_protocol(p, catalog, tmp_path)
    assert {slot['arm'] for slot in e.planned_slots(p, catalog) if slot['case_id'] == 'hidden'} == {'A', 'B'}


def test_bad_baseline_does_not_invert_repair_into_regression(tmp_path):
    c = case(tmp_path)
    p = protocol(tmp_path, [c])
    left, right = row(tmp_path, c, 'A', 1), row(tmp_path, c, 'B', 1)
    left['artifacts']['owner'] = ref(tmp_path, 'bad-baseline.json', {'current_intent': 'old',
        'hard_events': {name: name == 'unknown_effect_replay' for name in e.HARD_EVENTS}})
    result = e.aggregate(p, [c], [left, right], tmp_path)
    assert result['comparisons'][3]['delta'] == 1
    assert result['comparisons'][3]['hard_violation'] is False
    assert result['status']['functional'] == 'failed'
    assert result['attempts'][0]['judgment']['hard_violations']


def test_catalog_blocks_cross_case_answer_leak_and_duplicate_ref_lineages(tmp_path):
    first = case(tmp_path)
    second = case(tmp_path, 'heldout-two', split='heldout')
    first['oracle']['sources'] = [ref(tmp_path, 'unique-answer.json', {'answer': 'first-only'})]
    second['candidate']['materials'].append(first['oracle']['sources'][0])
    with pytest.raises(ValueError, match='catalog oracle'):
        e.validate_catalog([first, second], tmp_path)
    second['candidate'] = copy.deepcopy(first['candidate'])
    second['candidate']['materials'] *= 2
    with pytest.raises(ValueError, match='renamed'):
        e.validate_catalog([first, second], tmp_path)


def envelope(p, catalog):
    payload = {"version": e.VERSION, "protocol": p, "catalog": catalog,
               "slots": e.planned_slots(p, catalog), "sealed_at": "2026-10-11T20:00:00+00:00"}
    return {"payload": payload, "sha256": e.digest(payload)}


def test_public_aggregate_binds_registration_and_unsealed_cannot_qualify(tmp_path):
    # Deliberately synthetic independent labels only exercise the statistical/API gate.
    catalog = [case(tmp_path, f"{family}-{split}-{i}", family, split) for family in e.FAMILIES
               for split, count in (("dev", 8), ("heldout", 20)) for i in range(count)]
    p = protocol(tmp_path, catalog, repeats=5)
    seal = envelope(p, catalog)
    templates = {arm: row(tmp_path, catalog[0], arm, 1) for arm in ("A", "B")}
    templates["A"]["artifacts"]["owner"] = ref(tmp_path, "owners/baseline-miss.json",
        {"current_intent": "old", "hard_events": {name: False for name in e.HARD_EVENTS}})
    rows = [{**templates[arm], "case_id": c["case_id"], "arm": arm, "rep": rep,
             "attempt_id": f"{c['case_id']}-{arm}-{rep}", "registration_sha256": seal["sha256"]}
            for c in catalog if c["split"] == "heldout" for arm in ("A", "B") for rep in range(1, 6)]
    unbound = e.aggregate(p, catalog, rows, tmp_path)
    assert unbound["status"]["registration"] == "unbound_diagnostic"
    assert unbound["status"]["default"] == "retain_previous"
    bound = e.aggregate(p, catalog, rows, tmp_path, registration=seal)
    assert bound["status"]["default"] == "eligible_pending_independent_review"
    assert bound["registration_sha256"] == seal["sha256"]
    assert bound["primary"]["N"] == 160
    assert bound["primary"]["S_obs"] == 800
    assert bound["primary"]["p_exact"] == [1, 2 ** 160]
    assert bound["primary"]["conclusion"] == "candidate_better"
    with pytest.raises(ValueError, match="seal mismatch"):
        e.aggregate(p, catalog, [], tmp_path, registration={**seal, "sha256": "0" * 64})
    changed = copy.deepcopy(p)
    changed["repeats"] += 1
    with pytest.raises(ValueError, match="protocol mismatch"):
        e.aggregate(changed, catalog, [], tmp_path, registration=seal)
    with pytest.raises(ValueError, match="catalog mismatch"):
        e.aggregate(p, list(reversed(catalog)), [], tmp_path, registration=seal)
    bad_schedule = copy.deepcopy(seal)
    bad_schedule["payload"]["slots"].pop()
    bad_schedule["sha256"] = e.digest(bad_schedule["payload"])
    with pytest.raises(ValueError, match="schedule mismatch"):
        e.aggregate(p, catalog, [], tmp_path, registration=bad_schedule)
    rows[0]["registration_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="not bound to seal"):
        e.aggregate(p, catalog, rows[:1], tmp_path, registration=seal)


def test_response_is_not_owner_and_malformed_answer_remains_failure(tmp_path):
    c = case(tmp_path)
    check = {"role": "response", "pointer": "/choice", "equals": "retain"}
    c["oracle"]["acceptable_results"] = [[check]]
    r = row(tmp_path, c, "B", 1)
    r["output"] = ref(tmp_path, "response.json", {"choice": "retain",
        "hard_events": {event: False for event in e.HARD_EVENTS}})
    assert e.judge_result(c, r, tmp_path)["success"]
    r["artifacts"]["owner"] = ref(tmp_path, "owner-unobserved.json", {"current_intent": "new"})
    judged = e.judge_result(c, r, tmp_path)
    assert not judged["success"]
    assert len(judged["missing_evidence"]) == len(e.HARD_EVENTS)
    r["artifacts"]["response"] = ref(tmp_path, "replacement.json", {"choice": "retain"})
    with pytest.raises(ValueError, match="response is reserved"):
        e.judge_result(c, r, tmp_path)
    del r["artifacts"]["response"]
    data = b'{"choice":"retain","choice":"retain"}'
    (tmp_path / "malformed.json").write_bytes(data)
    r["output"] = {"path": "malformed.json", "sha256": hashlib.sha256(data).hexdigest()}
    summary = e.aggregate(protocol(tmp_path, [c]), [c], [r], tmp_path)
    assert summary["arms"]["B"]["admitted"] == 1
    assert summary["arms"]["B"]["success"] == 0
    assert summary["attempts"][0]["judgment"]["acceptable_result"] is False
