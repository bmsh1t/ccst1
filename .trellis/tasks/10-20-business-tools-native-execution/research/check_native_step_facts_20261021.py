"""Isolated production-CLI checks for native step facts; never reads project tests."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[4]
START = time.monotonic()
ROOT = Path(tempfile.mkdtemp(prefix="ccst-native-step-check-"))
os.chmod(ROOT, 0o700)
PROJECT = ROOT / "project"
PROJECT.mkdir(mode=0o700)
GIT = ["git", "-c", f"safe.directory={SOURCE}"]
names = subprocess.run(
    [*GIT, "ls-files", "-z", "--", "tools", "memory", "knowledge/capabilities.yaml", "config.json"],
    cwd=SOURCE, capture_output=True, check=True,
).stdout.decode().split("\0")
for name in filter(None, names):
    if "tests" in Path(name).parts or not (SOURCE / name).is_file():
        continue
    path = PROJECT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SOURCE / name, path)
private_home = ROOT / "home"
private_home.mkdir(mode=0o700)
ENV = {"PATH": os.environ["PATH"], "HOME": str(private_home), "LANG": "C.UTF-8",
       "PYTHONPATH": str(PROJECT), "PYTHONDONTWRITEBYTECODE": "1"}
os.environ.clear()
os.environ.update(ENV)
os.chdir(PROJECT)
sys.path.insert(0, str(PROJECT))
sys.dont_write_bytecode = True
from tools.target_store import TargetStore, initialize_target_store
from tools import validation_runner as runner

COUNT = 0


def check(value, label):
    global COUNT
    assert value, label
    COUNT += 1


def cli(lane, args, evidence, code=0):
    input_file = ROOT / "input.json"
    input_file.write_text(json.dumps(evidence))
    result = subprocess.run(
        [sys.executable, str(PROJECT / "tools/validation_runner.py"), lane,
         "--repo-root", str(PROJECT), "--target", TARGET, "--evidence-json", str(input_file),
         *args, "--json"], cwd=PROJECT, env=ENV, capture_output=True, text=True, timeout=10,
    )
    check(result.returncode == code, f"{lane}: expected {code}, {result.stderr[-1500:]} {result.stdout[-700:]}")
    return json.loads(result.stdout) if code == 0 else result


def raw_inventory():
    return {str(p.relative_to(PROJECT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for directory in (PROJECT / "evidence", PROJECT / ".private") if directory.exists()
            for p in directory.rglob("*") if p.is_file()}


def reject(lane, args, evidence, diagnostic):
    before = store.binding(), raw_inventory()
    result = cli(lane, args, evidence, code=2)
    check(diagnostic in result.stderr, "specific refusal: " + diagnostic)
    check((store.binding(), raw_inventory()) == before, "refusal before attempt/material publication")


TARGET = "step-facts.invalid"
initialize_target_store(PROJECT, TARGET)
store = TargetStore(PROJECT, TARGET)


def finding(fid, method="POST"):
    endpoint = f"https://{TARGET}/{fid}"
    store.create_finding(command_id="create:" + fid, finding_id=fid, endpoint=endpoint, method=method,
                         family="authz", title="Synthetic " + fid, claim="Synthetic boundary", actor="fixture")
    return endpoint


def run(name, url, method="GET", **facts):
    directory = PROJECT / "evidence" / TARGET / "synthetic"
    directory.mkdir(parents=True, exist_ok=True)
    refs = {}
    for side in ("request", "response"):
        path = directory / (name + "." + side)
        path.write_text(f"SYNTHETIC {name} {side}\n")
        refs[side] = str(path.relative_to(PROJECT))
    return {"url": url, "method": method, "actor": "owner", "artifacts": refs, **facts}


endpoint = finding("mixed")
mixed = {"schema_version": 1, "source": "synthetic", "attempt_id": "mixed-original",
         "generated_at": "2001-01-01T12:00:00.123456+02:00", "result": "candidate", "subject_step": 1,
         "observed_difference": "Synthetic controlled mutation and read-back.", "runs": [
             run("baseline", f"https://{TARGET}/baseline", "POST", observed_at="2001-01-01T10:00:01.123456Z", state_changing=False),
             run("mutation", endpoint, "POST", observed_at="2001-01-01T10:00:02.654321Z", state_changing=True, redline_checked=True),
             run("readback", f"https://{TARGET}/readback", observed_at="2001-01-01T12:00:03+02:00", state_changing=False),
             run("unknown", f"https://{TARGET}/unknown", observed_at="2001-01-01T10:00:04Z", state_changing=None),
         ]}
args = ["--finding-id", "mixed", "--attempt-id", "mixed-original"]
summary = cli("record-evidence", args, mixed)
operation_id = summary["store_operation_id"]
execution = store.execution(operation_id)
rows = execution["observations"]
check(execution["attempt"]["started_at"] == "2001-01-01T10:00:00.123456+00:00", "original attempt start with offset and precision")
check([row["observed_at"] for row in rows] == ["2001-01-01T10:00:01.123456+00:00", "2001-01-01T10:00:02.654321+00:00", "2001-01-01T10:00:03+00:00", "2001-01-01T10:00:04+00:00"], "per-step normalized capture times")
check([row["state_changing"] for row in rows] == [0, 1, 0, None], "mixed step states including explicit null")
check([row["redline_checked"] for row in rows] == [0, 1, 0, 0], "per-step redline")
check(summary["state_changing"] is None and summary["redline_checked"] is False, "top-level facts remain defaults")
check(store.report_cleanup("mixed", require_verified=False)["pending_mutation_refs"] == [{"operation_id": operation_id, "step": 1}], "only actual mutation requires cleanup")
before = store.binding()
retry = cli("record-evidence", args, mixed)
check(retry["store_operation_id"] == operation_id and store.binding() == before, "CLI retry creates no new operation/attempt")
check(raw_inventory()[rows[1]["artifacts"][0]["ref"]] == rows[1]["artifacts"][0]["sha256"], "registered raw unchanged")

invalid_cases = [
    ("generated future", lambda e: e.update(generated_at="9999-01-01T00:00:00Z"), "cannot be in the future"),
    ("generated naive", lambda e: e.update(generated_at="2001-01-01T10:00:00"), "requires a timezone"),
    ("step future", lambda e: e["runs"][0].update(observed_at="9999-01-01T00:00:00Z"), "cannot be in the future"),
    ("step naive", lambda e: e["runs"][0].update(observed_at="2001-01-01T10:00:01"), "requires a timezone"),
    ("step before start", lambda e: e["runs"][0].update(observed_at="2001-01-01T10:00:00Z"), "predates its execution attempt"),
    ("state string", lambda e: e["runs"][0].update(state_changing="false"), "step facts must be boolean"),
    ("state number", lambda e: e["runs"][0].update(state_changing=1), "step facts must be boolean"),
    ("redline string", lambda e: e["runs"][0].update(redline_checked="true"), "step facts must be boolean"),
    ("mutation unchecked", lambda e: e["runs"][1].update(redline_checked=False), "requires --redline-checked"),
]
for index, (label, mutate, diagnostic) in enumerate(invalid_cases):
    evidence = copy.deepcopy(mixed)
    evidence["attempt_id"] = "rejected-" + str(index)
    mutate(evidence)
    reject("record-evidence", ["--finding-id", "mixed", "--attempt-id", evidence["attempt_id"]], evidence, diagnostic)

# Direct API callers also face the typed default-fact boundary.
for state, checked in ((1, True), (False, "true")):
    before = store.binding(), raw_inventory()
    try:
        runner.record_native_evidence(repo_root=PROJECT, target=TARGET, finding_id="mixed", evidence=mixed,
                                      state_changing=state, redline_checked=checked)
    except ValueError as exc:
        check("execution facts must be boolean" in str(exc), "API defaults typed")
    else:
        raise AssertionError("invalid API defaults accepted")
    check((store.binding(), raw_inventory()) == before, "invalid API defaults have no publication")

cleanup = {"schema_version": 1, "source": "synthetic", "attempt_id": "cleanup-original",
           "generated_at": "2001-01-01T10:00:00Z", "result": "candidate",
           "observed_difference": "Synthetic final read-back verifies the original baseline.",
           "cleanup_confirmation": {"status": "verified", "mutation_refs": [{"operation_id": operation_id, "step": 1}],
                                    "restored_state": "Synthetic baseline restored", "verification_basis": "Synthetic raw read-back"},
           "runs": [run("cleanup", f"https://{TARGET}/cleanup", observed_at="2001-01-01T10:00:05.987654Z", state_changing=False)]}
cleanup_args = ["--finding-id", "mixed", "--attempt-id", "cleanup-original", "--no-state-changing"]
for facts, diagnostic in (({"state_changing": True, "redline_checked": True}, "explicitly read-only"),
                          ({"state_changing": None}, "explicitly read-only"),
                          ({"observed_at": "2001-01-01T10:00:01Z"}, "must not predate its mutation")):
    evidence = copy.deepcopy(cleanup)
    evidence["runs"][0].update(facts)
    reject("record-evidence", cleanup_args, evidence, diagnostic)
clean_summary = cli("record-evidence", cleanup_args, cleanup)
check(store.report_cleanup("mixed")["status"] == "verified", "cleanup uses step time later than mutation although attempt start is earlier")
clean_row = store.execution(clean_summary["store_operation_id"])["observations"][0]
check(clean_row["observed_at"] == "2001-01-01T10:00:05.987654+00:00" and clean_row["state_changing"] == 0, "cleanup step facts persisted")
before = store.binding()
check(cli("record-evidence", cleanup_args, cleanup)["store_operation_id"] == clean_summary["store_operation_id"] and store.binding() == before, "cleanup original-attempt retry")

# Run the real prior implementation against the same isolated Store, then replay
# omitted-field material through the new implementation without a new identity.
old_path = PROJECT / "legacy_runner.py"
old_path.write_bytes(subprocess.run([*GIT, "show", "67eb3ed:tools/validation_runner.py"], cwd=SOURCE, capture_output=True, check=True).stdout)
spec = importlib.util.spec_from_file_location("legacy_runner", old_path)
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
legacy_endpoint = finding("legacy", method="GET")
legacy_evidence = {"schema_version": 1, "source": "synthetic", "attempt_id": "legacy-original", "generated_at": "2001-01-01T10:01:00.123456Z",
                   "result": "candidate", "observed_difference": "Synthetic historical single-time material.",
                   "runs": [run("legacy", legacy_endpoint, state_changing=False)]}
legacy_evidence["runs"][0].pop("state_changing")
old_summary = legacy.record_native_evidence(repo_root=PROJECT, target=TARGET, finding_id="legacy", evidence=legacy_evidence, state_changing=False)
old_summary["sync"] = legacy.sync_runner_artifacts(old_summary, repo_root=PROJECT)
check(old_summary["sync"]["status"] == "updated", "prior production implementation actually registered")
before = store.binding()
new_summary = cli("record-evidence", ["--finding-id", "legacy", "--attempt-id", "legacy-original", "--no-state-changing"], legacy_evidence)
check(new_summary["summary_path"] == old_summary["summary_path"] and new_summary["operation_id"] == old_summary["operation_id"], "omitted step fields retain historical material identity")
check(new_summary["store_operation_id"] == old_summary["sync"]["store"]["operation_id"] and store.binding() == before, "historical material replay keeps Store operation")
check(not {"observed_at", "state_changing", "redline_checked"} & new_summary["runs"][0].keys(), "no invented step fields")
legacy_row = store.execution(new_summary["store_operation_id"])["observations"][0]
check(legacy_row["observed_at"] == new_summary["generated_at"] and legacy_row["state_changing"] == 0, "legacy single-time defaults")

pair_endpoint = finding("pair", method="GET")
pair_run = {"baseline_url": pair_endpoint, "variant_url": pair_endpoint,
            "observed_at": "2001-01-01T10:03:00Z", "state_changing": True, "redline_checked": True, "artifacts": {}}
for side in ("baseline", "variant"):
    actual = run("pair-" + side, pair_endpoint)
    pair_run["artifacts"].update({side + "_" + kind: ref for kind, ref in actual["artifacts"].items()})
    identity = PROJECT / "evidence" / TARGET / (side + "-identity.json")
    identity.write_text(json.dumps({"requested_url": pair_endpoint}))
    pair_run["artifacts"][side + "_identity"] = str(identity.relative_to(PROJECT))
    obs = runner._store_observation(pair_run, repo_root=PROJECT, side=side, method="GET", family="authz",
                                    observed_at="2001-01-01T10:02:00Z", result="candidate", incomplete=False,
                                    state_changing=False, redline_checked=False)
    check(obs["observed_at"] == "2001-01-01T10:02:00Z" and obs["state_changing"] is False and obs["redline_checked"] is False,
          "historical " + side + " ignores new step overrides")

observation_run = run("no-finding", f"https://{TARGET}/observation", observed_at="9999-01-01T00:00:00Z", description="Synthetic observation")
observation = {"schema_version": 1, "kind": "native-observation", "source": "synthetic", "started_at": "2001-01-01T10:00:00Z", "outcome": "complete", "runs": [observation_run]}
reject("record-observation", ["--attempt-id", "observation-future"], observation, "cannot be in the future")
observation["runs"][0]["observed_at"] = "2001-01-01T10:00:01Z"
observation["started_at"] = "9999-01-01T00:00:00Z"
reject("record-observation", ["--attempt-id", "observation-start-future"], observation, "cannot be in the future")
observation["started_at"] = "2001-01-01T10:00:00Z"
no_finding = cli("record-observation", ["--attempt-id", "observation-original"], observation)
check(store.execution(no_finding["store_operation_id"])["observations"][0]["observed_at"] == "2001-01-01T10:00:01+00:00", "no-verdict lane capture time retained")
with sqlite3.connect(store.path) as connection:
    check(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and not connection.execute("PRAGMA foreign_key_check").fetchall(), "temporary Store integrity/FK")
    check(connection.execute("SELECT count(*) FROM attempts WHERE id LIKE 'rejected-%'").fetchone()[0] == 0, "rejected inputs created no attempts")
ast.parse((PROJECT / "tools/validation_runner.py").read_text())
check(True, "production Python syntax")
result = {"assertions": COUNT, "seconds": round(time.monotonic() - START, 3), "root": str(ROOT), "source_baseline": "67eb3ed", "project_tests": "not_read_or_run"}
(ROOT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
