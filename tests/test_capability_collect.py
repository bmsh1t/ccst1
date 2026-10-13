"""Real sandbox tests using local synthetic scripts, not model capability runs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_capability_evaluation_protocol import case, e

MODULE = Path(__file__).parent / "skill-validator" / "capability_collect.py"
sys.modules.setdefault("capability_evaluation", e)
spec = importlib.util.spec_from_file_location("capability_collect", MODULE)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def fixture(tmp_path, script):
    bank, programs, out = (tmp_path / name for name in ("bank", "programs", "collection"))
    bank.mkdir()
    programs.mkdir()
    candidate = case(bank)
    code = script.encode()
    (programs / "program.py").write_bytes(code)
    ref = {"path": "program.py", "sha256": hashlib.sha256(code).hexdigest()}
    return candidate, bank, ref, programs, out


def test_real_broker_isolates_bank_environment_and_records_reads(tmp_path, monkeypatch):
    # These paths are synthetic sentinels, never the real user HOME or configuration.
    sentinel = tmp_path / "not-public.txt"
    sentinel.write_text("hidden-answer-sentinel")
    monkeypatch.setenv("C0_TEST_INHERITED_TOKEN", "must-not-inherit")
    script = f'''
import json, os, pathlib, socket, sys
prompt = json.loads(input())
assert "family" not in prompt and "lineage" not in prompt and "split" not in prompt
assert prompt["case_id"] != "dev-one"
assert "C0_TEST_INHERITED_TOKEN" not in os.environ
assert not pathlib.Path({str(sentinel)!r}).exists()
assert not pathlib.Path("/root").exists()
assert os.environ["HOME"] == "/home/candidate"
try:
    socket.create_connection(("127.0.0.1", 9), timeout=.1)
except OSError:
    pass
else:
    raise AssertionError("unexpected network listener")
def call(i, method, params):
    print(json.dumps(dict(id=i, method=method, params=params)), flush=True)
    return json.loads(input())
listing = call(0, "list", {{}})
assert len(listing["result"]) == 1
material = call(1, "read", {{"resource": listing["result"][0]["id"]}})
assert json.loads(material["result"]["text"])["requests"] == ["/x?a=1", "/x?a=2"]
denied = call(2, "read", {{"resource": "../../oracle/truth.json"}})
assert denied["error"] == "unknown_resource"
call(3, "finish", {{"answer": {{"choice": "retain", "hard_events": {{"data_loss": False}}}}}})
'''
    args = fixture(tmp_path, script)
    report = c.collect(*args)
    assert report["status"] == "completed", report
    assert [r["kind"] for r in report["observations"]] == ["directory", "read", "result"]
    candidate, bank, _, _, out = args
    owner = e.load_json(out / report["artifacts"]["owner"]["path"])
    assert owner["hard_events"] == {}
    assert set(owner["unobserved_hard_events"]) == set(e.HARD_EVENTS)
    assert e.load_json(out / report["output"]["path"])["choice"] == "retain"
    previous = "0" * 64
    events = sorted((out / "events").glob("*.json"))
    for number, path in enumerate(events, 1):
        event = e.load_json(path)
        assert event["seq"] == number
        assert event["previous"] == previous
        previous = hashlib.sha256(path.read_bytes()).hexdigest()
    assert owner["trace_head"] == previous
    # Neither a candidate claim nor the broker report supplies domain-owner hard gates.
    result = {"adjudications": [], "actor": "script", "output": report["output"],
              "artifacts": report["artifacts"], "admission": report["admission"], "status": report["status"]}
    judged = e.judge_result(candidate, result, out)
    assert not judged["success"]
    assert len([check for check in judged["missing_evidence"] if check["pointer"].startswith("/hard_events/")]) == 6
    original = (out / "collection.json").read_bytes()
    with pytest.raises(ValueError, match="new absolute"):
        c.collect(*args)
    assert (out / "collection.json").read_bytes() == original
    assert sentinel.read_text() == "hidden-answer-sentinel"
    assert len(list((bank / "oracles").iterdir())) == 1


@pytest.mark.parametrize("script,status", [
    ('import time; input(); time.sleep(10)', "timeout"),
    ('import sys; input(); sys.exit(7)', "tool_failure"),
    ('input(); print("not-json", flush=True)', "protocol_failure"),
    ('input(); print("x" * 5000, flush=True)', "protocol_failure"),
    ('input(); print(\'{"id":1,"method":"finish","params":{"answer":{}}}\', flush=True); '
     'input(); print(\'{"id":2,"method":"finish","params":{"answer":{}}}\', flush=True)', "protocol_failure"),
])
def test_timeout_failure_malformed_oversize_and_double_finish_preserved(tmp_path, script, status):
    args = fixture(tmp_path, script)
    result = c.collect(*args, timeout=0.3, limit_bytes=1024)
    assert result["admission"] == "admitted"
    assert result["status"] == status, result
    assert e.verify_ref(result["output"], args[-1]).exists()
    assert (args[-1] / "stdout.bin").exists()
    assert (args[-1] / "stderr.bin").exists()
    assert e.load_json(args[-1] / "collection.json")["status"] == status


def test_missing_sandbox_never_runs_unisolated(tmp_path, monkeypatch):
    args = fixture(tmp_path, 'raise AssertionError("must never execute")')
    monkeypatch.setattr(c.shutil, "which", lambda *args, **kwargs: None)
    report = c.collect(*args)
    assert report["admission"] == "preflight"
    assert report["status"] == "preflight_not_run"
    assert not (args[-1] / "stdout.bin").exists()
    assert all(e.load_json(path)["kind"] != "admitted" for path in (args[-1] / "events").glob("*.json"))


def test_real_collector_cli(tmp_path):
    script = 'import json; input(); print(json.dumps({"id":1,"method":"finish","params":{"answer":{"ok":True}}}), flush=True); input()'
    candidate, bank, program, programs, out = fixture(tmp_path, script)
    (bank / "case.json").write_text(json.dumps(candidate))
    (programs / "ref.json").write_text(json.dumps(program))
    command = ["/usr/bin/python3", str(MODULE), "--case", str(bank / "case.json"), "--bank", str(bank),
               "--program", str(programs / "ref.json"), "--program-root", str(programs), "--out", str(out)]
    result = subprocess.run(command, capture_output=True, text=True, check=False,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "completed"
    repeated = subprocess.run(command, capture_output=True, text=True, check=False,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    assert repeated.returncode == 2


def test_hash_error_before_output_creation_and_no_answer_ever_in_prompt(tmp_path):
    args = fixture(tmp_path, "print('unused')")
    candidate, bank, program, programs, out = args
    program["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="hash mismatch"):
        c.collect(*args)
    assert not out.exists()
