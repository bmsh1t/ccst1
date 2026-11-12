"""FFUF wordlist transport and control failures across the real shell/adapter seam."""

import gzip
import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools.recon_adapter import ReconAdapter
from tools.recon_target_selector import select_targets


REPO = Path(__file__).resolve().parents[1]
TARGET = "ffuf.test:8080"
URL = f"http://{TARGET}"


def _row(url=URL + "/missing", status=404, length=4):
    return {"url": url, "status": status, "length": length, "words": 1, "lines": 1}


def _jsonl(rows):
    return "".join(json.dumps(row) + "\n" for row in rows)


def _env(root):
    return {
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), os.defpath]),
        "HOME": str(root), "XDG_CONFIG_HOME": str(root / "config"),
        "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
    }


@pytest.mark.parametrize("fault", ["", "duplicate", "missing", "mismatch", "base64", "boolean"])
def test_word_page_receipts_bind_every_position_and_input(tmp_path, fault):
    words = tmp_path / "words.txt"
    words.write_bytes(b"one\r\n\n#comment\none\nlast")
    rows = [dict(_row(URL + f"/{position}"), position=position,
                 input={"FUZZ": base64.b64encode(word).decode()})
            for position, word in enumerate([b"one", b"", b"#comment", b"one", b"last"], 1)]
    if fault == "duplicate":
        rows[-1] = rows[0]
    elif fault == "missing":
        rows.pop()
    elif fault == "mismatch":
        rows[0]["input"]["FUZZ"] = base64.b64encode(b"other").decode()
    elif fault == "base64":
        rows[0]["input"]["FUZZ"] = "!invalid"
    elif fault == "boolean":
        rows[0]["position"] = True
    result = tmp_path / "result.jsonl"
    result.write_text(_jsonl(list(reversed(rows))))
    if fault:
        with pytest.raises(ValueError):
            ReconAdapter(tmp_path).check_ffuf_run(result, words)
    else:
        ReconAdapter(tmp_path).check_ffuf_run(result, words)


@pytest.mark.parametrize("kind", ["missing", "empty", "json", "record", "one", "three",
                                 "mixed", "gzip", "zero", "size"])
def test_control_size_cli_distinguishes_invalid_from_zero(tmp_path, kind):
    controls = tmp_path / ("controls.gz" if kind == "gzip" else "controls.jsonl")
    pair = [_row(URL + "/one"), _row(URL + "/two")]
    contents = {
        "empty": "", "json": "{broken\n", "record": _jsonl([{}, {}]),
        "one": _jsonl(pair[:1]), "three": _jsonl(pair + pair[:1]),
        "mixed": _jsonl(pair) + "[]\n", "gzip": "not gzip",
        "zero": _jsonl(pair),
        "size": _jsonl([dict(row, status=200) for row in pair]),
    }
    if kind != "missing":
        controls.write_text(contents[kind])
    result = subprocess.run(
        [sys.executable, str(REPO / "tools/recon_adapter.py"), "--recon-dir", str(tmp_path),
         "--ffuf-control-size", "--controls", str(controls)],
        cwd=tmp_path, env=_env(tmp_path), capture_output=True, text=True, timeout=10,
    )
    if kind in {"zero", "size"}:
        assert (result.returncode, result.stdout) == (0, "0\n" if kind == "zero" else "4\n")
    else:
        assert result.returncode == 2, result.stdout + result.stderr
        error = json.loads(result.stdout)["error"]
        assert str(controls) in error and "expected exactly 2 valid FFUF controls" in error


def test_control_read_error_is_not_a_valid_zero(tmp_path, monkeypatch):
    controls = tmp_path / "controls.jsonl"
    controls.touch()
    original = Path.open

    def fail_control_read(path, *args, **kwargs):
        if path == controls:
            raise OSError("control read failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_control_read)
    with pytest.raises(ValueError, match="control read failure"):
        ReconAdapter(tmp_path).get_ffuf_control_filter_size(controls)


def _runtime(root):
    """Keep CLI reads/writes explicit-root without copying or replacing domain logic."""
    (root / "tools").mkdir(parents=True)
    for module in ("recon_adapter", "recon_target_selector"):
        extra = ""
        if module == "recon_target_selector":
            extra = (
                "args += ['--repo-root', str(root)]\n"
                "if '--record-results' in args:\n"
                "    (root / 'recorded.tsv').write_bytes(Path(args[args.index('--results') + 1]).read_bytes())\n"
            )
        (root / "tools" / f"{module}.py").write_text(
            "import sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(REPO)!r})\n"
            f"from tools.{module} import main\n"
            f"root = Path({str(root)!r})\nargs = sys.argv[1:]\n" + extra +
            "raise SystemExit(main(args))\n"
        )


def _functions(names):
    source = (REPO / "tools/recon_engine.sh").read_text()
    functions = {match[1]: match[0] for match in re.finditer(
        r"(?ms)^(\w+)\(\) \{.*?^\}", source
    )}
    return "\n".join(functions[name] for name in names)


def _shell(root, names, body, ffuf_path, variables=None, expected=0):
    assert os.pathsep not in str(ffuf_path.parent), "PATH entries cannot contain colons"
    script = 'set -euo pipefail\ntest "$(command -v ffuf)" = ' + shlex.quote(str(ffuf_path)) + "\n"
    script += _functions(names)
    script += '\nbb_auth_args_for_url() { BB_URL_AUTH_ARGS=(); }\n'
    variables = {"BASE_DIR": root, "RECON_DIR": root / "recon",
                 "FFUF_PHASE_DEADLINE_SECONDS": 20, **(variables or {})}
    script += "\n".join(f"{key}={shlex.quote(str(value))}" for key, value in variables.items())
    env = _env(root)
    env["PATH"] = str(ffuf_path.parent) + os.pathsep + env["PATH"]
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", script + "\n" + body],
        cwd=root, env=env, capture_output=True, text=True, timeout=25,
    )
    assert result.returncode == expected, result.stdout + result.stderr


WORKER_FUNCTIONS = ("timeout_bin", "run_with_timeout", "dir_fuzz_remaining_seconds",
                    "stop_ffuf_request", "ffuf_run_target")


@pytest.mark.parametrize("mode", ["empty", "malformed", "nonzero", "zero", "size", "main_failed",
                                 "control_429", "control_503", "main_429", "main_503",
                                 "gzip_failed"])
def test_phase_preserves_results_and_only_rotates_complete_hosts(tmp_path, mode):
    root = tmp_path / "ancestor:one with spaces"
    _runtime(root)
    dirs = root / "recon/dirs"
    for path in (dirs, root / "recon/live", root / "recon/logs", root / "wordlists", tmp_path / "bin"):
        path.mkdir(parents=True)
    urls = [URL, URL + "/nested"]
    (root / "recon/live/urls.txt").write_text("\n".join(urls) + "\n")
    (root / "wordlists/common.txt").write_text("found\nabsent\n")
    fake = tmp_path / "bin/ffuf"
    fake.write_text(
        f"#!{sys.executable}\nimport base64, json, sys\nfrom pathlib import Path\n"
        f"mode = {mode!r}\nroot = Path({str(root)!r})\n"
        "args = sys.argv[1:]\n"
        "wordarg = args[args.index('-w') + 1]\n"
        "words = (sys.stdin.read() if wordarg == '-' else Path(wordarg).read_text()).splitlines()\n"
        "main = words == ['found', 'absent']\n"
        "with (root / 'calls.jsonl').open('a') as out:\n"
        "    print(json.dumps({'args': args, 'words': words}), file=out)\n"
        "if not main and mode in {'empty', 'nonzero'}:\n"
        "    raise SystemExit(1 if mode == 'nonzero' else 0)\n"
        "if not main and mode == 'malformed':\n"
        "    print('{broken'); raise SystemExit(0)\n"
        "url = args[args.index('-u') + 1]\n"
        "for position, word in enumerate(words, 1):\n"
        "    status = 200 if main or mode in {'size', 'main_429', 'main_503'} else 404\n"
        "    if mode.startswith('control_') and not main or mode.startswith('main_') and main and word == 'absent' and mode != 'main_failed':\n"
        "        status = int(mode.rsplit('_', 1)[1])\n"
        "    print(json.dumps({'url': url.replace('FUZZ', word), 'status': status,\n"
        "                      'length': 4, 'words': 1, 'lines': 1, 'position': position,\n"
        "                      'input': {'FUZZ': base64.b64encode(word.encode()).decode()}}))\n"
        "raise SystemExit(1 if main and mode == 'main_failed' else 0)\n"
    )
    fake.chmod(0o700)
    if mode == "gzip_failed":
        compressor = tmp_path / "bin/gzip"
        compressor.write_text(
            "#!/bin/sh\n"
            'if [ "$2" != /dev/null ]; then echo "compression interrupted" >&2; exit 1; fi\n'
            f"exec {shlex.quote(shutil.which('gzip'))} \"$@\"\n"
        )
        compressor.chmod(0o700)
    variables = {
        "TARGET": TARGET, "RECON_TARGET_KEY": TARGET, "WORDLIST_DIR": root / "wordlists",
        "LEGACY_WORDLIST_DIR": root / "unused", "QUICK_MODE": "--quick", "THREADS": 2,
        "FFUF_HOST_CONCURRENCY": 2,
        "FFUF_PHASE_ARTIFACT": "", "FFUF_LOG": root / "recon/logs/ffuf.log",
        "RATE_LIMIT": 10, "FFUF_EFFECTIVE_BUDGET_SECONDS": 20,
        "DIR_FUZZ_HARD_BUDGET_SECONDS": 20, "FFUF_WORK_DIR": "",
        "FFUF_STATUS_COUNTS": "{}", "FFUF_HEAVY_SIGNATURES": "-",
        **{name: 0 for name in ("FFUF_ATTEMPTED", "FFUF_SUCCEEDED", "FFUF_FAILED",
                                "FFUF_CONTROL_FAILED", "FFUF_INTERRUPTED", "FFUF_OBSERVATIONS",
                                "FFUF_PARSE_ERRORS", "FFUF_SAMPLE_COUNT", "FFUF_OVERFLOW")},
        **{name: dirs / filename for name, filename in (
            ("FFUF_TARGET_STATE", "ffuf_target_state.json"), ("FFUF_TARGET_PLAN", "ffuf_target_plan.json"),
            ("FFUF_TARGETS_FILE", "ffuf_targets.txt"))},
    }
    _shell(root, (*WORKER_FUNCTIONS, "url_append_base", "archive_collector_artifact",
                  "run_ffuf_phase"),
           """FFUF_WORKER_PIDS=()
log_done() { :; }
log_warn() { :; }
emit_claude_hint() { :; }
record_recon_phase() { printf '%s' "$2" > "$RECON_DIR/phase-status"; }
run_ffuf_phase""", fake, variables, expected=1 if mode == "gzip_failed" else 0)
    if mode == "gzip_failed":
        assert not (root / "recorded.tsv").exists()
        assert not (dirs / "ffuf_summary.json").exists()
        assert json.loads((dirs / "ffuf_target_state.json").read_text())["completed"] == {}
        assert len(list(dirs.glob(".ffuf-workers.*/target-*/main.jsonl"))) == 2
        return
    control_failed = mode in {"empty", "malformed", "nonzero", "control_429", "control_503"}
    main_failed = mode in {"main_failed", "main_429", "main_503"}
    complete = not control_failed and not main_failed
    summary = json.loads((dirs / "ffuf_summary.json").read_text())
    assert (root / "recon/phase-status").read_text() == ("ok" if complete else "partial")
    assert len(summary["controls"]) == (0 if mode in {"empty", "malformed", "nonzero"} else 4)
    assert (summary["parse_error_count"] > 0) == (mode == "malformed")
    assert summary["attempted"] == 2
    assert summary["succeeded"] == (0 if main_failed else 2)
    assert summary["failed"] == (2 if main_failed else 0)
    assert summary["control_failed"] == (2 if control_failed else 0)
    assert summary["observations"] == 4
    with gzip.open(dirs / "ffuf_results.jsonl.gz", "rt") as stream:
        assert {json.loads(line)["url"] for line in stream} == {
            url + "/" + word for url in urls for word in ("found", "absent")
        }
    host_status = "ok" if complete else ("failed" if main_failed else "partial")
    if mode == "malformed":
        assert not (root / "recorded.tsv").exists()
    else:
        assert set((root / "recorded.tsv").read_text().splitlines()) == {f"{url}\t{host_status}" for url in urls}
    completed = json.loads((dirs / "ffuf_target_state.json").read_text())["completed"]
    assert set(completed) == (set(urls) if complete else set())
    retry = select_targets(target=TARGET, repo_root=root, httpx_path=root / "recon/live/httpx_full.txt",
                           urls_path=root / "recon/live/urls.txt", state_path=dirs / "ffuf_target_state.json",
                           plan_path=dirs / "retry.json", targets_path=dirs / "retry.txt",
                           wordlist_path=root / "wordlists/common.txt", limit=2)
    assert [item["url"] for item in retry["selected"]] == ([] if complete else urls)
    calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
    assert len(calls) == 4
    for call in calls:
        args = call["args"]
        assert args[args.index("-w") + 1] == "-"
        assert len(call["words"]) == 2
        assert "-ac" not in args and "-fs" not in args
        assert "-noninteractive" in args
        assert args[args.index("-mc") + 1] == "all"
    if mode in {"empty", "malformed"}:
        log = (root / "recon/logs/ffuf.log").read_text()
        assert "random-miss controls invalid:" in log and "expected exactly 2" in log


def test_summary_controls_remain_optional(tmp_path):
    (tmp_path / "dirs").mkdir()
    (tmp_path / "dirs/ffuf_results.jsonl").write_text(_jsonl([_row()]))
    summary = ReconAdapter(tmp_path).summarize_ffuf_results()
    assert summary["observations"] == 1 and summary["controls"] == []
    assert summary["parse_error_count"] == 0


def test_missing_main_wordlist_is_a_visible_failure(tmp_path):
    _runtime(tmp_path)
    worker = tmp_path / "worker"
    worker.mkdir()
    controls = tmp_path / "controls.jsonl"
    controls.write_text(_jsonl([_row(URL + "/one"), _row(URL + "/two")]))
    (tmp_path / "bin").mkdir()
    fake = tmp_path / "bin/ffuf"
    fake.write_text(f"#!/bin/sh\ncat {shlex.quote(str(controls))}\n")
    fake.chmod(0o700)
    _shell(tmp_path, WORKER_FUNCTIONS,
           'ffuf_run_target "$URL" "$WORKER" "$MISSING" 1 10', fake,
           {"URL": URL, "WORKER": worker, "MISSING": tmp_path / "missing.txt"})
    assert (worker / "summary.tsv").read_text().split("\t")[1:] == ["failed", "1", "0", "1", "0", "0\n"]
    assert (worker / "main.jsonl").read_text() == ""
    assert "missing.txt" in (worker / "worker.log").read_text()


@pytest.mark.parametrize(("folder", "failure"), [
    ("127.0.0.1:3001", ""), ("[::1]:3001", ""),
    ("ancestor:one with spaces/host:two", ""),
    ("partial-disconnect", "partial"), ("all-disconnect", "all"),
])
def test_real_ffuf_consumes_both_wordlists_through_background_stdin(tmp_path, folder, failure):
    executable = shutil.which("ffuf")
    assert executable, "real ffuf is required for the wordlist transport check"
    root = tmp_path / folder
    _runtime(root)
    (root / "recon").mkdir()
    worker = root / "worker"; worker.mkdir()
    words = root / "words.txt"; words.write_text("found\nabsent")
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if (failure == "all" and not self.path.startswith("/__bbhunt_missing_")
                    or failure == "partial" and self.path == "/absent"):
                self.close_connection = True
                return
            body = b"distinct found response" if self.path == "/found" else b"miss"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        _shell(root, WORKER_FUNCTIONS,
               f"( ffuf_run_target {shlex.quote(base)} {shlex.quote(str(worker))} {shlex.quote(str(words))} 1 10 ) &\nwait $!",
               Path(executable))
    finally:
        server.shutdown(); server.server_close(); thread.join()
    controls = [json.loads(line) for line in (worker / "control.jsonl").read_text().splitlines()]
    results = [json.loads(line) for line in (worker / "main.jsonl").read_text().splitlines()]
    assert len(controls) == 2 and all("/__bbhunt_missing_" in row["url"] for row in controls)
    expected = set() if failure == "all" else {base + "/found"}
    if not failure:
        expected.add(base + "/absent")
    assert {row["url"] for row in results} == expected
    assert "/found" in requests and "/absent" in requests and "/FUZZ" not in requests
    assert (worker / "summary.tsv").read_text().split("\t")[1:] == (
        ["failed", "1", "0", "1", "0", "0\n"] if failure else ["ok", "1", "1", "0", "0", "0\n"]
    )
