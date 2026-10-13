#!/usr/bin/env python3
"""Offline, read-only fixture broker; candidate responses are never owner evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import time
import uuid

import capability_evaluation as evaluation

VERSION = "capability-collector/1"


def sandbox_command(bwrap: str, program_directory: Path) -> list[str]:
    """Only system binaries and the frozen entry script are visible to the process."""
    return [bwrap, "--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr", "--symlink", "/usr/bin", "/bin",
            "--symlink", "/usr/lib", "/lib", "--symlink", "/usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
            "--dir", "/home/candidate", "--ro-bind", str(program_directory), "/runner",
            "--chdir", "/home/candidate", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "HOME", "/home/candidate", "--setenv", "LANG", "C.UTF-8",
            "--", "/usr/bin/python3", "-I", "-S", "-u", "/runner/candidate.py"]


class Collection:
    """Immutable files plus a hash-chained transcript owned outside the candidate mount."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.sequence = 0
        self.previous = "0" * 64
        self.observations: list[dict] = []

    def save(self, name: str, data: bytes) -> dict:
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}

    def save_json(self, name: str, value: object) -> dict:
        return self.save(name, evaluation.canonical_bytes(value) + b"\n")

    def event(self, kind: str, payload: dict, observation: str | None = None) -> dict:
        self.sequence += 1
        value = {"seq": self.sequence, "previous": self.previous,
                 "monotonic_ns": time.monotonic_ns(), "kind": kind, "payload": payload}
        reference = self.save_json(f"events/{self.sequence:06d}.json", value)
        self.previous = reference["sha256"]
        if observation is not None:
            self.observations.append({"kind": observation, "source": reference})
        return reference


def _prepare(case: dict, bank: Path, program: dict, program_root: Path, out: Path) -> tuple[Collection, dict, dict]:
    evaluation.validate_case(case, bank)
    script = evaluation.read_verified_ref(program, program_root)
    public = case["candidate"]
    resources = {}
    for kind, reference in [("initial", public["initial_state"])] + [("material", r) for r in public["materials"]]:
        if any(item["source"] == reference for item in resources.values()):
            continue
        data = evaluation.read_verified_ref(reference, bank)
        # The broker returns Unicode fixture text, not a local path or a Python object.
        text = data.decode("utf-8")
        resources[f"r{len(resources):04d}"] = {"kind": kind, "data": data, "text": text, "source": reference}
    if not out.is_absolute() or out.resolve() != out or out.exists():
        raise ValueError("output must be a new absolute, nonsymlink directory")
    for source in (bank.resolve(), program_root.resolve()):
        if out == source or out in source.parents or source in out.parents:
            raise ValueError("collection output must be disjoint from input roots")
    out.mkdir(mode=0o700)
    collection = Collection(out)
    collection.save("runner/candidate.py", script)
    for resource, item in resources.items():
        item["captured"] = collection.save(f"materials/{resource}.txt", item["data"])
    prompt = {"version": VERSION, "case_id": uuid.uuid4().hex, "question": public["question"],
              "allowed_actions": public["allowed_actions"],
              "resources": [{"id": key, "kind": value["kind"], "bytes": len(value["data"])}
                            for key, value in resources.items()],
              "rpc": {"request": {"id": "unique integer", "method": "list|read|finish", "params": "object"},
                      "list": {}, "read": {"resource": "resource ID"}, "finish": {"answer": "JSON value"}}}
    collection.save_json("prompt.json", prompt)
    collection.save_json("binding.json", {"version": VERSION, "case_sha256": evaluation.digest(case),
                         "program": program, "resources": {key: value["source"] for key, value in resources.items()}})
    return collection, resources, prompt


def _rpc(line: bytes, resources: dict, prompt: dict, seen: set, finished: bool) -> tuple[dict, str | None, object]:
    message = evaluation._json_bytes(line)
    if not isinstance(message, dict) or set(message) != {"id", "method", "params"}:
        raise ValueError("RPC requires exactly id/method/params")
    identity, method, params = message["id"], message["method"], message["params"]
    if type(identity) is not int or identity < 0 or identity in seen or finished:
        raise ValueError("duplicate/invalid RPC id or request after finish")
    seen.add(identity)
    if not isinstance(params, dict):
        raise ValueError("RPC params must be an object")
    if method == "list" and params == {}:
        return {"id": identity, "result": prompt["resources"]}, "directory", None
    if method == "read" and set(params) == {"resource"}:
        resource = params["resource"]
        if not isinstance(resource, str) or resource not in resources:
            return {"id": identity, "error": "unknown_resource"}, None, None
        item = resources[resource]
        return {"id": identity, "result": {"resource": resource, "text": item["text"],
                "sha256": item["captured"]["sha256"]}}, "read", item["captured"]
    if method == "finish" and set(params) == {"answer"}:
        return {"id": identity, "result": "recorded_not_judged"}, "result", params["answer"]
    raise ValueError("unknown RPC method or invalid parameters")


def _run(command: list[str], collection: Collection, resources: dict, prompt: dict,
         timeout: float, limit_bytes: int) -> tuple[str, dict, dict, dict]:
    started = time.monotonic()
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    output = None
    status, reason = "protocol_failure", "candidate did not finish"
    stdout, stderr = bytearray(), bytearray()
    process = subprocess.Popen(command, cwd=collection.directory, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    collection.event("started", {"pid": process.pid, "timeout": timeout, "limit_bytes": limit_bytes})
    selector = selectors.DefaultSelector()
    outgoing = bytearray(evaluation.canonical_bytes(prompt) + b"\n")
    pending = bytearray()
    seen: set[int] = set()
    finished = False
    try:
        for stream, key in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, key)
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                status, reason = "timeout", "wall-clock budget exhausted"
                break
            failed = False
            for key, _ in selector.select(min(remaining, 0.05)):
                if key.data == "stdin":
                    try:
                        written = os.write(key.fd, outgoing[:65536])
                        del outgoing[:written]
                    except BrokenPipeError:
                        outgoing.clear()
                    if not outgoing:
                        selector.unregister(key.fileobj)
                    continue
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream_data = stdout if key.data == "stdout" else stderr
                space = limit_bytes - len(stdout) - len(stderr)
                stream_data.extend(chunk[:space])
                if len(chunk) > space:
                    status, reason, failed = "protocol_failure", "output byte limit exceeded; raw prefix retained", True
                    break
                if key.data == "stderr":
                    continue
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, tail = pending.partition(b"\n")
                    pending = bytearray(tail)
                    request = collection.save(f"requests/{collection.sequence + 1:06d}.json", bytes(line) + b"\n")
                    try:
                        reply, observation, extra = _rpc(bytes(line), resources, prompt, seen, finished)
                    except (ValueError, UnicodeError) as exc:
                        collection.event("invalid_request", {"request": request, "error": str(exc)})
                        status, reason, failed = "protocol_failure", str(exc), True
                        break
                    payload = {"request": request, "reply": reply}
                    if observation == "read":
                        payload["material"] = extra
                    if observation == "result":
                        finished = True
                        output = collection.save_json("answer.json", extra)
                        payload["answer"] = output
                    collection.event("rpc", payload, observation)
                    outgoing.extend(evaluation.canonical_bytes(reply) + b"\n")
                    if len(outgoing) > limit_bytes:
                        status, reason, failed = "protocol_failure", "unconsumed broker response limit exceeded", True
                        break
                    if process.stdin not in selector.get_map():
                        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                if failed:
                    break
            if failed:
                break
            if process.poll() is not None and not any(k.data != "stdin" for k in selector.get_map().values()):
                break
        else:
            # A candidate can close its streams and keep running; still apply the deadline.
            pass
        if reason == "candidate did not finish":
            try:
                process.wait(timeout=max(0.001, timeout - (time.monotonic() - started)))
                if process.returncode != 0:
                    status, reason = "tool_failure", f"candidate exit code {process.returncode}"
                elif pending:
                    status, reason = "protocol_failure", "unterminated RPC frame"
                elif finished:
                    status, reason = "completed", "response collected; correctness not assessed"
            except subprocess.TimeoutExpired:
                status, reason = "timeout", "wall-clock budget exhausted"
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    streams = {"stdout": collection.save("stdout.bin", bytes(stdout)),
               "stderr": collection.save("stderr.bin", bytes(stderr))}
    terminal = {"status": status, "reason": reason, "returncode": process.returncode,
                "elapsed_seconds": time.monotonic() - started, "streams": streams}
    collection.event("terminated", terminal)
    if output is None:
        output = collection.save_json("no-answer.json", {"collector_failure": terminal})
    return status, output, terminal, streams


def collect(case: dict, bank: str | Path, program: dict, program_root: str | Path,
            out: str | Path, *, timeout: float = 10, limit_bytes: int = 1_048_576) -> dict:
    """Run a frozen local Python candidate. This does not authorize model experiments."""
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 3600:
        raise ValueError("timeout must be between 0 and 3600 seconds")
    if type(limit_bytes) is not int or not 1024 <= limit_bytes <= 16_777_216:
        raise ValueError("limit_bytes must be an integer between 1024 and 16777216")
    collection, resources, prompt = _prepare(case, Path(bank), program, Path(program_root), Path(out))
    bwrap = shutil.which("bwrap", path="/usr/bin:/bin")
    command = sandbox_command(bwrap, collection.directory / "runner") if bwrap else []
    preflight = {"available": False, "reason": "bwrap not installed"}
    if command:
        probe = command[:command.index("--") + 1] + ["/usr/bin/true"]
        try:
            result = subprocess.run(probe, cwd=collection.directory, env={"PATH": "/usr/bin:/bin"},
                                    capture_output=True, timeout=5, check=False)
            preflight = {"available": result.returncode == 0, "returncode": result.returncode,
                         "stdout": collection.save("preflight-stdout.bin", result.stdout),
                         "stderr": collection.save("preflight-stderr.bin", result.stderr)}
        except (OSError, subprocess.TimeoutExpired) as exc:
            preflight = {"available": False, "reason": str(exc)}
    collection.save_json("preflight.json", preflight)
    if preflight["available"]:
        collection.event("admitted", {"program_sha256": program["sha256"], "sandbox": "bubblewrap"})
        try:
            status, output, terminal, _ = _run(command, collection, resources, prompt, timeout, limit_bytes)
        except OSError as exc:
            status = "initialization_failure"
            terminal = {"status": status, "reason": str(exc)}
            collection.event("initialization_failure", terminal)
            output = collection.save_json("no-answer.json", {"collector_failure": terminal})
        admission = "admitted"
    else:
        admission, status = "preflight", "preflight_not_run"
        terminal = {"status": status, "preflight": preflight}
        collection.event("not_run", terminal)
        output = collection.save_json("no-answer.json", terminal)
    owner = collection.save_json("owner.json", {
        "collector": VERSION, "admission": admission, "status": status, "terminal": terminal,
        "trace_head": collection.previous, "trace_length": collection.sequence,
        "hard_events": {}, "unobserved_hard_events": list(evaluation.HARD_EVENTS),
        "observation_scope": "broker calls and isolated process only; no domain lifecycle observations"})
    report = {"version": VERSION, "case_sha256": evaluation.digest(case), "admission": admission,
              "status": status, "output": output, "artifacts": {"owner": owner},
              "observations": collection.observations, "terminal": terminal,
              "capability": "not_assessed", "registration": "not_bound"}
    collection.save_json("collection.json", report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("case", "bank", "program", "program-root", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--limit-bytes", type=int, default=1_048_576)
    args = parser.parse_args(argv)
    try:
        result = collect(evaluation.load_json(args.case), args.bank, evaluation.load_json(args.program),
                         args.program_root, args.out, timeout=args.timeout, limit_bytes=args.limit_bytes)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0 if result["status"] == "completed" else 1
    except (ValueError, OSError) as exc:
        print(f"capability-collect: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
