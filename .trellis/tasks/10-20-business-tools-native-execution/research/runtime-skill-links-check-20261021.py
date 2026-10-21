"""Isolated runtime Skill-link compatibility and single-entry acceptance."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
ORIGIN = Path(__file__).resolve().parents[4]
BASELINE = "1e0c06b"
START = time.monotonic()
CHECKS = 0


def check(condition, label):
    global CHECKS
    if not condition:
        raise AssertionError(label)
    CHECKS += 1


def rejected(call, part):
    try:
        call()
    except (ValueError, OSError) as exc:
        check(part in str(exc), f"expected {part}, got {exc}")
        return
    raise AssertionError(f"expected rejection: {part}")


def put(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def skill(path, name):
    return put(path / "SKILL.md", f"---\nname: {name}\ndescription: synthetic fixture\n---\n# Fixture\n")


with tempfile.TemporaryDirectory(prefix="ccst-runtime-skill-links-") as temporary:
    fixture = Path(temporary)
    checkout = fixture / "checkout"
    checkout.mkdir()
    names = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", BASELINE, "--", "tools", "memory"],
                                    cwd=ORIGIN, text=True).splitlines()
    selected = [name for name in names if Path(name).suffix in {".py", ".sh"} and "tests" not in Path(name).parts]
    archive = subprocess.check_output(["git", "archive", BASELINE, "--", *selected], cwd=ORIGIN)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        for member in bundle.getmembers():
            if member.isfile():
                destination = checkout / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(bundle.extractfile(member).read())
    (checkout / "tools/runtime_doctor.py").write_bytes((ORIGIN / "tools/runtime_doctor.py").read_bytes())
    put(checkout / "knowledge/capabilities.yaml", "capabilities: []\ncontracts: {}\n")
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ}
    environment.update(PYTHONPATH=str(checkout), PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                       CCST_RUNTIME_ROOT=str(fixture / "host"))
    os.environ.clear()
    os.environ.update(environment)
    os.chdir(checkout)
    sys.path[:0] = [str(checkout), str(checkout / "tools")]

    def guard(event, args):
        if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo"}:
            raise RuntimeError("fixture forbids network")
        if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0])).absolute()
            if any(root == path or root in path.parents for root in (ORIGIN, Path("/root/.claude"), Path("/root/.codex"))) or "tests" in path.parts:
                raise RuntimeError("fixture forbids private/original/project-test reads")
    sys.addaudithook(guard)

    from tools import autopilot_bootstrap as bootstrap
    from tools.runtime_doctor import _file_hash, _skill_entries, compare_runtime, sync_runtime

    repo, host = fixture / "candidate", fixture / "host"
    repo.mkdir()
    host.mkdir()
    put(repo / "CLAUDE.md", "# Synthetic candidate\n")
    skill(repo / "skills/src-hunter", "src-hunter")
    manifest = {"schema_version": 1, "paths": [{"kind": "commands", "relative_path": "autopilot.md"},
                                               {"kind": "skills", "relative_path": "src-hunter/SKILL.md"}],
                "mcp_contracts": []}
    put(repo / "commands/autopilot.md", "# Fixture\n<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST\n" +
        json.dumps(manifest) + "\nAUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->\n")
    original = sync_runtime(repo, host, prune=True)
    check(original["status"] == "complete" and compare_runtime(repo, host)["critical_clean"], "baseline staged runtime is clean")

    external = fixture / "shared/chrome-devtools-cli"
    skill(external, "chrome-devtools-cli")
    put(external / "references/usage.md", "# Shared external resource\n")
    (host / "skills/chrome-devtools-cli").symlink_to(external, target_is_directory=True)
    external_snapshot = (external / "SKILL.md").read_bytes()
    receipt_snapshot = (host / ".ccst-installed.json").read_bytes()

    check(compare_runtime(repo, host)["critical_clean"], "normal linked external Skill is not drift")
    entries = _skill_entries(host, allow_external_links=True)
    check(any(entry["identity"] == "chrome-devtools-cli" and not entry["known_identities"] for entry in entries), "linked identity is inspected")
    rejected(lambda: _skill_entries(host), "linked Skill directory")
    again = sync_runtime(repo, host, prune=True)
    check(again["status"] == "complete" and (host / "skills/chrome-devtools-cli").is_symlink(), "sync preserves external Skill link")
    check((external / "SKILL.md").read_bytes() == external_snapshot and (host / ".ccst-installed.json").read_bytes() == receipt_snapshot, "external bytes and receipt remain unchanged")

    # A SKILL.md file symlink and harmless nested asset links are legal reads.
    file_source = skill(fixture / "shared/file-source", "thirdparty-file")
    file_entry = host / "skills/thirdparty-file"
    file_entry.mkdir()
    (file_entry / "SKILL.md").symlink_to(file_source)
    assets = fixture / "shared/assets"
    assets.mkdir()
    (external / "references/src-hunter").symlink_to(assets, target_is_directory=True)
    check(compare_runtime(repo, host)["critical_clean"], "file-linked entry and name-only asset link are accepted")

    # Circular reference directories stop expanding; distinct logical aliases remain inspected.
    (external / "references/back").symlink_to(external, target_is_directory=True)
    loop_entries = _skill_entries(host, allow_external_links=True)
    check(len(loop_entries) < 10, "directory cycle terminates")
    (host / "skills/another-alias").symlink_to(external, target_is_directory=True)
    check(compare_runtime(repo, host)["critical_clean"], "external aliases do not create CCST drift")

    # Renaming a linked CCST entry never conceals its real identity.
    hidden_source = fixture / "shared/hidden"
    skill(hidden_source, "web2-recon")
    hidden_link = host / "skills/looks-external"
    hidden_link.symlink_to(hidden_source, target_is_directory=True)
    before_receipt = (host / ".ccst-installed.json").read_bytes()
    rejected(lambda: compare_runtime(repo, host), "linked CCST Skill entry")
    rejected(lambda: sync_runtime(repo, host, prune=True), "linked CCST Skill entry")
    check(hidden_link.is_symlink() and (host / ".ccst-installed.json").read_bytes() == before_receipt, "conflict causes no publication or deletion")
    hidden_link.unlink()
    nested = skill(external / "references/ordinary-name", "src-hunter")
    rejected(lambda: compare_runtime(repo, host), "linked CCST Skill entry")
    nested.unlink()
    nested.parent.rmdir()
    file_source.write_text("---\nname: src-hunting\n---\n# Fixture\n")
    rejected(lambda: compare_runtime(repo, host), "linked CCST Skill entry")
    skill(file_source.parent, "thirdparty-file")

    # The managed root remains a regular installed file; a matching link is never owned.
    core = host / "skills/src-hunter/SKILL.md"
    core_bytes = core.read_bytes()
    core_source = put(fixture / "shared/core.md", core_bytes.decode())
    core.unlink()
    core.symlink_to(core_source)
    rejected(lambda: _skill_entries(host, allow_external_links=True), "linked CCST Skill entry")
    rejected(lambda: _file_hash(core, host), "unsafe runtime/source path")
    core.unlink()
    core.write_bytes(core_bytes)

    # Real Bootstrap uses the fixed compare owner; isolate downstream state/capability acquisition.
    target = "skill-link-fixture.invalid"
    with patch.object(bootstrap, "build_capability_profile", return_value={}), \
         patch.object(bootstrap, "build_autopilot_bootstrap_state", return_value={}) as state, \
         patch.object(bootstrap, "compact_autopilot_state", return_value={}), \
         patch.object(bootstrap, "load_capability_degraded_marker", return_value={}):
        payload = bootstrap.build_autopilot_bootstrap([target], cwd=repo, repo_root=repo, runtime_root=host)
        check(payload["action"] == "continue" and payload["runtime"]["critical_clean"] and state.call_count == 1, "Bootstrap reaches state with normal external links")
        hidden_link.symlink_to(hidden_source, target_is_directory=True)
        blocked = bootstrap.build_autopilot_bootstrap([target], cwd=repo, repo_root=repo, runtime_root=host)
        check(blocked["action"] == "stop_runtime_error" and "linked CCST Skill entry" in blocked["error"]["reason"], "Bootstrap retains real identity conflict")
        check(state.call_count == 1, "conflict blocks downstream state acquisition")
        hidden_link.unlink()

    # Uninspectable linked entry remains a visible error; source-side links stay strict.
    file_source.write_text("---\nname: [ambiguous]\n---\n")
    rejected(lambda: compare_runtime(repo, host), "cannot reliably inspect Skill name")
    skill(file_source.parent, "thirdparty-file")
    source_link = repo / "skills/source-link"
    source_link.symlink_to(external, target_is_directory=True)
    rejected(lambda: _skill_entries(repo), "linked Skill directory")
    source_link.unlink()
    check(compare_runtime(repo, host)["critical_clean"], "final normal runtime remains clean")
    check((external / "SKILL.md").read_bytes() == external_snapshot, "external Skill bytes are never changed")
    os.chdir(fixture.parent)

print(json.dumps({"status": "passed", "assertions": CHECKS, "seconds": round(time.monotonic() - START, 3),
                  "baseline": BASELINE, "overlay": ["tools/runtime_doctor.py"],
                  "scope": "synthetic source/runtime/shared links; no project tests, real host, private data or network"}))
