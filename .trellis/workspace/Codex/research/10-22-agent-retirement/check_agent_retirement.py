"""Accept five agent retirements using disposable tracked-source copies only."""

from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


REPO = Path(__file__).resolve().parents[5]
BASELINE = "1a8a95d0589463f0a3aebff037034bbc2b5e0953"
RETIRED = {"recon-agent", "recon-ranker", "chain-builder", "web3-auditor", "token-auditor"}
SURVIVING = {"autopilot", "validator", "report-writer", "disclosed-researcher", "credential-hunter"}
SOURCE_PATHS = ["tools", "memory", "agents", "commands", "skills", "rules", "CLAUDE.md",
                "README.md", "docs/autopilot-lanes.md", "docs/ctf-web-distillation-audit.md"]
REVIEW_BOUNDARY = (
    "只读复核仅审阅父会话明确目标的现有证据；不发目标请求、不运行采集或投影刷新，\n"
    "不初始化、导入或修复 Store。缺失或无效材料返回 unknown 与恢复建议；状态及派生\n"
    "产物由父会话通过原 owner 写回。普通 `surface.py` 也可能发布投影，不在只读复核中运行。\n\n"
).encode()


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=REPO)


def source_copies(before: Path, current: Path) -> None:
    archive = git("archive", BASELINE, "--", *SOURCE_PATHS)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        for entry in bundle:
            relative = Path(entry.name)
            assert not relative.is_absolute() and ".." not in relative.parts
            assert "tests" not in relative.parts
            assert entry.isdir() or entry.isfile(), entry.name
            if entry.isfile():
                destination = before / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(entry) as handle:
                    destination.write_bytes(handle.read())
                destination.chmod(entry.mode)
    for relative in git("ls-files", "-z", "--", *SOURCE_PATHS).decode().split("\0"):
        if not relative:
            continue
        path = REPO / relative
        assert "tests" not in Path(relative).parts
        assert path.resolve().is_relative_to(REPO) and not path.is_symlink(), relative
        if not path.exists():
            assert relative in {f"agents/{name}.md" for name in RETIRED}, relative
            continue
        assert stat.S_ISREG(path.stat().st_mode), relative
        destination = current / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def receipt(runtime: Path) -> dict:
    return json.loads((runtime / ".ccst-installed.json").read_text())


def owned_agents(runtime: Path) -> set[str]:
    return {Path(path).stem for path, item in receipt(runtime).items() if item["kind"] == "agents"}


def snapshot(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file()}


def compact_function(root: Path):
    symbols = {"_compact_candidate", "_compact_intel_continuation", "_LANE_CONTRACTS",
               "LANE_CONTRACT_TEXT_MAX_CHARS", "_lane_contract_text", "_lane_contract_projection",
               "compact_autopilot_state"}
    parsed = ast.parse((root / "tools/autopilot_bootstrap.py").read_text())
    nodes = [node for node in parsed.body if
             (isinstance(node, ast.FunctionDef) and node.name in symbols) or
             (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in symbols
                                                 for t in node.targets))]
    # Only next_step prose is stubbed; the changed projection and lane reader are real.
    namespace = {"Path": Path, "Any": object, "json": json, "REPO_ROOT": root,
                 "describe_next_step": lambda state: "fixture owner step"}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(root / "tools/autopilot_bootstrap.py"), "exec"), namespace)
    return namespace["compact_autopilot_state"]


def check(before: Path, current: Path, runtime: Path, conflict_runtime: Path) -> dict:
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(current))
    from tools import runtime_doctor as doctor

    assert Path(doctor.__file__).resolve().is_relative_to(current)
    kinds = list(doctor.KIND_ORDER)
    checks = []
    before_agents = doctor._repo_files(before, "agents")
    current_agents = doctor._repo_files(current, "agents")
    assert {Path(p).stem for p in before_agents} == RETIRED | SURVIVING
    assert {Path(p).stem for p in current_agents} == SURVIVING
    for relative, path in current_agents.items():
        assert path.read_bytes() == before_agents[relative].read_bytes(), relative
    for kind, allowed_change in (("commands", "autopilot.md"), ("skills", "src-hunter/SKILL.md")):
        old, new = doctor._repo_files(before, kind), doctor._repo_files(current, kind)
        assert old.keys() == new.keys()
        if kind == "commands":
            assert len(new) == 37
        for relative, path in new.items():
            if relative != allowed_change:
                assert path.read_bytes() == old[relative].read_bytes(), relative
            else:
                assert path.read_bytes().split(b"---", 2)[1] == old[relative].read_bytes().split(b"---", 2)[1]
    skill = (current / "skills/src-hunter/SKILL.md").read_bytes()
    assert skill.count(REVIEW_BOUNDARY) == 1
    assert skill.replace(REVIEW_BOUNDARY, b"", 1) == (before / "skills/src-hunter/SKILL.md").read_bytes()
    assert (current / "CLAUDE.md").read_bytes() == (before / "CLAUDE.md").read_bytes()
    for path in (current / "rules").rglob("*.md"):
        relative = path.relative_to(current)
        if relative.as_posix() != "rules/ccst/campaign.md":
            assert path.read_bytes() == (before / relative).read_bytes(), str(relative)
    manifest = doctor.load_critical_runtime_manifest(current)
    assert manifest["status"] == "valid" and manifest == doctor.load_critical_runtime_manifest(before)
    for entry in manifest["paths"]:
        assert (current / entry["kind"] / entry["relative_path"]).is_file(), entry
    checks.append("five agents removed; five survivors, 37 commands, complete modules/6k body and critical manifest preserved")

    compact_before, compact_current = compact_function(before), compact_function(current)
    state = {
        "next_action": "validate_finding", "selection_mode": "owner", "target_kind": "domain",
        "resume_summary": {"target_memory": {"active_goal": "fixture", "pending_candidates": ["C-1"]},
                           "source_binding": {"snapshot_id": "fixture-snapshot"}},
        "scope": {"status": "ready", "scope_hash": "fixture-scope"},
        "continuation": {"invocation_id": "I-1", "selected_target": "fixture.invalid"},
        "owner_continuations": [{"id": "F-1", "owner": "finding", "action": "validate_finding"},
                                {"id": "A-1", "owner": "action_queue", "evidence_ref": "fixture-evidence"}],
        "surface_review_candidates": [{"id": "S-1", "url": "https://fixture.invalid/x?a=1&a=%2F",
                                       "method": "GET", "evidence_ref": "fixture-source"}],
        "surface_projection": {"status": "ready", "path": "fixture-surface",
                               "continuation": {"available": True, "next_cursor": "fixture-cursor", "command": "fixture-page"}},
        "memory_candidate_next": {"id": "C-1", "evidence_ref": "fixture-memory"},
        "intel_continuation": {"action": "collect_web_intel", "recommended": [{"subject": "fixture", "query": "fixture-query"}]},
    }
    for hints in ([], [{"tool": "recon-ranker", "mode": "review", "reason": "historical"}],
                  [{"tool": "context_pack"}, {"tool": "checkpoint"}]):
        state["enrichment_hints"] = hints
        untouched = copy.deepcopy(state)
        previous, projected = compact_before(state), compact_current(state)
        assert projected["enrichment_hints"] == [] and state == untouched
        previous["enrichment_hints"] = []
        assert projected == previous
        assert projected["owner_continuations"] == state["owner_continuations"]
        assert projected["target_memory"]["source_binding"] == state["resume_summary"]["source_binding"]
        assert projected["surface_projection"] == state["surface_projection"]
        assert projected["surface_candidates"] == state["surface_review_candidates"]
        assert projected["lane_contract"]["text_available"]
    checks.append("real compact projection discards historical specialist hints; owner, Surface, cursor, memory and lane facts unchanged")

    installed = doctor.sync_runtime(before, runtime, kinds, prune=True)
    assert installed["status"] == "complete" and owned_agents(runtime) == RETIRED | SURVIVING
    assert not (runtime / doctor.ENTRY_MIGRATION_RECORD).exists()
    shutil.copytree(runtime, conflict_runtime)
    normal = doctor.sync_runtime(current, runtime, kinds)
    assert normal["status"] == "complete" and normal["removed"] == []
    assert owned_agents(runtime) == RETIRED | SURVIVING
    checks.append("baseline installs 10 owned agents; ordinary current sync retains all five retired owned copies")

    extra = runtime / doctor.RUNTIME_SUBDIRS["agents"] / "user-owned.md"
    extra.write_bytes(b"user-owned agent\n")
    extra_before = (extra.read_bytes(), extra.stat().st_mtime_ns)
    pruned = doctor.sync_runtime(current, runtime, kinds, prune=True)
    removed = {Path(p).relative_to(runtime).as_posix() for p in pruned["removed"]}
    assert pruned["status"] == "complete"
    assert removed == {f"agents/claude-bug-bounty/{name}.md" for name in RETIRED}
    assert owned_agents(runtime) == SURVIVING
    assert (extra.read_bytes(), extra.stat().st_mtime_ns) == extra_before
    assert extra.relative_to(runtime).as_posix() not in receipt(runtime)
    for kind in kinds:
        for relative, path in doctor._repo_files(current, kind).items():
            destination = runtime / doctor.RUNTIME_SUBDIRS[kind] / relative
            assert destination.read_bytes() == path.read_bytes(), str(destination)
            assert receipt(runtime)[destination.relative_to(runtime).as_posix()] == {
                "kind": kind, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    comparison = doctor.compare_runtime(current, runtime, kinds)
    assert comparison["critical_clean"] and comparison["critical_manifest"]["status"] == "valid"
    assert all(item["counts"]["diff"] == item["counts"]["missing"] == 0 for item in comparison["kinds"])
    checks.append("prune removes exactly five unchanged owned agents; all current payloads/receipts match and unowned extra bytes/mtime survive")

    modified = conflict_runtime / doctor.RUNTIME_SUBDIRS["agents"] / "recon-agent.md"
    modified.write_bytes(modified.read_bytes() + b"\nuser edit\n")
    candidate = current.parent / "conflict-source"
    shutil.copytree(current, candidate)
    arsenal = candidate / "commands/arsenal.md"
    arsenal.write_bytes(arsenal.read_bytes() + b"\nfixture pending sync\n")
    unchanged = snapshot(conflict_runtime)
    rejected = doctor.sync_runtime(candidate, conflict_runtime, kinds, prune=True)
    assert rejected["status"] == "rejected" and rejected["copied"] == rejected["removed"] == []
    assert any(item["path"] == modified.relative_to(conflict_runtime).as_posix()
               and item["action"] == "remove" and item["ownership"] == "receipt"
               for item in rejected["conflict_details"])
    assert snapshot(conflict_runtime) == unchanged
    assert not (conflict_runtime / doctor.ENTRY_MIGRATION_RECORD).exists()
    checks.append("modified obsolete agent rejects the whole batch before pending command writes; payload/receipt bytes and mtimes preserved")
    return {"status": "passed", "baseline": BASELINE, "checks": checks,
            "agents_before": 10, "agents_after": 5, "commands": 37,
            "skill_resources": len(doctor._repo_files(current, "skills")), "removed": sorted(removed),
            "limits": ["no project tests, real runtime, target data, network or paid model calls",
                       "pure projection fixture does not exercise owner-state acquisition or host discovery/cache behavior"]}


def main() -> None:
    assert __debug__, "run without -O so acceptance assertions are active"
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ccst-agent-retirement-") as directory:
        root = Path(directory)
        before, current = root / "before", root / "current"
        source_copies(before, current)
        result = check(before, current, root / "runtime", root / "conflict-runtime")
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    Path(__file__).with_name("result.json").write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
