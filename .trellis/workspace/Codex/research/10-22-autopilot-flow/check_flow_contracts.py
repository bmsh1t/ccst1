"""Check Autopilot document interfaces and usage in a disposable source copy."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[5]
BASELINE = "d9d215a70b2dbafe5844a1e50d79290b81825a51"
TOOL_FILES = ["__init__.py", "autopilot_args.py", "target_paths.py", "runtime_doctor.py",
              "artifact_io.py", "skill_reference_contract.py", "autopilot_bootstrap.py"]
REFERENCE = r"(?:commands|skills|docs|rules|knowledge)/[^\s`|();：，。<>]+\.md(?:#[^\s`|();：，。<>]+)?"


def historical(relative: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{BASELINE}:{relative}"], cwd=REPO)


def check(root: Path, sections, anchors, frontmatter) -> dict:
    sys.path.insert(0, str(root))
    from tools.autopilot_args import parse_autopilot_args
    from tools.runtime_doctor import load_critical_runtime_manifest

    assert Path(sys.modules["tools.autopilot_args"].__file__).is_relative_to(root)
    assert Path(sys.modules["tools.runtime_doctor"].__file__).is_relative_to(root)
    command = (root / "commands/autopilot.md").read_text()
    before = historical("commands/autopilot.md").decode()
    parsed = sections(command)
    shared = parsed["Shared Automation"]
    assert command.count("\n## Shared Automation\n") == 1
    assert command.rstrip().endswith(shared)
    assert set(sections(before)) <= set(parsed)
    assert list(sections(shared))[1] == "State Consumption Loop"
    for title in ("State Consumption Loop", "Startup And Recovery", "Investigation Skill",
                  "Execution Invariants", "Refresh After An Action", "Transition And Finish Contract",
                  "Claiming Exhaustion", "Final Response"):
        assert parsed[title] in shared, title
    prefix = "Authoritative bootstrap contract (do not reinterpret):"
    bootstrap = next(line for line in command.splitlines() if line.startswith(prefix))
    assert bootstrap == next(line for line in before.splitlines() if line.startswith(prefix))
    assert bootstrap not in shared and frontmatter(command) == frontmatter(before)
    round_body = (root / "commands/autopilot-round.md").read_text()
    assert "commands/autopilot.md#shared-automation" in round_body
    for relative in ("commands/autopilot-round.md", "skills/runtime-protocol.md",
                     "skills/src-hunter/SKILL.md", "docs/autopilot-lanes.md", "CLAUDE.md"):
        assert (root / relative).read_bytes() == historical(relative), relative
    for path in (root / "skills/src-hunter").rglob("*.md"):
        assert path.read_bytes() == historical(path.relative_to(root).as_posix()), str(path)
    checks = ["unchanged entry frontmatter/bootstrap, CLAUDE import declarations and src-hunter materials; "
              "Round retains every shared workflow/recovery/finish section"]

    references = set(re.findall(REFERENCE, command))
    for reference in references:
        path, _, anchor = reference.partition("#")
        destination = root / path
        assert destination.is_file(), reference
        if anchor:
            assert anchor in anchors(destination.read_text()), reference
    links = re.findall(r"\]\((#[^)]+)\)", command)
    assert links
    for link in links:
        assert link[1:] in anchors(command), link
    for relative in ("skills/runtime-protocol.md", "docs/architecture-contract.md", "commands/autopilot-round.md"):
        for anchor in re.findall(r"commands/autopilot\.md#([\w-]+)", (root / relative).read_text()):
            assert anchor in anchors(command), (relative, anchor)
    checks.append(f"{len(references)} unique checkout references, {len(links)} local links and incoming command anchors resolve")

    start, end = "<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST", "AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->"
    assert before.split(start, 1)[1].split(end, 1)[0] == command.split(start, 1)[1].split(end, 1)[0]
    manifest = load_critical_runtime_manifest(root)
    assert manifest["status"] == "valid" and manifest["schema_version"] == 3
    for entry in manifest["paths"]:
        assert (root / entry["kind"] / entry["relative_path"]).is_file(), entry
    source = ast.parse((root / "tools/autopilot_bootstrap.py").read_text())
    names = {"_LANE_CONTRACTS", "LANE_CONTRACT_TEXT_MAX_CHARS", "_lane_contract_text"}
    nodes = [node for node in source.body if
             (isinstance(node, ast.FunctionDef) and node.name in names) or
             (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets))]
    namespace = {"Path": Path, "Any": object}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "isolated_lane_reader", "exec"), namespace)
    for reference, _ in namespace["_LANE_CONTRACTS"].values():
        path, _, anchor = reference.partition("#")
        assert anchor in anchors((root / path).read_text()), reference
        result = namespace["_lane_contract_text"](root, reference)
        if path.startswith("docs/"):
            expected = next(body for title, body in sections((root / path).read_text()).items()
                            if "-".join(title.lower().split()) == anchor)
            assert result["available"] and result["text"] == expected, reference
        else:
            assert not result["available"] and "read the ref directly" in result["reason"]
    checks.append("real manifest reader accepts unchanged inventory; real lane reader retains full sections and controller reference")

    fixture = root / "invocation"
    fixture.mkdir()
    (fixture / "targets.txt").write_text("fixture.invalid\n")
    (fixture / "auth.json").write_text("{}\n")
    (fixture / "context.json").write_text("{}\n")
    examples = re.findall(r"^/autopilot (.+)$", parsed["Usage"], re.MULTILINE)
    assert len(examples) == 4
    outputs = [parse_autopilot_args(shlex.split(example), cwd=fixture) for example in examples]
    assert all(item["valid"] for item in outputs), outputs
    assert (outputs[0]["cadence"], outputs[0]["quick"], outputs[0]["deep"], outputs[0]["max_lanes"]) == ("paranoid", False, False, None)
    assert outputs[1]["seed_url"] == "https://target.com/app" and outputs[1]["deep"] and outputs[1]["cadence"] == "normal"
    assert outputs[2]["quick"] and outputs[2]["deep"] and outputs[2]["max_lanes"] == 16 and outputs[2]["recon_flags"] == ["--quick"]
    assert outputs[3]["target_kind"] == "list" and outputs[3]["cadence"] == "normal"
    for cap in (1, 32):
        assert parse_autopilot_args(["fixture.invalid", "--deep", "--max-lanes", str(cap)], cwd=fixture)["valid"]
    for flags in (["--deep", "--max-lanes", "0"], ["--deep", "--max-lanes", "33"],
                  ["--max-lanes", "16"], ["--normal", "--yolo"]):
        assert not parse_autopilot_args(["fixture.invalid", *flags], cwd=fixture)["valid"], flags
    round_args = parse_autopilot_args(["fixture.invalid"], cwd=fixture, round_defaults=True)
    assert round_args["valid"] and round_args["cadence"] == "normal" and round_args["deep"] and round_args["max_lanes"] == 16
    bound = parse_autopilot_args(["fixture.invalid", "--auth-file", "auth.json", "--context-file=context.json"], cwd=fixture)
    assert bound["valid"] and bound["hunt_auth_flags"] == ["--auth-file", str(fixture / "auth.json"), "--context-file", str(fixture / "context.json")]
    checks.append("real pure parser accepts all documented examples, defaults, combined quick/deep and bound auth/context; rejects invalid caps/modes")
    return {"status": "passed", "baseline": BASELINE, "checks": checks,
            "command_before_bytes": len(before.encode()), "command_after_bytes": len(command.encode()),
            "shared_automation_bytes": len(shared.encode()),
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "limits": "Static document/source interfaces only; no project tests, target-state acquisition, actual runtime install, Claude/model calls or network."}


def main() -> None:
    assert __debug__, "assertions must be enabled"
    sys.dont_write_bytecode = True
    started = time.monotonic()
    # Reuse the prior pure Markdown helpers without running that historical acceptance.
    helper = Path(__file__).parents[1] / "10-22-autopilot-docs/check_document_contracts.py"
    spec = importlib.util.spec_from_file_location("previous_doc_helpers", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="ccst-autopilot-flow-") as directory:
        root = Path(directory)
        command = (REPO / "commands/autopilot.md").read_text()
        paths = {ref.partition("#")[0] for ref in re.findall(REFERENCE, command)}
        paths.update(["commands/autopilot.md", "commands/autopilot-round.md", "CLAUDE.md",
                      "docs/autopilot-lanes.md", "docs/architecture-contract.md"])
        paths.update("tools/" + name for name in TOOL_FILES)
        paths.update(subprocess.check_output(["git", "ls-files", "-z", "--", "skills"], cwd=REPO).decode().strip("\0").split("\0"))
        for relative in sorted(paths):
            source = REPO / relative
            assert "tests" not in Path(relative).parts and source.is_file() and not source.is_symlink(), relative
            assert source.resolve().is_relative_to(REPO), relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        result = check(root, module.sections, module.anchors, module.frontmatter)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    Path(__file__).with_name("result.json").write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
