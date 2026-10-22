"""Check automation entry interfaces and static reading sets without target I/O."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[5]
BASELINE = "1c6fb2f981d69378cd1d8ece646f09bc64413b11"
CHANGED = ["commands/autopilot.md", "commands/autopilot-round.md", "commands/checkpoint.md",
           "skills/runtime-protocol.md", "docs/architecture-contract.md"]


def main() -> None:
    assert __debug__, "assertions must be enabled"
    sys.dont_write_bytecode = True
    started = time.monotonic()
    research = Path(__file__).parents[1]
    helpers = runpy.run_path(str(research / "10-22-autopilot-docs/check_document_contracts.py"))
    previous = runpy.run_path(str(research / "10-22-autopilot-flow/check_flow_contracts.py"))
    sections, anchors, frontmatter = (helpers[name] for name in ("sections", "anchors", "frontmatter"))
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "CLAUDE.md", "rules", "skills/src-hunter"], cwd=REPO
    ).decode().rstrip("\0").split("\0")
    paths = set(tracked + CHANGED + ["docs/autopilot-lanes.md", "agents/autopilot.md"])
    for relative in CHANGED:
        paths.update(ref.partition("#")[0] for ref in re.findall(previous["REFERENCE"], (REPO / relative).read_text()))
    resident = ["CLAUDE.md"] + [line[1:].strip() for line in (REPO / "CLAUDE.md").read_text().splitlines() if line.startswith("@")]
    paths.update(resident)
    old = {p: subprocess.check_output(["git", "show", f"{BASELINE}:{p}"], cwd=REPO).decode() for p in sorted(paths)}
    new = {p: (REPO / p).read_bytes().decode() for p in paths}
    for relative in tracked + ["docs/autopilot-lanes.md", "agents/autopilot.md"]:
        assert new[relative] == old[relative], relative
    for relative in ["commands/autopilot.md", "commands/autopilot-round.md", "commands/checkpoint.md"]:
        assert frontmatter(new[relative]) == frontmatter(old[relative]), relative
    for relative in CHANGED[:2]:
        assert [line for line in new[relative].splitlines() if "(do not reinterpret):" in line] == [
            line for line in old[relative].splitlines() if "(do not reinterpret):" in line], relative
    command = new[CHANGED[0]]
    start, end = "<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST", "AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->"
    assert command.split(start)[1].split(end)[0] == old[CHANGED[0]].split(start)[1].split(end)[0]
    parsed = sections(command)
    assert command.count("\n## Shared Automation\n") == 1
    assert command.rstrip().endswith(parsed["Shared Automation"])
    for title in ("State Consumption Loop", "Investigation Skill", "Transition And Finish Contract"):
        assert parsed[title] in parsed["Shared Automation"]
    assert "commands/autopilot.md#shared-automation" in new[CHANGED[1]]
    assert "commands/autopilot.md" not in new["skills/runtime-protocol.md"]
    assert "skills/runtime-protocol.md#native-skill-loading" in parsed["Investigation Skill"]
    assert "commands/checkpoint.md#global-review" in command and "commands/checkpoint.md#global-review" in new[CHANGED[1]]
    links = set()
    for relative in CHANGED:
        references = re.findall(previous["REFERENCE"], new[relative])
        references += [link for link in re.findall(r"\]\((#[^)]+)\)", new[relative])]
        for reference in references:
            destination, _, anchor = reference.partition("#")
            destination = destination or relative
            assert (REPO / destination).is_file(), (relative, reference)
            if anchor:
                assert anchor in anchors(new[destination]), (relative, reference)
            links.add((relative, reference))

    with tempfile.TemporaryDirectory(prefix="ccst-automation-contract-") as directory:
        root = Path(directory)
        for relative in paths | {"tools/" + name for name in previous["TOOL_FILES"]}:
            assert "tests" not in Path(relative).parts
            source, destination = REPO / relative, root / relative
            assert not source.is_symlink() and source.resolve().is_relative_to(REPO)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        sys.path.insert(0, str(root))
        from tools.autopilot_args import parse_autopilot_args
        from tools.runtime_doctor import load_critical_runtime_manifest
        assert Path(sys.modules["tools.autopilot_args"].__file__).is_relative_to(root)
        assert load_critical_runtime_manifest(root)["status"] == "valid"
        tree = ast.parse((root / "tools/autopilot_bootstrap.py").read_text())
        names = {"_LANE_CONTRACTS", "LANE_CONTRACT_TEXT_MAX_CHARS", "_lane_contract_text"}
        nodes = [node for node in tree.body if
                 (isinstance(node, ast.FunctionDef) and node.name in names) or
                 (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets))]
        namespace = {"Path": Path, "Any": object}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "lane_reader", "exec"), namespace)
        for reference, _ in namespace["_LANE_CONTRACTS"].values():
            path, _, anchor = reference.partition("#")
            assert anchor in anchors(new[path]), reference
            result = namespace["_lane_contract_text"](root, reference)
            if path.startswith("docs/"):
                expected = next(body for title, body in sections(new[path]).items() if "-".join(title.lower().split()) == anchor)
                assert result["available"] and result["text"] == expected, reference
            else:
                assert not result["available"] and "read the ref directly" in result["reason"]
        (root / "targets.txt").write_text("fixture.invalid\n")
        for name in ("auth.json", "context.json"):
            (root / name).write_text("{}\n")
        examples = re.findall(r"^/autopilot (.+)$", parsed["Usage"], re.MULTILINE)
        results = [parse_autopilot_args(shlex.split(example), cwd=root) for example in examples]
        assert len(results) == 4 and all(result["valid"] for result in results)
        assert results[0]["cadence"] == "paranoid" and not results[0]["deep"]
        assert results[1]["seed_url"] == "https://target.com/app" and results[1]["cadence"] == "normal"
        assert results[2]["quick"] and results[2]["deep"] and results[2]["max_lanes"] == 16
        assert results[3]["target_kind"] == "list"
        for cap in (1, 32):
            assert parse_autopilot_args(["fixture.invalid", "--deep", "--max-lanes", str(cap)], cwd=root)["valid"]
        for flags in (["--deep", "--max-lanes", "33"], ["--max-lanes", "1"], ["--normal", "--yolo"]):
            assert not parse_autopilot_args(["fixture.invalid", *flags], cwd=root)["valid"]
        round_args = parse_autopilot_args(["fixture.invalid"], cwd=root, round_defaults=True)
        assert (round_args["cadence"], round_args["deep"], round_args["max_lanes"]) == ("normal", True, 16)
        bound = parse_autopilot_args(["fixture.invalid", "--auth-file", "auth.json", "--context-file=context.json"], cwd=root)
        assert bound["valid"] and bound["hunt_auth_flags"] == ["--auth-file", str(root / "auth.json"), "--context-file", str(root / "context.json")]

    def reading_set(bodies, references):
        values = {}
        for reference in references:
            path, _, title = reference.partition("#")
            body = sections(bodies[path])[title] if title else bodies[path]
            values[reference] = len(body.encode())
        return {"sources": values, "bytes": sum(values.values())}

    common = [CHANGED[0], "skills/runtime-protocol.md#Shared Knowledge Recall",
              "skills/runtime-protocol.md#Shared Memory Continuity", "skills/src-hunter/SKILL.md",
              "skills/src-hunter/知识库/打穿短表.md"]
    loaded = common + ["skills/runtime-protocol.md#Native Skill Loading"]
    action = ["rules/ccst/hunting.md", "rules/ccst/tool-ai-boundary.md",
              "skills/runtime-protocol.md#5. Execution and write-back",
              "docs/autopilot-lanes.md#State And Queue", "docs/evidence-runners.md#绑定已认领行动"]
    finish = ["rules/ccst/coverage-gate.md", "rules/ccst/retrospective.md", "knowledge/promotion-rules.md"]
    measurements = {
        "owners_full_files": {"before": reading_set(old, CHANGED[:4]), "after": reading_set(new, CHANGED[:4])},
        "startup_sections": {"before": reading_set(old, common), "after": reading_set(new, loaded)},
        "action_sections": {"before": reading_set(old, common + action), "after": reading_set(new, loaded + action)},
        "exhaustion_sections": {"before": reading_set(old, common + action + finish + ["commands/checkpoint.md#显式轮次与复核"]),
                                "after": reading_set(new, loaded + action + finish + ["commands/checkpoint.md#Global Review"])},
        "resident_full_files": {"before": reading_set(old, resident), "after": reading_set(new, resident)},
    }
    for name, values in measurements.items():
        assert values["after"]["bytes"] <= values["before"]["bytes"], name
    assert len(command.encode()) < len(old[CHANGED[0]].encode()) / 2
    for path, digest in {
        "tools/autopilot_state.py": "6cb58e7ff7a61a1e060ef8bd4ca62c912d9d6f103807d88d65368aca45e4dd9e",
        "tools/surface_projection.py": "ac0a1b8c38c3d05c2f7aa015a607333185421e69c2103078404f448063243982",
    }.items():
        assert hashlib.sha256((REPO / path).read_bytes()).hexdigest() == digest, path
    output = {"status": "passed", "baseline": BASELINE, "resolved_references": len(links),
              "command_before_bytes": len(old[CHANGED[0]].encode()), "command_after_bytes": len(command.encode()),
              "command_sha256": hashlib.sha256(command.encode()).hexdigest(), "reading_sets": measurements,
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "limits": "Static specified reading sets, not actual host loads/tokens. Unchanged method-specific expansions and tool outputs excluded. No project tests, target I/O, runtime installation, network or model calls."}
    Path(__file__).with_name("result.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({key: value for key, value in output.items() if key != "reading_sets"}, ensure_ascii=False, indent=2))
    for name, values in measurements.items():
        print(name, values["before"]["bytes"], "->", values["after"]["bytes"])


if __name__ == "__main__":
    main()
