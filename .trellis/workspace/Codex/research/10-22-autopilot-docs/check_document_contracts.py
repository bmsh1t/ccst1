"""Check document interfaces in a disposable source copy, without target I/O."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parents[5]
CHANGED = (
    "commands/autopilot.md",
    "agents/autopilot.md",
    "docs/ccst-runtime-adapter.md",
)


def historical(relative: str) -> bytes:
    return subprocess.check_output(["git", "show", "eebaa01:" + relative], cwd=REPO)


def sections(body: str) -> dict[str, str]:
    lines = body.splitlines()
    headings: list[tuple[int, int, str]] = []
    fenced = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        if not fenced and (match := re.match(r"^(#{1,6})\s+(.+)$", line)):
            headings.append((index, len(match[1]), match[2]))
    result = {}
    for position, (start, level, title) in enumerate(headings):
        end = next((other[0] for other in headings[position + 1:] if other[1] <= level), len(lines))
        result[title] = "\n".join(lines[start:end]).strip()
    return result


def frontmatter(body: str) -> str:
    assert body.startswith("---\n")
    return body.split("---", 2)[1]


def anchors(body: str) -> set[str]:
    return {
        re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", title.lower()))
        for title in sections(body)
    }


def check(root: Path) -> dict:
    sys.path.insert(0, str(root))
    from tools.runtime_doctor import _repo_files, compare_runtime, load_critical_runtime_manifest, RUNTIME_SUBDIRS

    checks = []
    source = (root / "tools/autopilot_bootstrap.py").read_text()
    parsed = ast.parse(source)
    symbols = {"_LANE_CONTRACTS", "LANE_CONTRACT_TEXT_MAX_CHARS", "_lane_contract_text"}
    nodes = [node for node in parsed.body if
             (isinstance(node, ast.FunctionDef) and node.name in symbols) or
             (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in symbols for t in node.targets))]
    # Execute the real pure Markdown extractor without importing target runtime.
    namespace = {"Path": Path, "Any": object}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "lane_contract_extractor", "exec"), namespace)
    extractor = namespace["_lane_contract_text"]
    for reference, _reason in namespace["_LANE_CONTRACTS"].values():
        if reference.startswith("docs/"):
            actual = extractor(root, reference)
            assert actual["available"] and actual["text"]
            path, _, anchor = reference.partition("#")
            expected = next(value for title, value in sections((root / path).read_text()).items()
                            if "-".join(title.lower().split()) == anchor)
            assert actual["text"] == expected
    checks.append("real selected-lane extraction retains complete section text")

    for relative in CHANGED:
        before = historical(relative).decode()
        after = (root / relative).read_text()
        assert list(sections(before)) == list(sections(after))
    before_command = historical(CHANGED[0]).decode()
    command = (root / CHANGED[0]).read_text()
    assert frontmatter(before_command) == frontmatter(command)
    assert frontmatter(historical(CHANGED[1]).decode()) == frontmatter((root / CHANGED[1]).read_text())
    assert next(line for line in before_command.splitlines() if line.startswith("Authoritative bootstrap")) == next(
        line for line in command.splitlines() if line.startswith("Authoritative bootstrap"))
    old_sections, new_sections = sections(before_command), sections(command)
    for title in ["Investigation Skill", "State Consumption Loop", "Execution Invariants", "Transition And Finish Contract"]:
        assert old_sections[title] == new_sections[title]
    assert list(title for title in new_sections if title == "Shared Automation") == ["Shared Automation"]
    assert command.endswith(new_sections["Shared Automation"] + "\n")
    for relative in ["commands/autopilot-round.md", "CLAUDE.md", "skills/runtime-protocol.md",
                     "skills/src-hunter/SKILL.md", "docs/autopilot-lanes.md"]:
        assert (root / relative).read_bytes() == historical(relative)
    checks.append("frontmatter, bootstrap, round, complete 6k imports and core investigation/finish contracts unchanged")

    protected_agent_sections = ["Use When", "Write Boundary And Result"]
    old_agent = sections(historical(CHANGED[1]).decode())
    new_agent = sections((root / CHANGED[1]).read_text())
    assert all(old_agent[title] == new_agent[title] for title in protected_agent_sections)
    assert sections(historical(CHANGED[2]).decode())["来源与历史"] == sections((root / CHANGED[2]).read_text())["来源与历史"]
    checks.append("specialist owner-write/result boundary and adapter source history unchanged")

    count = 0
    reference_pattern = r"(?:docs|rules|commands|skills|knowledge)/[^\s`|();：，。<>]+\.md#[^\s`|();：，。<>]+"
    for relative in CHANGED:
        path = root / relative
        body = path.read_text()
        for reference in re.findall(reference_pattern, body):
            target, _, anchor = reference.partition("#")
            assert anchor in anchors((root / target).read_text()), (relative, reference)
            count += 1
        for reference in re.findall(r"\]\(([^)]+)\)", body):
            if "://" in reference:
                continue
            target, _, anchor = reference.partition("#")
            destination = path.parent / target
            assert destination.is_file(), (relative, reference)
            if anchor:
                assert anchor in anchors(destination.read_text()), (relative, reference)
            count += 1
    checks.append(f"{count} Markdown references resolve to existing paths and, where provided, section anchors")

    manifest = load_critical_runtime_manifest(root)
    assert manifest["status"] == "valid" and manifest["schema_version"] == 3
    start = "<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST"
    end = "AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->"
    assert before_command.split(start, 1)[1].split(end, 1)[0] == command.split(start, 1)[1].split(end, 1)[0]
    with tempfile.TemporaryDirectory(prefix="ccst-doc-runtime-") as directory:
        runtime = Path(directory)
        receipt = {}
        for kind in RUNTIME_SUBDIRS:
            for relative, source_path in _repo_files(root, kind).items():
                destination = runtime / RUNTIME_SUBDIRS[kind] / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                raw = source_path.read_bytes()
                destination.write_bytes(raw)
                receipt[destination.relative_to(runtime).as_posix()] = {
                    "kind": kind, "sha256": hashlib.sha256(raw).hexdigest()}
        (runtime / ".ccst-installed.json").write_text(json.dumps(receipt))
        comparison = compare_runtime(root, runtime)
        assert comparison["clean"] and comparison["critical_clean"], {
            key: comparison[key] for key in ["drift_count", "critical_drift", "missing_critical", "advisory_drift"]}
    checks.append("real runtime inventory comparison accepts unchanged critical manifest and current sources")
    measurements = []
    for relative in CHANGED:
        before, after = historical(relative), (root / relative).read_bytes()
        measurements.append({"path": relative, "before_bytes": len(before), "after_bytes": len(after),
                             "before_chars": len(before.decode()), "after_chars": len(after.decode()),
                             "sha256": hashlib.sha256(after).hexdigest()})
    resident = ["CLAUDE.md"] + [line[1:] for line in (root / "CLAUDE.md").read_text().splitlines() if line.startswith("@")]
    return {"status": "passed", "checks": checks, "measurements": measurements,
            "resident_before_bytes": sum(len(historical(path)) for path in resident),
            "resident_after_bytes": sum(len((root / path).read_bytes()) for path in resident),
            "limits": "Document/runtime interfaces only; no model invocation, target I/O, or project tests."}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ccst-doc-source-") as directory:
        isolated = Path(directory)
        # Exact tracked-source whitelist excludes tests, target data and personal runtime.
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=REPO).decode().split("\0")
        for relative in tracked:
            path = Path(relative)
            if not relative or (path.parts[0] not in {"tools", "docs", "rules", "commands", "agents", "skills"}
                                and relative != "CLAUDE.md"):
                continue
            if path.parts[0] == "tools" and path.suffix != ".py":
                continue
            destination = isolated / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((REPO / path).read_bytes())
        sys.dont_write_bytecode = True
        print(json.dumps(check(isolated), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
