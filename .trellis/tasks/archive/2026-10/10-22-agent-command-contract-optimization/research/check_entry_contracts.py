"""Focused source-copy acceptance; no project tests, real targets or host runtime."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from unittest.mock import patch
from urllib.parse import unquote


REPO = next(path.parent for path in Path(__file__).resolve().parents if path.name == ".trellis")
BASELINE = "2ce0171"
SPECIALTIES = ("chain-builder", "web3-auditor", "token-auditor")
COMMANDS = ("chain", "web3-audit", "token-scan")
MODULES = ("triage-validation", "web3-audit", "meme-coin-audit")


def baseline(relative: str) -> str:
    return subprocess.check_output(["git", "show", f"{BASELINE}:{relative}"], cwd=REPO).decode()


def normalized(value: str) -> str:
    return " ".join(value.split())


def sections(body: str) -> dict[str, str]:
    headings = []
    fence = ""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if fence:
            if re.fullmatch(re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*", line):
                fence = ""
            continue
        if opening := re.match(r"(`{3,}|~{3,})", line):
            fence = opening[1]
        elif heading := re.match(r"^(#{1,6})\s+(.+)$", line):
            headings.append((index, len(heading[1]), heading[2]))
    result = {}
    for position, (start, level, title) in enumerate(headings):
        end = next((i for i, size, _ in headings[position + 1:] if size <= level), len(lines))
        result[title] = "\n".join(lines[start:end]).strip()
    return result


def frontmatter(body: str) -> str:
    return re.match(r"\A---\n.*?\n---\n", body, re.S)[0]


def check_documents(root: Path) -> dict:
    from tools.runtime_doctor import _repo_files, load_critical_runtime_manifest

    changed = subprocess.check_output(["git", "diff", "--name-only", "-z", BASELINE], cwd=REPO).decode().split("\0")
    content_paths = [p for p in changed if p.startswith(("commands/", "agents/", "skills/", "docs/")) or p == "README.md"]
    for agent, command, module in zip(SPECIALTIES, COMMANDS, MODULES):
        paths = (f"agents/{agent}.md", f"commands/{command}.md")
        for relative in paths:
            before, after = baseline(relative), (root / relative).read_text()
            assert frontmatter(before) == frontmatter(after), relative
            before_output = next(body for title, body in sections(before).items() if title.endswith("Output"))
            after_output = next(body for title, body in sections(after).items() if title.endswith("Output"))
            old_fields = set(re.findall(r"\b([A-Z_]+):", before_output))
            new_fields = set(re.findall(r"\b([A-Z_]+):", after_output))
            assert old_fields <= new_fields, (relative, old_fields - new_fields)
            assert f"../skills/src-hunter/modules/{module}.md" in after, relative
        if "Usage" in sections(baseline(paths[1])):
            before_usage = re.findall(r"```text\n(.*?)\n```", sections(baseline(paths[1]))["Usage"], re.S)
            after_usage = re.findall(r"```text\n(.*?)\n```", sections((root / paths[1]).read_text())["Usage"], re.S)
            assert before_usage == after_usage, paths[1]

    web3 = normalized((root / "skills/src-hunter/modules/web3-audit.md").read_text())
    old_web3 = sections(baseline("agents/web3-auditor.md"))
    methods = [normalized(section.split("\n", 1)[1]) for name, section in old_web3.items() if name.startswith("Class ")]
    assert len(methods) == 10 and all(method in web3 for method in methods)
    assert "index/loop" in web3 and "TWAP" in web3 and "source independence and bounds" in web3
    assert "clearest expected learning and lowest reversible cost" in web3
    assert "authority transitions" in web3 and "actor binding and replay scope" in web3
    for method in methods:
        assert method not in normalized((root / "agents/web3-auditor.md").read_text())
    for command, module, count in (("token-scan", "meme-coin-audit", 8), ("chain", "triage-validation", 7)):
        rows = [line for line in baseline(f"commands/{command}.md").splitlines() if line.startswith("| ")][1:]
        assert len(rows) == count, (command, rows)
        content = (root / f"skills/src-hunter/modules/{module}.md").read_text()
        assert all(row in content for row in rows), command
        assert all(row not in (root / f"commands/{command}.md").read_text() for row in rows)
    triage = (root / "skills/src-hunter/modules/triage-validation.md").read_text()
    old_examples = [line for line in sections(baseline("skills/src-hunter/modules/triage-validation.md"))[
        "CONDITIONALLY VALID — CHAIN REQUIRED"].splitlines() if line.startswith("| ")]
    assert all(row in triage for row in old_examples)
    for detail in ("expected learning", "kill condition", "evidence hashes", "actor/state, observation kind, and evidence",
                   "Stop adding hops", "Independent Findings stay separate", "concrete\nreopen condition"):
        assert detail in triage, detail
    token = (root / "skills/src-hunter/modules/meme-coin-audit.md").read_text()
    assert "slippage" in token and "A token age" in token and "least-impact read-back" in token
    assert "web3-auditor" in (root / "agents/token-auditor.md").read_text()
    for relative in ("agents/token-auditor.md", "commands/token-scan.md"):
        assert "source or bytecode revision when available" in normalized((root / relative).read_text())
    for relative in ("agents/web3-auditor.md", "agents/token-auditor.md", "commands/web3-audit.md", "commands/token-scan.md"):
        body = normalized((root / relative).read_text())
        assert "non-HTTP Store lifecycle" in body and "actual" in body and "Do not fabricate" in body

    links = 0
    for relative in content_paths:
        path, body = root / relative, (root / relative).read_text()
        references = re.findall(r"\]\(([^)]+)\)", body)
        for reference in references:
            if "://" in reference or "<" in reference or not reference.split("#")[0].endswith(".md"):
                continue
            target, _, anchor = reference.partition("#")
            destination = (path.parent / unquote(target)).resolve()
            assert destination.is_file(), (relative, reference)
            if anchor:
                anchors = {re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", title.lower()))
                           for title in sections(destination.read_text())}
                assert anchor in anchors, (relative, reference)
            links += 1
    for kind, expected in (("agents", 10), ("commands", 37)):
        files = _repo_files(root, kind)
        assert len(files) == expected, (kind, len(files))
    installed = _repo_files(root, "skills")
    assert all(f"src-hunter/modules/{module}.md" in installed for module in MODULES)
    assert load_critical_runtime_manifest(root)["status"] == "valid"

    protected = [path for path in subprocess.check_output(
        ["git", "ls-files", "-z", "--", "rules", "skills/src-hunter/知识库"], cwd=REPO).decode().split("\0") if path]
    protected += ["CLAUDE.md", "skills/src-hunter/SKILL.md", "skills/runtime-protocol.md", "commands/autopilot.md",
                  "commands/autopilot-round.md", "agents/autopilot.md", "docs/autopilot-lanes.md", "tools/target_store.py"]
    for relative in protected:
        before = subprocess.check_output(["git", "show", f"{BASELINE}:{relative}"], cwd=REPO)
        assert (root / relative).read_bytes() == before, relative
    remember = (root / "commands/remember.md").read_text()
    assert "summary_path" in remember and "--validate-json VALIDATION_SUMMARY_PATH" in remember
    assert "projection has no\nsummary locator" in remember
    recon = sections((root / "commands/recon.md").read_text())["Focused FFUF Discovery"]
    assert all(flag in recon for flag in ("--conditions", "--reopen-when", "--operation-ref OPERATION_ID:STEP"))
    return {"migrated_methods": 25, "checked_links": links, "protected_files": len(protected),
            "entry_document_bytes_before": sum(len(baseline(p).encode()) for p in content_paths if p.startswith(("agents/", "commands/"))),
            "entry_document_bytes_after": sum((root / p).stat().st_size for p in content_paths if p.startswith(("agents/", "commands/")))}


def check_disclosure(root: Path, data: Path) -> list[str]:
    from tools import disclosure_search as d

    for heading in ("#", "##"):
        assert d._retained_full_readings(f"## Read in full\nquotation\n{heading}\nstale body\n") == "## Read in full\nquotation\n"
    try:
        d.write_disclosed_patterns("fixture.test", data, vertical=False, no_mcp=True)
        raise AssertionError("non-string industry accepted")
    except ValueError as error:
        assert "vertical must be a string" in str(error)
    target = "fixture.test"
    output = data / "evidence" / target / "disclosed_patterns.md"
    output.parent.mkdir(parents=True)
    first = "## Read in full\r\n\r\nSource https://example.invalid/reports/1：原始引文\r\n### Detail\r\n````text\r\n```\r\n## Keep fenced heading\r\n````\r\n\r\n"
    second = "## Read in full\n\nSecond quotation.\n"
    output.write_bytes(("# Old summary\n~~~\n## Read in full\nnot a reading\n~~~\n" + first +
                        "## Old generated content\nREMOVE ME\n" + second + "# Old footer\nDROP FOOTER\n").encode())
    sibling = output.with_suffix(".readings.md")
    sibling.write_bytes(b"# Independent readings\nsource and attribution\n")
    sibling_before = sibling.read_bytes(), sibling.stat().st_mtime_ns

    class Provider:
        def __init__(self, mode="complete"):
            self.mode, self.calls = mode, []

        def search_disclosed_reports(self, **kwargs):
            self.calls.append(kwargs)
            if self.mode == "unavailable" or self.mode == "partial" and "program" in kwargs:
                raise OSError("synthetic provider failure")
            if self.mode == "empty":
                return []
            return [{"title": "old material" if self.mode == "complete" else "fresh material", "severity": "high",
                     "url": "https://example.invalid/" + str(kwargs.get("keyword", "same")), "program": "peer"}]

    def readings_intact():
        content = output.read_bytes().decode()
        assert first in content and second in content
        assert "REMOVE ME" not in content and "DROP FOOTER" not in content and "not a reading" not in content
        assert "(disclosed_patterns.readings.md)" in content
        assert (sibling.read_bytes(), sibling.stat().st_mtime_ns) == sibling_before
        return content

    def render(provider, **kwargs):
        with patch.object(d, "_load_h1_client", return_value=provider), patch.object(
                d, "_load_tech_stack_hint", return_value=["finance", "one", "two", "three", "four", "five"]):
            d.write_disclosed_patterns(target, data, **kwargs)
        return readings_intact()

    provider = Provider()
    text = render(provider, vertical=" finance \n")
    similar = [c["keyword"] for c in provider.calls if "keyword" in c]
    assert similar == ["finance", "one", "two", "three", "four"]
    assert "_Query status: complete_" in text and "_Material industry: finance_" in text
    cache = d._cache_path(data, target)
    cache_before = cache.read_bytes(), cache.stat().st_mtime_ns
    cached = render(Provider("unavailable"), vertical="finance")
    assert "_Query status: cached_" in cached and (cache.read_bytes(), cache.stat().st_mtime_ns) == cache_before
    failed = render(Provider("unavailable"), vertical="SaaS")
    assert "_Query status: unavailable_" in failed and "_Material source: cache_" in failed
    assert "_Requested industry: SaaS_" in failed and "_Material industry: finance_" in failed
    assert "Cached industry differs" in failed and "old material" in failed
    partial = render(Provider("partial"), vertical="SaaS")
    assert "_Query status: partial_" in partial and "_Material source: live_" in partial
    assert "fresh material" in partial and "old material" not in partial
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == cache_before
    empty = render(Provider("empty"), vertical="SaaS")
    assert "_Query status: complete_" in empty and "_MCP coverage: no_mcp_coverage_" in empty
    assert "_All executed queries succeeded with zero reports._" in empty
    payload = json.loads(cache.read_bytes())
    payload.pop("vertical")
    cache.write_text(json.dumps(payload))
    legacy_before = cache.read_bytes(), cache.stat().st_mtime_ns
    legacy = render(Provider("unavailable"))
    assert "_Query status: cached_" in legacy
    legacy_mismatch = render(Provider("unavailable"), vertical="finance")
    assert "_Material industry: not supplied_" in legacy_mismatch and "Cached industry differs" in legacy_mismatch
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == legacy_before
    payload["vertical"] = False
    cache.write_text(json.dumps(payload))
    invalid_before = cache.read_bytes()
    invalid = render(None, vertical="finance")
    assert "cache vertical must be a string" in invalid and "_Material source: none_" in invalid
    assert cache.read_bytes() == invalid_before
    with patch.object(d, "_load_cache", side_effect=AssertionError("no-mcp read cache")), patch.object(
            d, "_load_h1_client", side_effect=AssertionError("no-mcp loaded provider")), patch.object(
            d, "_load_tech_stack_hint", side_effect=AssertionError("no-mcp read inventory")):
        d.write_disclosed_patterns(target, data, no_mcp=True)
    skipped = readings_intact()
    assert "_Query status: skipped_" in skipped and cache.read_bytes() == invalid_before
    old_bytes = output.read_bytes()
    original_read = Path.read_bytes

    def refused(path):
        if path == output:
            raise PermissionError("synthetic output read failure")
        return original_read(path)

    with patch.object(Path, "read_bytes", refused):
        try:
            d.write_disclosed_patterns(target, data, no_mcp=True)
            raise AssertionError("unreadable output overwritten")
        except PermissionError:
            pass
    assert output.read_bytes() == old_bytes
    output.write_bytes(b"\xff")
    try:
        d.write_disclosed_patterns(target, data, no_mcp=True)
        raise AssertionError("invalid UTF-8 overwritten")
    except ValueError as error:
        assert "UTF-8" in str(error)
    assert output.read_bytes() == b"\xff"
    output.write_bytes(old_bytes)
    with patch.object(d, "write_text_atomic", side_effect=OSError("synthetic publication failure")):
        try:
            d.write_disclosed_patterns(target, data, no_mcp=True)
            raise AssertionError("publication failure hidden")
        except OSError:
            pass
    assert output.read_bytes() == old_bytes
    custom = data / "custom notes.md"
    custom.write_bytes(first.encode())
    custom.with_suffix(".readings.md").write_text("independent custom notes")
    d.write_disclosed_patterns(target, data, output_path=custom, no_mcp=True)
    assert first.encode() in custom.read_bytes() and "custom%20notes.readings.md" in custom.read_text()
    assert output.read_bytes() == old_bytes
    assert not list(data.rglob("metadata.sqlite3"))
    return ["vertical quota and normalization", "same-industry/legacy cache reuse", "cross-industry failure and partial isolation",
            "strict legacy-cache health", "CRLF/fenced legacy readings and independent notes", "no-mcp and custom output",
            "read/decode/publication failure preserves existing bytes"]


def check_cli(root: Path, data: Path) -> list[str]:
    environment = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    provider = root / "mcp/hackerone-mcp/server.py"
    provider.parent.mkdir(parents=True)
    provider.write_text("from pathlib import Path\nimport json\ndef search_disclosed_reports(**kwargs):\n"
                        "    with (Path(__file__).parents[2] / 'provider-calls.jsonl').open('a') as f: f.write(json.dumps(kwargs)+'\\n')\n"
                        "    return [{'title':'CLI fixture','url':'https://example.invalid/report','program':'peer'}]\n")
    command = [sys.executable, "-B", "tools/disclosure_search.py", "--repo-root", str(data), "--target", "cli.test", "--vertical", "finance"]
    result = subprocess.run(command, cwd=root, env=environment, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0 and "disclosed_patterns written:" in result.stdout, result.stderr
    calls = [json.loads(line) for line in (root / "provider-calls.jsonl").read_text().splitlines()]
    assert any(call.get("keyword") == "finance" for call in calls)
    output = data / "evidence/cli.test/disclosed_patterns.md"
    output.write_bytes(b"\xff")
    invalid = subprocess.run(command + ["--no-mcp"], cwd=root, env=environment, text=True, capture_output=True, timeout=10)
    assert invalid.returncode == 2 and "disclosed_patterns written:" not in invalid.stdout and output.read_bytes() == b"\xff"
    help_result = subprocess.run([sys.executable, "-B", "tools/coverage_matrix.py", "find-gaps", "--help"], cwd=root,
                                 env=environment, text=True, capture_output=True, timeout=10)
    assert help_result.returncode == 0 and "--limit" in help_result.stdout and "--all" not in help_result.stdout, help_result.stderr
    return ["real disclosure CLI/provider vertical handoff", "CLI invalid output exit 2 without success", "real find-gaps help matches documentation"]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ccst-entry-check-") as directory:
        root = Path(directory) / "source"
        root.mkdir()
        sources = subprocess.check_output(["git", "ls-files", "-z", "--", "tools", "memory", "commands", "agents", "skills", "rules", "docs", "CLAUDE.md", "README.md"], cwd=REPO).decode().split("\0")
        for relative in filter(None, sources):
            if relative.startswith(("tools/", "memory/")) and not relative.endswith(".py"):
                continue
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((REPO / relative).read_bytes())
        sys.path.insert(0, str(root))
        docs = check_documents(root)
        tree = ast.parse((root / "tools/surface.py").read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_surface_options")
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "surface_options", "exec"), namespace)
        options = namespace["_surface_options"]({"stats": {"review_pool": 10}, "recon_artifacts": {"counts": {"browser_xhr_urls": 1}}}, "fixture.test")
        assert any("surface pool" in option for option in options) and any("XHR/API" in option for option in options)
        assert all("chain-builder" not in option for option in options)
        data = Path(directory) / "data"
        cases = check_disclosure(root, data)
        cases += check_cli(root, Path(directory) / "cli-data")
    result = {"status": "passed", "baseline": BASELINE, "documents": docs, "cases": cases,
              "surface": "review remains available without count-driven chain delegation", "scope": "isolated source and synthetic inputs; no model/host acceptance"}
    (Path(__file__).parent / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
