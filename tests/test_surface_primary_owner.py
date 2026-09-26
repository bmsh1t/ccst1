"""Primary Surface reads current owners even beside retired files."""

import json
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from tools.surface import load_surface_context
from tools.surface_projection import load_surface_projection
from tools.surface_index import SurfaceIndexError, build_surface_index, iter_surface_index, load_surface_index_status, page_surface_index
from tools.target_store import TargetStore

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_primary_surface_ignores_retired_matrix_and_profile(tmp_path):
    target = "surface-owner.test"
    TargetStore(tmp_path, target).initialize()
    (tmp_path / "recon" / target).mkdir(parents=True)
    matrix_path = tmp_path / "evidence" / target / "coverage_matrix.json"
    matrix_path.parent.mkdir(parents=True)
    matrix_path.write_text("{broken", encoding="utf-8")
    memory_dir = tmp_path / "hunt-memory"
    profile_path = memory_dir / "targets" / f"{target}.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text("{broken", encoding="utf-8")

    context = load_surface_context(tmp_path, target, memory_dir=memory_dir)

    assert context["available"] is True
    assert context["profile"] is None
    assert context["coverage_matrix"]["backend"] == "primary"
    assert context["owner_projection"]["backend"] == "primary"


def test_surface_terminal_endpoint_advice_preserves_order_without_history_metadata(tmp_path):
    from tools.surface import _primary_action_queue, _action_queue_final_endpoints

    store = TargetStore(tmp_path, "surface-owner.test")
    store.initialize()
    for index in range(12):
        store.create_action(command_id=f"create-{index}", action_id=f"A-{index:02}", kind="work",
                            subject={"url": f"https://{store.target}/item?owner={index % 2}"},
                            intent="Review endpoint", execution_key=f"review-{index}", actor="operator",
                            metadata={"detail": "Long historical context" * 100})
        if index < 10:
            store.transition_action(command_id=f"close-{index}", action_id=f"A-{index:02}", expected_version=1,
                                    status="blocked" if index == 8 else "cancelled", reason="Recorded result", actor="operator")
    rows = store.final_action_endpoints()
    assert [row["id"] for row in rows] == ["A-08", "A-09"]
    assert all(set(row) == {"id", "endpoint", "status"} for row in rows)
    assert _action_queue_final_endpoints(_primary_action_queue(store)) == {"/item": "n/a"}


@pytest.mark.parametrize("count", [7, 57])
def test_primary_surface_cli_expands_every_indexed_url_from_first_page(tmp_path, count):
    root = tmp_path / "surface data"
    target = "surface-window.test"
    store = TargetStore(root, target)
    store.initialize()
    urls = [f"https://{target}/static/unknown-{i:03}.json" for i in range(count)]
    urls += ["https://external.test/context"]
    source = root / "recon" / target / "urls" / "api_endpoints.txt"
    source.parent.mkdir(parents=True)
    source.write_text("\n".join(urls) + "\n", encoding="utf-8")
    before = store.binding()
    argv = [sys.executable, "-B", "tools/surface.py", "--repo-root", str(root), "--target", target]
    result = subprocess.run([*argv, "--json"], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    surface = json.loads(result.stdout)
    window = surface["surface_index"]["continuation"]
    assert window["available"] is True
    assert window["starts_at"] == "first-page"
    assert window["scope"] == "all-indexed-urls"
    command = shlex.split(window["command"])
    assert "--cursor" not in command
    assert command[command.index("--repo-root") + 1] == str(root)
    projection = json.loads((root / "state" / target / "surface-projection.json").read_text())
    assert projection["surface"]["surface_index"]["continuation"] == window
    review_window = {"order": "url", "total": count, "returned": min(count, 16),
                     "remaining": max(0, count - 16), "limit": 16}
    assert surface["review_window"] == projection["surface"]["review_window"] == review_window
    cached = load_surface_projection(root, target)
    assert cached["status"] == "valid"
    assert cached["surface"]["review_window"] == review_window
    rendered = subprocess.run(argv, cwd=REPO_ROOT, capture_output=True, text=True)
    assert rendered.returncode == 0, rendered.stderr
    assert window["command"] in rendered.stdout

    visited = []
    cursor = ""
    while True:
        page_argv = [*command, "--cursor", cursor] if cursor else command
        page_result = subprocess.run(page_argv, cwd=REPO_ROOT, capture_output=True, text=True)
        assert page_result.returncode == 0, page_result.stderr
        page = json.loads(page_result.stdout)
        assert page["index_revision"] == surface["surface_index"]["index_revision"]
        visited.extend(row["url"] for row in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert sorted(visited) == sorted(urls)
    assert store.binding() == before
    assert source.read_text() == "\n".join(urls) + "\n"


@pytest.mark.parametrize("count", [0, 57])
def test_primary_coverage_cli_windows_expand_without_retired_state(tmp_path, count):
    root = tmp_path / "coverage data"
    target = "coverage-window.test"
    store = TargetStore(root, target)
    store.initialize()
    endpoints = [f"/static/unknown-{i:03}.json" for i in range(count)]
    source = root / "recon" / target / "urls" / "api_endpoints.txt"
    source.parent.mkdir(parents=True)
    source.write_text("\n".join(f"https://{target}{path}" for path in endpoints), encoding="utf-8")
    retired = root / "evidence" / target / "coverage_matrix.json"
    retired.parent.mkdir(parents=True)
    retired.write_text("{broken", encoding="utf-8")
    before = store.binding()

    def query(argv):
        result = subprocess.run(argv, cwd=REPO_ROOT, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    for subcommand in ("needs-triage", "find-gaps"):
        argv = [sys.executable, "-B", "tools/coverage_matrix.py", subcommand,
                "--repo-root", str(root), "--target", target]
        window = query([*argv, "--limit", "5"])
        full = query(shlex.split(window["expand_command"]))
        full_items = full["items"] if subcommand == "needs-triage" else full
        assert window["items"] == full_items[:5]
        assert window["total"] == len(full_items)
        assert window["returned"] + window["remaining"] == len(full_items)
        assert window["truncated"] is (len(full_items) > 5)
        assert {row["endpoint"] for row in full_items} == set(endpoints)
        order = [(row["endpoint"], row.get("vuln_class", "")) for row in full_items]
        assert order == sorted(order)
        invalid = subprocess.run([*argv, "--limit", "-1"], cwd=REPO_ROOT, capture_output=True, text=True)
        assert invalid.returncode == 2

    checkpoint_argv = [sys.executable, "-B", "tools/checkpoint.py", "--repo-root", str(root), "--target", target]
    checkpoint = query([*checkpoint_argv, "--json"])
    coverage = checkpoint["coverage"]
    full_gaps = query(shlex.split(coverage["window"]["expand_command"]))
    assert coverage["high_value_gaps"] == full_gaps[:10]
    assert coverage["window"]["total"] == len(full_gaps)
    text = subprocess.run(checkpoint_argv, cwd=REPO_ROOT, capture_output=True, text=True)
    assert text.returncode == 0, text.stderr
    assert coverage["window"]["expand_command"] in text.stdout
    assert store.binding() == before
    assert retired.read_text() == "{broken"
    assert not (root / "state" / target / "checkpoint_latest.json").exists()


def test_primary_surface_index_binds_store_claims_and_raw_sources(tmp_path):
    from tools.coverage_matrix import read_matrix

    target = "index-owner.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    raw = tmp_path / "recon" / target / "urls" / "api_endpoints.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text(f"https://{target}/api-only\n")
    retired = tmp_path / "findings" / target / "findings.json"
    retired.parent.mkdir(parents=True)
    retired.write_text(json.dumps([{"url": f"https://{target}/retired-only"}]))
    store.create_finding(command_id="first", finding_id="F-1", title="Recorded claim",
                         claim="Unassessed", endpoint=f"https://{target}/current-only",
                         method="GET", family="custom", actor="operator")
    matrix = read_matrix(target, tmp_path, current_only=True, as_of="2026-09-24T00:00:00Z")
    assert {row["endpoint"] for row in matrix["endpoints"]} == {"/api-only", "/current-only"}
    raw.write_text(f"https://{target}/api-new\n")
    changed = read_matrix(target, tmp_path, current_only=True, as_of=matrix["as_of"])
    assert changed["source_fingerprint"] != matrix["source_fingerprint"]

    build_surface_index(tmp_path, target)
    assert {row["url"] for row in iter_surface_index(tmp_path, target)} == {
        f"https://{target}/api-new", f"https://{target}/current-only",
    }
    page = page_surface_index(tmp_path, target, limit=1)
    retired.write_text("{broken")
    assert load_surface_index_status(tmp_path, target)["status"] == "valid"
    store.create_finding(command_id="second", finding_id="F-2", title="New claim",
                         claim="Unassessed", endpoint=f"https://{target}/new-claim",
                         method="GET", family="custom", actor="operator")
    assert load_surface_index_status(tmp_path, target)["status"] == "stale"
    with pytest.raises(SurfaceIndexError):
        page_surface_index(tmp_path, target, cursor=page["next_cursor"])
    build_surface_index(tmp_path, target)
    assert {row["url"] for row in iter_surface_index(tmp_path, target)} == {
        f"https://{target}/api-new", f"https://{target}/current-only", f"https://{target}/new-claim",
    }


@pytest.mark.parametrize("count", [0, 57])
def test_primary_pickup_preserves_surface_and_coverage_expansions(tmp_path, count):
    root = tmp_path / "pickup data"
    target = "pickup-window.test"
    store = TargetStore(root, target)
    store.initialize()
    urls = [f"https://{target}/unclassified-{i:03}" for i in range(count)]
    if count:
        urls.append("https://external.test/context")
    source = root / "recon" / target / "urls" / "api_endpoints.txt"
    source.parent.mkdir(parents=True)
    source.write_text("\n".join(urls), encoding="utf-8")
    build_surface_index(root, target)
    binding = store.binding()

    def run(argv):
        result = subprocess.run(argv, cwd=REPO_ROOT, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    for tool in ("context_pack", "checkpoint", "resume"):
        argv = [sys.executable, "-B", f"tools/{tool}.py", "--repo-root", str(root), "--target", target]
        payload = json.loads(run([*argv, "--json"]))
        container = payload
        if tool == "checkpoint":
            container = payload["context_pack"]
        elif tool == "resume":
            container = payload["summary"]["checkpoint"]
        queries = container["source_queries"]
        surface = queries["surface"]
        assert surface["row_count"] == len(urls)
        assert surface["continuation"]["starts_at"] == "first-page"
        assert surface["continuation"]["scope"] == "all-indexed-urls"
        text = run(argv)
        for command in (surface["continuation"]["command"], queries["coverage"]["command"]):
            assert command in text
            parsed = shlex.split(command)
            assert parsed[parsed.index("--repo-root") + 1] == str(root)
        command = shlex.split(surface["continuation"]["command"])
        seen = []
        cursor = ""
        while True:
            page = json.loads(run(command + (["--cursor", cursor] if cursor else [])))
            assert page["index_revision"] == surface["index_revision"]
            seen.extend(item["url"] for item in page["items"])
            cursor = page["next_cursor"]
            if not cursor:
                break
        assert sorted(seen) == sorted(urls)
        gaps = json.loads(run(shlex.split(queries["coverage"]["command"])))
        assert len(gaps) == queries["coverage"]["total"]
        assert {item["endpoint"] for item in gaps} == {f"/unclassified-{i:03}" for i in range(count)}
    assert store.binding() == binding
    assert source.read_text() == "\n".join(urls)
    assert not (root / "state" / target / "checkpoint_latest.json").exists()
