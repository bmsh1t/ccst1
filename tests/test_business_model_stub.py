"""Tests for tools/business_model_stub.py (task 09-11-ai-capability-roadmap, batch 7 B4).

B4 is a deterministic stub generator: it derives the technology-stack and
observed-endpoint sections from recon artifacts and leaves business-judgment
sections to the AI. The tests pin the contract from the dispatch prompt:

- a target with recon artifacts gets a stub (tech stack, observed endpoints,
  AI-fill markers on judgment sections);
- a target without recon artifacts is rejected (no empty-shell file);
- an existing business_model.md inside the 30-day window is skipped;
- a stale file (> 30 days) is not silently overwritten: it requires an
  explicit --refresh, and --refresh warns that AI-filled sections are lost;
- derivation is pure field-moving: no AI, no semantic inference.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

import business_model_stub
from business_model_stub import generate_stub, main


def _seed_recon(repo: Path, target_key: str) -> None:
    recon_dir = repo / "recon" / target_key
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "http://target.test [200] [9903] [Juicy Shop App]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls").mkdir()
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "http://target.test/rest/basket/1\n"
        "http://target.test/rest/user/login\n"
        "http://target.test/rest/user/reset-password?email=\n"
        "http://target.test/rest/basket/1\n",  # duplicate must not repeat
        encoding="utf-8",
    )


def test_stub_is_generated_from_recon_artifacts(tmp_path: Path) -> None:
    _seed_recon(tmp_path, "target.test")

    result = generate_stub(target="target.test", repo_root=tmp_path)

    assert result["status"] == "generated"
    output = tmp_path / "evidence" / "target.test" / "business_model.md"
    assert output.is_file()
    text = output.read_text(encoding="utf-8")
    # Observed endpoints are carried over verbatim (deduped), no meaning added.
    assert "/rest/basket/1" in text
    assert "/rest/user/login" in text
    assert text.count("/rest/basket/1") == 1  # duplicate collapsed
    # Observed query parameter names are carried over mechanically.
    assert "email" in text
    # Tech stack section exists (inventory had no components -> honest empty).
    assert "## Observed technology stack" in text
    # Judgment sections are explicitly left to the AI.
    assert "## App purpose" in text
    assert "## Crown jewels" in text
    assert "## Trust boundaries" in text
    assert "## Sensitive workflows" in text
    assert "## First hypotheses" in text
    assert text.count("<!-- AI: fill from observed purpose -->") == 5
    # Deterministic derivation note is present.
    assert "deterministically derived" in text.lower()


def test_stub_carries_components_from_inventory(tmp_path: Path) -> None:
    _seed_recon(tmp_path, "target.test")
    # First run builds the inventory from the seeded httpx source.
    generate_stub(target="target.test", repo_root=tmp_path)
    inventory_path = tmp_path / "recon" / "target.test" / "live" / "technology_inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["components"] = [
        {"name": "express", "display_name": "Express", "version": "4.18", "raw_label": "Express:4.18"},
    ]
    # Keep the source binding so load_or_build reuses the updated file.
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")

    result = generate_stub(
        target="target.test", repo_root=tmp_path, force=True
    )

    assert result["status"] == "regenerated_forced"
    text = (tmp_path / "evidence" / "target.test" / "business_model.md").read_text(encoding="utf-8")
    assert "express:4.18" in text


def test_missing_recon_dir_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no recon artifacts"):
        generate_stub(target="nope.test", repo_root=tmp_path)
    assert not (tmp_path / "evidence" / "nope.test" / "business_model.md").exists()


def test_empty_recon_dir_is_rejected(tmp_path: Path) -> None:
    recon_dir = tmp_path / "recon" / "empty.test"
    recon_dir.mkdir(parents=True)

    with pytest.raises(ValueError, match="empty"):
        generate_stub(target="empty.test", repo_root=tmp_path)


def test_fresh_file_inside_30_day_window_is_skipped(tmp_path: Path) -> None:
    _seed_recon(tmp_path, "target.test")
    first = generate_stub(target="target.test", repo_root=tmp_path)
    output = tmp_path / "evidence" / "target.test" / "business_model.md"
    original = output.read_text(encoding="utf-8")

    second = generate_stub(target="target.test", repo_root=tmp_path)

    assert first["status"] == "generated"
    assert second["status"] == "skipped_fresh"
    assert second["age_days"] < 1
    # The fresh file is untouched.
    assert output.read_text(encoding="utf-8") == original


def test_stale_file_requires_explicit_refresh(tmp_path: Path) -> None:
    _seed_recon(tmp_path, "target.test")
    output = tmp_path / "evidence" / "target.test" / "business_model.md"
    generate_stub(target="target.test", repo_root=tmp_path)
    # AI fills the judgment sections after generation.
    filled = output.read_text(encoding="utf-8").replace(
        "<!-- AI: fill from observed purpose -->",
        "AI business judgment written by hand",
    )
    output.write_text(filled, encoding="utf-8")
    # Age the file past the 30-day window.
    stale = time.time() - (31 * 86400)
    os.utime(output, (stale, stale))

    stale_result = generate_stub(target="target.test", repo_root=tmp_path)
    assert stale_result["status"] == "stale_needs_refresh"
    assert stale_result["age_days"] >= 30
    # Stale without --refresh: the AI-filled content is preserved.
    assert "AI business judgment written by hand" in output.read_text(encoding="utf-8")

    refreshed = generate_stub(target="target.test", repo_root=tmp_path, refresh=True)
    assert refreshed["status"] == "refreshed"
    assert "warning" in refreshed
    # The documented degradation: refresh overwrites, AI-filled text is lost.
    refreshed_text = output.read_text(encoding="utf-8")
    assert "AI business judgment written by hand" not in refreshed_text
    assert "<!-- AI: fill from observed purpose -->" in refreshed_text


def test_cli_reports_errors_and_json(tmp_path: Path, capsys) -> None:
    rc = main(["--target", "nope.test", "--repo-root", str(tmp_path), "--json"])
    assert rc == 2
    assert "no recon artifacts" in capsys.readouterr().err

    _seed_recon(tmp_path, "target.test")
    rc = main(["--target", "target.test", "--repo-root", str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "generated"
    assert payload["endpoint_count"] == 3


def test_endpoint_input_is_bounded(tmp_path: Path) -> None:
    recon_dir = tmp_path / "recon" / "flood.test"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "http://flood.test [200] [1] [Flood]\n", encoding="utf-8"
    )
    (recon_dir / "urls").mkdir()
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "".join(f"http://flood.test/api/endpoint-{i}\n" for i in range(1000)),
        encoding="utf-8",
    )

    result = generate_stub(target="flood.test", repo_root=tmp_path)

    assert result["status"] == "generated"
    assert result["endpoint_count"] == business_model_stub.MAX_ENDPOINT_LINES
