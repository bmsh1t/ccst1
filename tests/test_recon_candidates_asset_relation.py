"""Asset-relation scope review classification.

Covers the ownership-evidence routing published in skills/web2-recon/SKILL.md
and docs/autopilot-lanes.md: a third-party-hosted host/service with multiple
page/behavioral/brand evidence points is recorded at confidence:high with
multiple sources so it routes to scope-review. Ownership evidence never
expands authorization — the gate is only the forced in-scope/external/excluded
decision, which surfaces as an asset-scope-review lead.
"""

import json

from tools.recon_candidates import build_recon_candidates
from tools.runtime_state import inspect_recon_artifacts
from tools.surface import _build_exposure_lead_hints


def _write_obs(path, asset_type, value, relation, related, source, source_ref, confidence):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "asset-relation-observation",
                    "asset_type": asset_type,
                    "value": value,
                    "relation": relation,
                    "related": related,
                    "signals": ["login-form"],
                    "source": source,
                    "source_ref": source_ref,
                    "confidence": confidence,
                },
                ensure_ascii=False,
            )
            + "\n"
        )


def _candidates(recon_dir):
    return [
        json.loads(line)
        for line in (recon_dir / "exposure" / "asset_relation_candidates.jsonl")
        .read_text(encoding="utf-8")
        .strip()
        .splitlines()
    ]


def test_multi_evidence_ownership_routes_to_scope_review(tmp_path):
    recon = tmp_path / "recon" / "tarj.com"
    (recon / "live").mkdir(parents=True)
    obs = recon / "exposure" / "asset_relation_observations.jsonl"
    obs.parent.mkdir(exist_ok=True)

    # 三个不同 evidence point (page/behavioral/brand), 各自独立 source
    for source, source_ref in (
        ("page-evidence", "./a.html"),
        ("behavioral-evidence", "./b.html"),
        ("brand-evidence", "./c.html"),
    ):
        _write_obs(
            obs, "domain", "tarj.hooo.com", "affiliate", ["tarj.com"],
            source, source_ref, "high",
        )

    payload = build_recon_candidates(tmp_path, "tarj.com", asset_input=obs)

    candidates = _candidates(recon)
    assert len(candidates) == 1
    row = candidates[0]
    assert row["scope_status"] == "scope-review"
    assert row["confidence"] == "high"
    assert len(row["sources"]) == 3
    assert payload["asset_scope_review_pending"] == 1
    assert payload["asset_scope_status_counts"] == {"scope-review": 1}


def test_scope_review_requires_high_confidence_and_multiple_sources(tmp_path):
    recon = tmp_path / "recon" / "tarj.com"
    (recon / "live").mkdir(parents=True)
    obs = recon / "exposure" / "asset_relation_observations.jsonl"
    obs.parent.mkdir(exist_ok=True)

    # 高置信 + 多来源 -> scope-review
    for source, source_ref in (
        ("page-evidence", "./a.html"),
        ("brand-evidence", "./c.html"),
    ):
        _write_obs(obs, "domain", "tarj.ok.com", "affiliate", ["tarj.com"],
                   source, source_ref, "high")
    # 低置信 + 多来源 -> 不进 scope-review
    for source, source_ref in (
        ("page-evidence", "./d.html"),
        ("brand-evidence", "./e.html"),
    ):
        _write_obs(obs, "domain", "tarj.low.com", "affiliate", ["tarj.com"],
                   source, source_ref, "low")
    # 高置信 + 单来源 -> 不进 scope-review
    _write_obs(obs, "domain", "tarj.single.com", "affiliate", ["tarj.com"],
               "page-evidence", "./f.html", "high")

    build_recon_candidates(tmp_path, "tarj.com", asset_input=obs)
    by_value = {row["value"]: row for row in _candidates(recon)}

    assert by_value["tarj.ok.com"]["scope_status"] == "scope-review"
    assert by_value["tarj.low.com"]["scope_status"] == "external-chain-context"
    assert by_value["tarj.single.com"]["scope_status"] == "external-chain-context"


def test_scope_review_requires_target_linked_related(tmp_path):
    recon = tmp_path / "recon" / "tarj.com"
    (recon / "live").mkdir(parents=True)
    obs = recon / "exposure" / "asset_relation_observations.jsonl"
    obs.parent.mkdir(exist_ok=True)

    # 高置信 + 多来源, 但 related 不含主目标 -> 只是 external context
    for source, source_ref in (
        ("page-evidence", "./a.html"),
        ("brand-evidence", "./c.html"),
    ):
        _write_obs(obs, "domain", "other.svc.com", "affiliate", ["other.org"],
                   source, source_ref, "high")

    build_recon_candidates(tmp_path, "tarj.com", asset_input=obs)
    row = _candidates(recon)[0]
    assert row["scope_status"] == "external-chain-context"
    assert row["scope_reason"] != ""


def test_scope_review_projects_surface_lead(tmp_path):
    recon = tmp_path / "recon" / "tarj.com"
    (recon / "live").mkdir(parents=True)
    obs = recon / "exposure" / "asset_relation_observations.jsonl"
    obs.parent.mkdir(exist_ok=True)

    for source, source_ref in (
        ("page-evidence", "./a.html"),
        ("behavioral-evidence", "./b.html"),
        ("brand-evidence", "./c.html"),
    ):
        _write_obs(obs, "domain", "tarj.hooo.com", "affiliate", ["tarj.com"],
                   source, source_ref, "high")

    build_recon_candidates(tmp_path, "tarj.com", asset_input=obs)

    artifacts = inspect_recon_artifacts(tmp_path, "tarj.com")
    assert artifacts["asset_relations"]["scope_review_pending"] == 1

    leads = _build_exposure_lead_hints(artifacts, "tarj.com")
    scope_lead = [lead for lead in leads if lead.get("category") == "asset-scope-review"]
    assert len(scope_lead) == 1
    assert "explicit target set" in scope_lead[0]["next_action"]
