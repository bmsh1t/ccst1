import json

from tools import recon_host_verify
from tools.scope_context import ScopeContext
from tools.runtime_state import inspect_recon_artifacts
from tools.surface import _build_exposure_lead_hints
from tools.target_paths import target_storage_key


def _fixture(tmp_path, target="target.test"):
    recon = tmp_path / "recon" / target_storage_key(target)
    (recon / "live").mkdir(parents=True)
    (recon / "exposure").mkdir()
    (recon / "live" / "httpx_full.txt").write_text(
        "http://api.target.test [200]\nhttp://admin.target.test [200]\n",
        encoding="utf-8",
    )
    return recon


def _write_candidates(recon, rows):
    (recon / "exposure" / "host_pivot_candidates.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )


def test_verify_probes_scoped_shared_ip_hosts_and_records_difference(tmp_path, monkeypatch):
    recon = _fixture(tmp_path)
    _write_candidates(
        recon,
        [
            {
                "kind": "host-pivot-candidate",
                "value": "192.0.2.10",
                "signals": ["shared-ip"],
                "related": ["api.target.test", "admin.target.test"],
            }
        ],
    )

    def fake_probe(host, **_kwargs):
        return {"status": 200, "content_type": "text/plain", "body_bytes": len(host), "body_sha256": host}

    monkeypatch.setattr(recon_host_verify, "_probe", fake_probe)
    summary = recon_host_verify.verify(tmp_path, "target.test")

    assert summary["status"] == "complete"
    assert summary["selected_count"] == 1
    assert summary["probe_count"] == 2
    assert summary["outcome_counts"] == {"response_difference": 1}
    observations = [
        json.loads(line)
        for line in (recon / "exposure" / "host_collision_observations.jsonl").read_text().splitlines()
    ]
    assert observations[0]["request_mode"] == "hostname-baseline"
    assert {item["host"] for item in observations[0]["probes"]} == {
        "api.target.test",
        "admin.target.test",
    }


def test_verify_keeps_external_related_hosts_inert(tmp_path, monkeypatch):
    recon = _fixture(tmp_path)
    _write_candidates(
        recon,
        [
            {
                "kind": "host-pivot-candidate",
                "value": "api.target.test",
                "signals": ["cname"],
                "related": ["external.example"],
            }
        ],
    )
    calls = []
    monkeypatch.setattr(
        recon_host_verify,
        "_probe",
        lambda host, **kwargs: calls.append((host, kwargs)) or {"status": 200},
    )

    summary = recon_host_verify.verify(tmp_path, "target.test")

    assert summary["probe_count"] == 1
    assert calls == [("api.target.test", {"scheme": "http", "port": None, "timeout": 5.0})]
    assert all("external.example" not in json.dumps(item) for item in calls)


def test_verify_does_not_repeat_same_candidate_on_resume(tmp_path, monkeypatch):
    recon = _fixture(tmp_path)
    _write_candidates(
        recon,
        [
            {
                "kind": "host-pivot-candidate",
                "value": "api.target.test",
                "signals": ["origin-candidate"],
            }
        ],
    )
    calls = []
    monkeypatch.setattr(
        recon_host_verify,
        "_probe",
        lambda host, **_kwargs: calls.append(host) or {"status": 204},
    )

    first = recon_host_verify.verify(tmp_path, "target.test")
    second = recon_host_verify.verify(tmp_path, "target.test")

    assert first["probe_count"] == 1
    assert second["probe_count"] == 0
    assert second["skipped_existing"] == 1
    assert calls == ["api.target.test"]


def test_verify_keeps_network_failure_explicitly_unavailable(tmp_path, monkeypatch):
    recon = _fixture(tmp_path)
    _write_candidates(
        recon,
        [
            {
                "kind": "host-pivot-candidate",
                "value": "api.target.test",
                "signals": ["origin-candidate"],
            }
        ],
    )
    monkeypatch.setattr(recon_host_verify, "_probe", lambda *_args, **_kwargs: {"status": None, "error": "timeout"})

    summary = recon_host_verify.verify(tmp_path, "target.test")

    assert summary["outcome_counts"] == {"unavailable": 1}


def test_verify_ignores_low_signal_and_malformed_candidates(tmp_path, monkeypatch):
    recon = _fixture(tmp_path)
    _write_candidates(
        recon,
        [
            {"value": "api.target.test", "signals": ["unrelated"]},
            {"value": "not a host", "signals": ["shared-ip"]},
        ],
    )
    monkeypatch.setattr(recon_host_verify, "_probe", lambda *_args, **_kwargs: {"status": 200})

    summary = recon_host_verify.verify(tmp_path, "target.test")

    assert summary["selected_count"] == 0
    assert summary["probe_count"] == 0
    assert summary["status"] == "complete"


def test_collision_observations_are_visible_as_soft_surface_signal(tmp_path):
    recon = _fixture(tmp_path)
    observations = recon / "exposure" / "host_collision_observations.jsonl"
    observations.write_text('{"kind":"host-collision-observation"}\n', encoding="utf-8")

    artifacts = inspect_recon_artifacts(tmp_path, "target.test")
    leads = _build_exposure_lead_hints(artifacts, "target.test")

    assert artifacts["counts"]["host_collision_observations"] == 1
    assert artifacts["exposure_paths"]["host_collision_observations"] == (
        "exposure/host_collision_observations.jsonl"
    )
    collision = next(item for item in leads if item["category"] == "host-collision-observation")
    assert collision["priority"] == "high"
    assert "host_collision_observations.jsonl" in collision["artifact"]


def test_verify_uses_explicitly_scoped_ip_as_host_header_control(tmp_path, monkeypatch):
    recon = _fixture(tmp_path)
    _write_candidates(
        recon,
        [
            {
                "kind": "host-pivot-candidate",
                "value": "127.0.0.1",
                "signals": ["shared-ip"],
                "related": ["api.target.test"],
            }
        ],
    )
    monkeypatch.setattr(
        recon_host_verify,
        "_scope_checker",
        lambda *_args: ScopeContext(root_target="target.test", in_scope=["127.0.0.1"]),
    )
    calls = []
    monkeypatch.setattr(
        recon_host_verify,
        "_probe",
        lambda host, **kwargs: calls.append((host, kwargs)) or {"status": 200},
    )

    summary = recon_host_verify.verify(tmp_path, "target.test")

    assert summary["probe_count"] == 2
    assert any(
        host == "api.target.test"
        and kwargs.get("connect_host") == "127.0.0.1"
        and kwargs.get("host_header") == "api.target.test"
        for host, kwargs in calls
    )
