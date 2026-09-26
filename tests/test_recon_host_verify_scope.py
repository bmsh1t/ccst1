import json

import pytest

from tools.scope_source import scope_source_path
from tools import recon_host_verify
from tools.scope_context import ScopeContext


def test_host_verification_respects_exclusions_before_probe(tmp_path, monkeypatch):
    target = "target.example"
    context = ScopeContext(
        root_target=target,
        out_of_scope=["admin.target.example", "http://api.target.example:8080"],
    )
    rows = [
        {"value": "admin.target.example", "related": [], "signals": ["cname"]},
        {"value": "api.target.example:8080", "related": [], "signals": ["cname"]},
    ]
    assert [item["hosts"] for item in recon_host_verify.select_candidates(rows, target, context)] == [
        [("api.target.example", 8080)]
    ]
    assert recon_host_verify.select_candidates(
        [{"value": "app.target.example", "related": [], "signals": ["cname"]}], target, context
    )[0]["hosts"] == [("app.target.example", None)]

    recon_dir = tmp_path / "recon" / target
    exposure = recon_dir / "exposure"
    exposure.mkdir(parents=True)
    (exposure / "host_pivot_candidates.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    live = recon_dir / "live"
    live.mkdir()
    (live / "httpx_full.txt").write_text("http://api.target.example:8080\n", encoding="utf-8")
    monkeypatch.setattr(recon_host_verify, "load_scope_context", lambda *_: context)

    def reject_probe(*_args, **_kwargs):
        raise AssertionError("out-of-scope probe")

    monkeypatch.setattr(recon_host_verify, "_probe", reject_probe)

    result = recon_host_verify.verify(tmp_path, target)
    assert result["probe_count"] == 0


def test_invalid_scope_source_fails_without_summary_or_probe(tmp_path, monkeypatch):
    target = "target.example"
    profile = scope_source_path(tmp_path, target)
    profile.parent.mkdir(parents=True, mode=0o700)
    profile.write_text("{broken", encoding="utf-8")
    profile.chmod(0o600)

    def reject_probe(*_args, **_kwargs):
        raise AssertionError("invalid scope reached probe")

    monkeypatch.setattr(recon_host_verify, "_probe", reject_probe)
    with pytest.raises(ValueError, match="invalid scope source"):
        recon_host_verify.verify(tmp_path, target)
    assert not (tmp_path / "recon" / target / recon_host_verify.SUMMARY_PATH).exists()


@pytest.mark.parametrize(
    "profile_target,snapshot,error",
    [
        ("other.example", {"out_of_scope": ["admin.target.example"]}, "target mismatch"),
        ("target.example", {"out_of_scope": "admin.target.example"}, "invalid scope source"),
    ],
)
def test_scope_source_identity_and_shape_are_required(tmp_path, profile_target, snapshot, error):
    target = "target.example"
    profile = scope_source_path(tmp_path, target)
    profile.parent.mkdir(parents=True, mode=0o700)
    profile.write_text(json.dumps({"schema_version": 1, "root_target": profile_target, **snapshot}), encoding="utf-8")
    profile.chmod(0o600)

    with pytest.raises(ValueError, match=error):
        recon_host_verify.verify(tmp_path, target)
    assert not (tmp_path / "recon" / target / recon_host_verify.SUMMARY_PATH).exists()


def test_explicit_port_scope_reaches_only_its_authorized_probe(tmp_path, monkeypatch):
    target = "target.example"
    context = ScopeContext(root_target=target, in_scope=["http://partner.example:8443"])
    exposure = tmp_path / "recon" / target / "exposure"
    exposure.mkdir(parents=True)
    (exposure / "host_pivot_candidates.jsonl").write_text(
        json.dumps({"value": "partner.example:8443", "related": [], "signals": ["cname"]}) + "\n",
        encoding="utf-8",
    )
    live = exposure.parent / "live"
    live.mkdir()
    (live / "httpx_full.txt").write_text(
        "https://partner.example:8443\nhttp://partner.example:8443\n", encoding="utf-8"
    )
    calls = []

    def probe(host, **kwargs):
        calls.append((host, kwargs["scheme"], kwargs["port"]))
        return {"status": 200}

    monkeypatch.setattr(recon_host_verify, "load_scope_context", lambda *_: context)
    monkeypatch.setattr(recon_host_verify, "_probe", probe)
    result = recon_host_verify.verify(tmp_path, target)
    assert result["probe_count"] == 1
    assert calls == [("partner.example", "http", 8443)]
