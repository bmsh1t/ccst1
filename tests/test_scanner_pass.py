from __future__ import annotations

import json

from tools.coverage_matrix import rebuild_matrix
from tools.scanner_pass_writer import write_scanner_pass
from tools.target_store import TargetStore


def _scanner_fixture(tmp_path, target="scanner-primary.test"):
    findings = tmp_path / "findings" / target
    recon = tmp_path / "recon" / target
    (findings / "sqli").mkdir(parents=True)
    (recon / "urls").mkdir(parents=True)
    (recon / "urls" / "all.txt").write_text(
        f"https://{target}/search?q=1\n", encoding="utf-8"
    )
    return findings, recon


def test_scanner_pass_is_advisory_and_empty_categories_are_not_runs(tmp_path):
    TargetStore(tmp_path, "scanner-primary.test").initialize()
    findings, recon = _scanner_fixture(tmp_path)
    output = write_scanner_pass(
        target="scanner-primary.test", findings_dir=findings, recon_dir=recon
    )
    assert json.loads(output.read_text(encoding="utf-8"))["endpoints"] == []

    (findings / "sqli" / "result.txt").write_text("scanner lead\n", encoding="utf-8")
    write_scanner_pass(target="scanner-primary.test", findings_dir=findings, recon_dir=recon)
    matrix = rebuild_matrix("scanner-primary.test", repo_root=tmp_path)
    cell = matrix["endpoints"][0]["cells"]["SQLi"]
    assert cell["status"] == "untested"
    assert cell["scanner_swept"] is True


def test_scanner_pass_writer_is_not_a_primary_domain_writer(tmp_path):
    target = "scanner-primary.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    findings, recon = _scanner_fixture(tmp_path, target)
    before = store.context(limit=1)["revision"]

    write_scanner_pass(target=target, findings_dir=findings, recon_dir=recon)

    assert store.context(limit=1)["revision"] == before
    assert store.context(limit=1)["counts"] == {
        "actions": 0, "attempts": 0, "operations": 0, "findings": 0, "experiences": 0
    }
