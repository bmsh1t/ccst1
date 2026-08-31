"""Direct-only Skills expose a bounded manual execution contract."""

from __future__ import annotations

import re
from pathlib import Path

from tools.context_pack import SKILL_CATALOG, SKILL_PATHS, build_context_pack


REPO_ROOT = Path(__file__).resolve().parents[1]
DIRECT_ONLY = {
    "cicd-security",
    "mobile-pentest",
    "web3-audit",
    "meme-coin-audit",
}
PRIMARY = {
    "bb-methodology",
    "bug-bounty",
    "credential-attack",
    "triage-validation",
    "web2-recon",
    "web2-vuln-classes",
}


def test_direct_only_skills_have_domain_contracts_and_stay_manual(tmp_path):
    for skill_id in DIRECT_ONLY:
        entry = SKILL_CATALOG[skill_id]
        assert entry["route_mode"] == "direct-only"
        text = (REPO_ROOT / entry["path"]).read_text(encoding="utf-8")
        assert "## Direct Execution Contract" in text[:2500]
        for label in ("Entry", "Evidence", "Stop"):
            match = re.search(rf"^- {label}:\s*(.+)$", text, re.MULTILINE)
            assert match and match.group(1).strip(), (skill_id, label)

    assert {
        skill_id
        for skill_id, entry in SKILL_CATALOG.items()
        if entry["route_mode"] == "direct-only"
    } == DIRECT_ONLY
    assert set(SKILL_PATHS) == PRIMARY

    for skill_id in DIRECT_ONLY:
        pack = build_context_pack(tmp_path, target="target.com", focus=f"{skill_id} review")
        assert pack["selected_skill_id"] in PRIMARY
