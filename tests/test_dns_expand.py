"""Tests for the AI-selected DNS expansion lane."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tools.dns_expand import run_dns_expansion


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _executable(path: Path, content: str) -> None:
    _write(path, content)
    path.chmod(0o755)


def _seed(repo: Path, *hosts: str) -> Path:
    path = repo / "recon" / "example.test" / "subdomains" / "all.txt"
    _write(path, "".join(f"{host}\n" for host in hosts))
    return path


def _fake_generators(bin_dir: Path) -> None:
    _executable(
        bin_dir / "alterx",
        "#!/bin/sh\nprintf '%s\\n' dev.example.test api.example.test outside.invalid\n",
    )
    _executable(
        bin_dir / "dnsgen",
        "#!/bin/sh\nprintf '%s\\n' stage.example.test dev.example.test\n",
    )


def _fake_puredns(bin_dir: Path, *, exit_code: int = 0) -> None:
    _executable(
        bin_dir / "puredns",
        f"#!{sys.executable}\n"
        "import sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "resolved = Path(args[args.index('--write') + 1])\n"
        "wildcards = Path(args[args.index('--write-wildcards') + 1])\n"
        "resolved.write_text('dev.example.test\\nstage.example.test\\nsurprise.example.test\\noutside.invalid\\n', encoding='utf-8')\n"
        "wildcards.write_text('wild.example.test\\noutside.invalid\\n', encoding='utf-8')\n"
        f"raise SystemExit({exit_code})\n",
    )


def test_dns_expansion_merges_only_scoped_resolved_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_path = _seed(tmp_path, "example.test", "api.example.test", "outside.invalid")
    bin_dir = tmp_path / "bin"
    _fake_generators(bin_dir)
    _fake_puredns(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    result = run_dns_expansion(
        "example.test",
        reason="passive hosts expose dev/stage naming dialect",
        repo_root=tmp_path,
    )

    assert result["status"] == "ok"
    assert result["counts"] == {
        "available_seeds": 2,
        "selected_seeds": 2,
        "candidates": 2,
        "resolved": 2,
        "wildcards": 1,
        "new_all_hosts": 2,
        "new_resolved_hosts": 2,
    }
    assert seed_path.read_text(encoding="utf-8").splitlines() == [
        "api.example.test",
        "dev.example.test",
        "example.test",
        "stage.example.test",
    ]
    resolved_path = seed_path.parent / "resolved.txt"
    assert resolved_path.read_text(encoding="utf-8").splitlines() == [
        "dev.example.test",
        "stage.example.test",
    ]
    manifest_path = seed_path.parent / "dns-expansion" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["trigger_reason"] == "passive hosts expose dev/stage naming dialect"
    assert manifest["status"] == "ok"
    assert "outside.invalid" not in (seed_path.parent / "dns-expansion" / "resolved.txt").read_text(
        encoding="utf-8"
    )
    assert "surprise.example.test" not in seed_path.read_text(encoding="utf-8")


def test_missing_puredns_preserves_candidates_without_merging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_path = _seed(tmp_path, "example.test", "api.example.test")
    original = seed_path.read_bytes()
    bin_dir = tmp_path / "bin"
    _fake_generators(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    result = run_dns_expansion(
        "example.test",
        reason="environment labels suggest sibling hosts",
        repo_root=tmp_path,
    )

    assert result["status"] == "unavailable"
    assert result["tools"]["puredns"]["status"] == "missing"
    assert result["counts"]["candidates"] == 2
    assert seed_path.read_bytes() == original
    assert not (seed_path.parent / "resolved.txt").exists()


def test_failed_resolution_clears_stale_lane_output_and_does_not_merge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_path = _seed(tmp_path, "example.test", "api.example.test")
    original = seed_path.read_bytes()
    stale = seed_path.parent / "dns-expansion" / "resolved.txt"
    _write(stale, "stale.example.test\n")
    bin_dir = tmp_path / "bin"
    _fake_generators(bin_dir)
    _fake_puredns(bin_dir, exit_code=7)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    result = run_dns_expansion(
        "example.test",
        reason="passive inventory is sparse",
        repo_root=tmp_path,
    )

    assert result["status"] == "error"
    assert result["tools"]["puredns"]["returncode"] == 7
    assert result["failure_summary"] == "puredns error; no hosts were merged"
    assert seed_path.read_bytes() == original
    assert not stale.exists()


def test_explicit_wordlist_works_without_permutation_generators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed_path = _seed(tmp_path, "example.test")
    wordlist = tmp_path / "dns-words.txt"
    _write(wordlist, "dev\nstage\noutside.invalid\n")
    bin_dir = tmp_path / "bin"
    _fake_puredns(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    result = run_dns_expansion(
        "example.test",
        reason="AI selected a reviewed environment wordlist",
        wordlist=str(wordlist),
        max_candidates=2,
        repo_root=tmp_path,
    )

    assert result["status"] == "ok"
    assert result["source_counts"] == {"wordlist": 2}
    assert result["tools"]["alterx"]["status"] == "missing"
    assert result["tools"]["dnsgen"]["status"] == "missing"
    assert (seed_path.parent / "dns-expansion" / "candidates.txt").read_text(
        encoding="utf-8"
    ).splitlines() == ["dev.example.test", "stage.example.test"]


@pytest.mark.parametrize(
    ("target", "reason", "message"),
    [
        ("127.0.0.1", "sparse", "requires one domain"),
        ("example.test", "", "trigger reason is required"),
    ],
)
def test_dns_expansion_rejects_invalid_invocation(
    tmp_path: Path, target: str, reason: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        run_dns_expansion(target, reason=reason, repo_root=tmp_path)


def test_dns_expansion_is_routed_as_an_ai_selected_non_baseline_lane() -> None:
    repo = Path(__file__).resolve().parents[1]
    recon_command = (repo / "commands" / "recon.md").read_text(encoding="utf-8")
    autopilot_command = (repo / "commands" / "autopilot.md").read_text(encoding="utf-8")
    skill = (repo / "skills" / "web2-recon" / "SKILL.md").read_text(encoding="utf-8")

    for text in (recon_command, autopilot_command, skill):
        assert "tools/dns_expand.py" in text
        assert "--reason" in text
    assert "not a default Recon phase" in recon_command
    assert "host count alone is not a trigger" in " ".join(autopilot_command.split())
