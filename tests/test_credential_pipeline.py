"""Credential candidate pool 和 HIBP 审阅排序回归。"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tools.breach_checker import bucket_for_count, rank_results


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_hibp_review_order_preserves_target_relevance_inside_buckets():
    passwords = ["brand-zero", "sweet-first", "unknown", "sweet-second", "common"]
    results = {
        "brand-zero": 0,
        "sweet-first": 3,
        "unknown": -1,
        "sweet-second": 500,
        "common": 5000,
    }

    assert rank_results(passwords, results) == [
        ("sweet-first", 3),
        ("sweet-second", 500),
        ("brand-zero", 0),
        ("unknown", -1),
        ("common", 5000),
    ]
    assert bucket_for_count(-1) == "unknown"
    assert bucket_for_count(0) == "zero"
    assert bucket_for_count(1000) == "sweet"
    assert bucket_for_count(1001) == "common"


def test_wordlist_engine_uses_installed_tool_overrides_and_stable_source_order(tmp_path: Path):
    bin_dir = tmp_path / "bin"
    rules = tmp_path / "rules"
    bin_dir.mkdir()
    rules.mkdir()
    (rules / "best66.rule").write_text(":\n", encoding="utf-8")

    cewler = bin_dir / "cewler"
    hashcat = bin_dir / "hashcat.bin"
    pydictor = bin_dir / "pydictor.py"
    _write_executable(
        cewler,
        """#!/bin/bash
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf 'product\nportal\nproduct\n' > "$out"
""",
    )
    _write_executable(
        hashcat,
        """#!/bin/bash
printf 'product2026\nportal2026\nproduct2026\n'
""",
    )
    _write_executable(
        pydictor,
        """#!/usr/bin/env python3
import pathlib, sys
out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
out.mkdir(parents=True, exist_ok=True)
(out / 'result.txt').write_text(chr(10).join(['acmecorp2026', 'product']) + chr(10))
""",
    )

    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.update(
        {
            "CEWLER_BIN": str(cewler),
            "HASHCAT_BIN": str(hashcat),
            "PYDICTOR_BIN": str(pydictor),
            "HASHCAT_RULES_DIR": str(rules),
        }
    )
    completed = subprocess.run(
        [str(root / "tools" / "wordlist_engine.sh"), "acmecorp.test"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    out_dir = tmp_path / "recon" / "acmecorp.test" / "wordlists"
    assert (out_dir / "candidate-pool.txt").read_text(encoding="utf-8").splitlines() == [
        "acmecorp2026",
        "product",
        "portal",
        "product2026",
        "portal2026",
    ]
    assert (out_dir / "ranked.txt").read_bytes() == (out_dir / "candidate-pool.txt").read_bytes()


def test_wordlist_engine_degrades_to_brand_source(tmp_path: Path):
    pydictor = tmp_path / "pydictor.py"
    _write_executable(
        pydictor,
        """#!/usr/bin/env python3
import pathlib, sys
out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
out.mkdir(parents=True, exist_ok=True)
(out / 'result.txt').write_text('acmecorp2026' + chr(10))
""",
    )
    root = Path(__file__).resolve().parents[1]
    env = {
        **os.environ,
        "PATH": "/usr/bin:/bin",
        "PYDICTOR_BIN": str(pydictor),
        "HOME": str(tmp_path / "home"),
    }

    completed = subprocess.run(
        [str(root / "tools" / "wordlist_engine.sh"), "acmecorp.test"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    pool = tmp_path / "recon" / "acmecorp.test" / "wordlists" / "candidate-pool.txt"
    assert pool.read_text(encoding="utf-8").splitlines() == ["acmecorp2026"]


def test_credential_handoff_never_uses_candidate_pool_as_live_input():
    root = Path(__file__).resolve().parents[1]
    agent = (root / "agents" / "credential-hunter.md").read_text(encoding="utf-8")
    osint = (root / "tools" / "osint_employees.sh").read_text(encoding="utf-8")

    assert "spray-shortlist.txt" in agent
    assert "known_users_file" in agent
    assert "candidate-pool.txt`、`ranked.txt`" in agent
    assert "$HOME/Tools/username-anarchy/username-anarchy" in osint
    assert "$HOME/Tools/pydictor/pydictor.py" in osint


def test_osint_uses_canonical_target_key_for_url_targets(tmp_path: Path):
    harvester = tmp_path / "theHarvester"
    username_anarchy = tmp_path / "username-anarchy"
    _write_executable(
        harvester,
        """#!/usr/bin/env python3
import json, pathlib, sys
name = sys.argv[sys.argv.index('-f') + 1]
pathlib.Path(name + '.json').write_text(json.dumps({'emails': ['alice.smith@acmecorp.test']}))
""",
    )
    _write_executable(username_anarchy, "#!/bin/bash\nprintf 'alice.smith\\n'\n")
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [str(root / "tools" / "osint_employees.sh"), "https://www.acmecorp.test:8443/login"],
        cwd=tmp_path,
        env={
            **os.environ,
            "THEHARVESTER_BIN": str(harvester),
            "USERNAME_ANARCHY_BIN": str(username_anarchy),
            "HOME": str(tmp_path / "home"),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    out_dir = tmp_path / "recon" / "www.acmecorp.test:8443" / "osint"
    assert (out_dir / "emails.txt").read_text(encoding="utf-8").strip() == "alice.smith@acmecorp.test"
    assert (out_dir / "usernames.txt").read_text(encoding="utf-8").strip() == "alice.smith"


def test_hibp_cli_rejects_unbounded_numeric_arguments(tmp_path: Path):
    wordlist = tmp_path / "candidate.txt"
    wordlist.write_text("Secret#1\n", encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        ["python3", str(root / "tools" / "breach_checker.py"), str(wordlist), "--concurrent", "0"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "positive integer" in completed.stderr


def test_wordlist_engine_fails_when_every_source_is_empty(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [str(root / "tools" / "wordlist_engine.sh"), "x.io"],
        cwd=tmp_path,
        env={**os.environ, "PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "home")},
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "all candidate sources are empty" in completed.stderr
