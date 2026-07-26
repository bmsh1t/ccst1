"""Read-only external tool diagnostic contract."""

from __future__ import annotations

import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "external_arsenal.sh"
CORE_TOOLS = ("subfinder", "httpx", "katana", "gau", "waybackurls", "ffuf", "nuclei", "curl")


def _fake_tools(tmp_path: Path) -> dict[str, str]:
    bin_dir = tmp_path / "go" / "bin"
    bin_dir.mkdir(parents=True)
    script = "#!/bin/sh\nprintf '%s %s\\n' \"${0##*/}\" \"${1:-}\"\n"
    for tool in CORE_TOOLS:
        path = bin_dir / tool
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
    return {
        "HOME": str(tmp_path),
        "PATH": str(bin_dir),
        "LC_ALL": "C",
    }


def test_core_version_smoke_uses_only_known_read_only_flags(tmp_path):
    result = subprocess.run(
        ["/bin/bash", str(SCRIPT), "--versions"],
        text=True,
        capture_output=True,
        env=_fake_tools(tmp_path),
        check=False,
    )

    assert result.returncode == 0
    assert "subfinder" in result.stdout and "subfinder -version" in result.stdout
    assert "gau" in result.stdout and "gau --version" in result.stdout
    assert "ffuf" in result.stdout and "ffuf -V" in result.stdout
    assert "waybackurls" in result.stdout and "UNSUPPORTED" in result.stdout


def test_single_version_smoke_reports_missing_without_installing(tmp_path):
    env = {"HOME": str(tmp_path), "PATH": str(tmp_path / "empty"), "LC_ALL": "C"}

    result = subprocess.run(
        ["/bin/bash", str(SCRIPT), "--version", "definitely-missing-tool"],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert result.returncode == 1
    assert "definitely-missing-tool" in result.stdout
    assert "MISSING" in result.stdout
    assert not (tmp_path / "go").exists()
