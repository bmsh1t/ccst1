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


def test_eburst_is_detected_from_shared_tools_dir_without_installing(tmp_path):
    home = tmp_path / "Tools" / "EBurst"
    home.mkdir(parents=True)
    (home / "EBurst.py").write_text("# fixture\n", encoding="utf-8")
    python2 = tmp_path / "python2"
    python2.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python2.chmod(0o755)
    env = {"HOME": str(tmp_path), "PATH": str(tmp_path), "LC_ALL": "C"}

    result = subprocess.run(
        ["/bin/bash", str(SCRIPT), "--have", "eburst"],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "yes"

    version = subprocess.run(
        ["/bin/bash", str(SCRIPT), "--version", "eburst"],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert version.returncode == 0
    assert "Python 2" in version.stdout
