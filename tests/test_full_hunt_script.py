"""Regression tests for scripts/full_hunt.sh auth-aware plumbing."""

import subprocess
from pathlib import Path


def test_full_hunt_bash_syntax_is_valid():
    script = Path(__file__).resolve().parent.parent / "scripts" / "full_hunt.sh"

    result = subprocess.run(
        ["bash", "-n", str(script)],
        cwd=script.resolve().parent.parent,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_full_hunt_uses_auth_helper_for_shell_tools():
    script = Path(__file__).resolve().parent.parent / "scripts" / "full_hunt.sh"
    text = script.read_text(encoding="utf-8")

    assert "_auth_helper.sh" in text
    assert 'export BBHUNT_AUTH_HEADERS="$_BB_HEADERS_TMP"' in text
    assert '"${BB_AUTH_ARGS[@]}"' in text
    assert 'httpx -silent "${BB_AUTH_ARGS[@]}"' in text
    assert 'katana -u "$TARGETURL" -d 3 -jc -kf all "${BB_AUTH_ARGS[@]}"' in text
    assert 'ffuf -u "$TARGETURL/FUZZ" -w "$WL_DIRS"' in text
    assert 'nuclei -u "$TARGETURL"' in text
    assert 'curl -sk "$TARGETURL/api/" \\' in text
