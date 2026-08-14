import hashlib
import json
import subprocess
import sys
from pathlib import Path

from aspnet_viewstate_knownkey import match_aspnet_viewstate_response


VALIDATION_KEY = "0074D9E5776602E629B362073918A43AD0D631800111D0453DB3416D3827C95B81F575B388A6B425E39AC49BCDC2DC8A57AD2207DC726E78544525A83AB4FE08"
SIGNED_VIEWSTATE = "/wEPDwUJODc0MjgwMjkwZGTCdzCrBtl0AFYdKsWX1bQ8DcMilw=="
MAC_DISABLED_VIEWSTATE = "/wEPDwUJODc0MjgwMjkwZGQ="
PAGE_URL = "http://TARGET/default2.aspx"
GENERATOR = "9BD98A7D"


def _body(viewstate: str) -> str:
    return (
        f'<input type="hidden" name="__VIEWSTATE" value="{viewstate}" />'
        f'<input type="hidden" name="__VIEWSTATEGENERATOR" value="{GENERATOR}" />'
    )


def test_match_uses_project_machine_keys_without_returning_key_by_default():
    result = match_aspnet_viewstate_response(_body(SIGNED_VIEWSTATE), page_url=PAGE_URL)

    assert result["matcher"] == "badsecrets.ASPNET_Viewstate"
    assert result["machine_key_records"] == 7436
    assert result["validation_keys"] == 7427
    assert result["complete_key_pairs"] == 7419
    assert result["keys_revealed"] is False
    assert result["network_requests"] == 0
    assert result["queue_actions"] == 0
    assert result["matches"] == [{
        "viewstate_index": 0,
        "kind": "known-machine-key",
        "machine_key_line": 14,
        "validation_key_fingerprint": hashlib.sha256(VALIDATION_KEY.encode("ascii")).hexdigest(),
        "validation_algorithm": "SHA1",
        "framework_mode": "DOTNET40",
    }]
    assert VALIDATION_KEY not in str(result)


def test_explicit_reveal_returns_key_for_controlled_validation():
    result = match_aspnet_viewstate_response(
        _body(SIGNED_VIEWSTATE),
        page_url=PAGE_URL,
        reveal_keys=True,
    )

    assert result["keys_revealed"] is True
    assert result["matches"][0]["validation_key"] == VALIDATION_KEY


def test_match_distinguishes_mac_disabled_from_known_key():
    result = match_aspnet_viewstate_response(_body(MAC_DISABLED_VIEWSTATE), page_url=PAGE_URL)

    assert result["matches"] == [{"viewstate_index": 0, "kind": "mac-disabled"}]


def test_cli_reads_captured_body_without_network_or_state_write(tmp_path):
    body_file = tmp_path / "captured.html"
    body_file.write_text(_body(SIGNED_VIEWSTATE), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).parents[1] / "tools" / "aspnet_viewstate_knownkey.py"),
            "--body-file", str(body_file),
            "--page-url", PAGE_URL,
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    result = json.loads(completed.stdout)
    assert result["network_requests"] == 0
    assert result["queue_actions"] == 0
    assert len(result["matches"]) == 1
    assert VALIDATION_KEY not in completed.stdout

    revealed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).parents[1] / "tools" / "aspnet_viewstate_knownkey.py"),
            "--body-file", str(body_file),
            "--page-url", PAGE_URL,
            "--reveal-key",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(revealed.stdout)["matches"][0]["validation_key"] == VALIDATION_KEY
