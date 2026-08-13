import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from telerik_knownkey import match_telerik_response


BADSECRETS_KEY = "PrivateKeyForHashOfUploadConfiguration"
BADSECRETS_SIGNED_DIALOG_PARAMETERS = "QXN5bmNVcGxvYWQ=cm9ZGMxl1f9VzD8sb7UpaCvTtMqORlOzfOsoWfeEbsc="
ASPNET_MACHINE_KEY = "0000000000000000000000000000000000000000"
ASPNET_MACHINE_SIGNED_DIALOG_PARAMETERS = "QXN5bmNVcGxvYWQ=zrrq03LykcwiF34IA2+Vh8iHX2juCoVeNt+1cOPCPJM="


def test_match_uses_vendored_badsecrets_key_sources_without_returning_the_key():
    result = match_telerik_response(json.dumps({"SerializedParameters": BADSECRETS_SIGNED_DIALOG_PARAMETERS}))

    assert result["matcher"] == "vendored-badsecrets.telerik_hashkey"
    assert result["key_sources"] == ["aspnet_machinekeys.txt", "telerik_hash_keys.txt"]
    assert result["network_requests"] == 0
    assert result["queue_actions"] == 0
    assert result["matches"] == [{
        "serialized_parameters_index": 0,
        "key_fingerprint": hashlib.sha256(BADSECRETS_KEY.encode("utf-8")).hexdigest(),
    }]
    assert BADSECRETS_KEY not in str(result)


def test_match_uses_vendored_aspnet_machine_key_list():
    result = match_telerik_response(json.dumps({"SerializedParameters": ASPNET_MACHINE_SIGNED_DIALOG_PARAMETERS}))

    assert result["matches"] == [{
        "serialized_parameters_index": 0,
        "key_fingerprint": hashlib.sha256(ASPNET_MACHINE_KEY.encode("utf-8")).hexdigest(),
    }]


def test_match_rejects_invalid_values_and_bounds_captured_values():
    assert match_telerik_response('{"SerializedParameters":"not-a-telerik-value"}')["matches"] == []
    with pytest.raises(ValueError, match="max_values"):
        match_telerik_response("", max_values=9)


def test_cli_matches_captured_file_without_accepting_a_target_or_key_file(tmp_path):
    body_file = tmp_path / "captured.html"
    body_file.write_text(json.dumps({"SerializedParameters": BADSECRETS_SIGNED_DIALOG_PARAMETERS}), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).parents[1] / "tools" / "telerik_knownkey.py"),
            "--body-file", str(body_file),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    result = json.loads(completed.stdout)
    assert result["network_requests"] == 0
    assert result["queue_actions"] == 0
    assert len(result["matches"]) == 1
