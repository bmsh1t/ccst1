"""大规模 Surface validator 的小型可重复 smoke test。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "skill-validator" / "check_surface_scaling.py"


def test_surface_scaling_validator_preserves_exact_synthetic_index():
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--urls",
            "500",
            "--legacy-inventory-mib",
            "1",
            "--max-finalize-seconds",
            "30",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    payload = json.loads(completed.stdout)
    summary = payload["cold"]["index_summary"]
    assert payload["passed"] is True
    assert summary["source_rows"] == 502
    assert summary["unique_urls"] == 500
    assert summary["exact_duplicates"] == 2
    assert payload["cold"]["tail_preserved"] is True
    assert payload["cold"]["observation_total"] >= summary["unique_urls"]
    assert (
        payload["cold"]["observation_untouched"]
        == payload["cold"]["observation_total"]
    )
    assert payload["external_index"] == {}
