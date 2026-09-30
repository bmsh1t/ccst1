"""Retired object inference; compatibility for the protected Checkpoint caller.

Claude reads raw artifacts and explicitly records Case objects. This adapter
performs no artifact scan, object inference, Store mutation or route selection.
"""
from pathlib import Path


def build_case_state_seed(repo_root: str | Path, target: str, *, limit: int = 8) -> dict:
    return {"status": "retired", "suggested_objects": []}


if __name__ == "__main__":
    raise SystemExit("Object inference is retired; read raw artifacts natively and use target_case_state.py for explicit records.")
