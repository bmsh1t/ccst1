"""Atomic publication of ordinary UTF-8 artifacts; domain admission stays with callers."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TextIO


@contextmanager
def atomic_text_writer(path: str | Path) -> Iterator[TextIO]:
    """Publish a complete file, keeping old bytes on write/sync/replace failure.

    The temporary file is private (0600) and lives beside the destination.
    Callers own locks, schema validation and multi-file publication ordering.
    This does not fsync the parent directory or provide a multi-file transaction.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_text_atomic(path: str | Path, content: str) -> None:
    with atomic_text_writer(path) as handle:
        handle.write(content)


def write_json_atomic(
    path: str | Path, payload: Any, *, ensure_ascii: bool = False, sort_keys: bool = False,
) -> None:
    with atomic_text_writer(path) as handle:
        json.dump(payload, handle, ensure_ascii=ensure_ascii, indent=2, sort_keys=sort_keys)
        handle.write("\n")
