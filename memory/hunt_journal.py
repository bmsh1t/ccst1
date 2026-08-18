"""
Append-only hunt journal backed by JSONL files.

Uses fcntl.flock() for safe concurrent appends.
Corrupted lines are skipped with a warning, not a crash.
"""

import fcntl
import hashlib
import json
import os
import sys
from pathlib import Path

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import (
    SchemaError,
    make_journal_entry,
    make_session_summary_entry,
    validate_journal_entry,
)


_DIAGNOSTIC_FINGERPRINTS: set[str] = set()


class HuntJournal:
    """Read/write hunt journal entries from a JSONL file."""

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep_backups: int = DEFAULT_KEEP,
    ):
        """
        Args:
            path: Path to the journal.jsonl file. Parent dirs are created if needed.
            max_bytes: Rotate the file when it exceeds this size.
            keep_backups: Number of rotated backups to retain.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups

    def append(self, entry: dict) -> None:
        """Validate and append a journal entry. Raises SchemaError on invalid entry, OSError on disk failure."""
        validated = validate_journal_entry(entry)
        line = json.dumps(validated, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)

        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def read_all(self, *, validate: bool = True) -> list[dict]:
        """Read all journal entries. Corrupted lines are skipped with a warning.

        Args:
            validate: If True, validate each entry against the schema. Invalid entries are skipped.

        Returns:
            List of valid journal entries.
        """
        if not self.path.exists():
            return []

        entries = []
        invalid_rows = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    invalid_rows.append((lineno, f"corrupted: {e}"))
                    continue

                if validate:
                    try:
                        validate_journal_entry(entry)
                    except SchemaError as e:
                        invalid_rows.append((lineno, f"failed validation: {e}"))
                        continue

                entries.append(entry)

        if invalid_rows:
            try:
                stat = self.path.stat()
                fingerprint = hashlib.sha256(
                    f"{self.path}:{stat.st_size}:{stat.st_mtime_ns}:{len(invalid_rows)}".encode()
                ).hexdigest()
            except OSError:
                fingerprint = str(self.path)
            if fingerprint not in _DIAGNOSTIC_FINGERPRINTS:
                _DIAGNOSTIC_FINGERPRINTS.add(fingerprint)
                first_line, first_reason = invalid_rows[0]
                print(
                    f"WARNING: journal {self.path} has {len(invalid_rows)} invalid rows "
                    f"(first line {first_line}: {first_reason}); valid rows retained",
                    file=sys.stderr,
                )

        return entries

    def log_session_summary(
        self,
        target: str,
        action: str,
        endpoints_tested: list[str],
        vuln_classes_tried: list[str],
        findings_count: int,
        session_id: str | None = None,
    ) -> None:
        """Auto-log a session summary entry at hunt/autopilot session end.

        Failures are non-fatal and should never crash the main workflow.
        """
        try:
            entry = make_session_summary_entry(
                target=target,
                action=action,
                endpoints_tested=endpoints_tested,
                vuln_classes_tried=vuln_classes_tried,
                findings_count=findings_count,
                session_id=session_id,
            )
            self.append(entry)
        except Exception as e:
            print(f"WARNING: auto-log session summary failed (non-fatal): {e}", file=sys.stderr)

    def log_hypothesis_transition(
        self,
        target: str,
        previous: str,
        current: str,
        reason: str,
    ) -> bool:
        """Append one schema-compliant hypothesis transition when state changed."""
        previous = " ".join(str(previous or "").split())[:500]
        current = " ".join(str(current or "").split())[:500]
        reason = " ".join(str(reason or "working_memory_update").split())[:500]
        if not current or current == previous:
            return False
        try:
            self.append(
                make_journal_entry(
                    target=target,
                    action="hunt",
                    vuln_class="hypothesis",
                    endpoint="session",
                    result="informational",
                    technique="hypothesis_transition",
                    notes=json.dumps(
                        {"from": previous, "to": current, "reason": reason},
                        separators=(",", ":"),
                    ),
                    tags=["auto_logged", "hypothesis_transition"],
                )
            )
            return True
        except Exception as e:
            print(f"WARNING: hypothesis transition log failed (non-fatal): {e}", file=sys.stderr)
            return False

    def query(self, *, target: str | None = None, vuln_class: str | None = None,
              action: str | None = None, result: str | None = None) -> list[dict]:
        """Query journal entries by field values. All filters are AND-ed."""
        entries = self.read_all()
        if target is not None:
            entries = [e for e in entries if e.get("target") == target]
        if vuln_class is not None:
            entries = [e for e in entries if e.get("vuln_class") == vuln_class]
        if action is not None:
            entries = [e for e in entries if e.get("action") == action]
        if result is not None:
            entries = [e for e in entries if e.get("result") == result]
        return entries
