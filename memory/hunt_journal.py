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
from contextlib import contextmanager
from pathlib import Path

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import (
    SchemaError,
    make_journal_entry,
    make_session_summary_entry,
    validate_journal_entry,
)


_DIAGNOSTIC_FINGERPRINTS: set[str] = set()


class JournalConflictError(ValueError):
    """The retained journal binding already has different content."""


class JournalIntegrityError(ValueError):
    """Retained journal bytes cannot safely establish an append-once result."""


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

    @contextmanager
    def locked(self):
        """Serialize append, rotation and explicit cleanup across inode changes.

        This lock is not reentrant; callers inside it use the existing rotation
        primitives directly. The sidecar carries no memory or receipt state.
        """
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _append_locked(self, entry: dict) -> None:
        encoded = (json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")
        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)
        fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                start = os.fstat(fd).st_size
                if start and os.pread(fd, 1, start - 1) != b"\n":
                    raise JournalIntegrityError(f"Incomplete journal tail at {self.path}; inspect the retained bytes")
                try:
                    written = os.write(fd, encoded)
                    if written != len(encoded):
                        raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
                    os.fsync(fd)
                except OSError:
                    # Only undo an incomplete tail from this append. A complete
                    # row survives sync/ack failure and is recognized on retry.
                    if start < os.fstat(fd).st_size < start + len(encoded):
                        os.ftruncate(fd, start)
                        os.fsync(fd)
                    raise
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def append(self, entry: dict) -> None:
        """Validate and append; existing callers retain the None return value."""
        validated = validate_journal_entry(entry)
        if "command_id" in validated:
            self.append_once(validated)
            return
        with self.locked():
            self._append_locked(validated)

    def append_once(self, entry: dict) -> bool:
        """Append a Store-bound command once; False means already present.

        The guarantee covers retained live/numbered-backup rows. Legacy rows
        have no command binding and are never guessed or rewritten. Timestamps
        and session IDs describe the original call, not the replay payload.
        """
        validated = validate_journal_entry(entry)
        if "command_id" not in validated:
            raise SchemaError("append_once requires command_id and store_id")
        # Compare the actual JSON representation, including values that change
        # Python type on disk (for example a tuple stored as a list).
        validated = json.loads(json.dumps(validated, separators=(",", ":")))
        key = tuple(validated[field] for field in ("target", "store_id", "command_id"))
        payload = {field: value for field, value in validated.items() if field not in {"ts", "session_id"}}
        with self.locked():
            prefix = self.path.name + "."
            backups = sorted(
                (path for path in self.path.parent.iterdir()
                 if path.name.startswith(prefix) and path.name[len(prefix):].isascii()
                 and path.name[len(prefix):].isdigit() and int(path.name[len(prefix):]) > 0),
                key=lambda path: int(path.name[len(prefix):]),
            )
            paths = ([self.path] if self.path.exists() else []) + backups
            found = False
            for path in paths:
                with path.open("rb") as handle:
                    for lineno, line in enumerate(handle, 1):
                        if not line.strip():
                            continue
                        try:
                            if not line.endswith(b"\n"):
                                raise JournalIntegrityError("incomplete row")
                            saved = validate_journal_entry(json.loads(line))
                        except (ValueError, UnicodeError, SchemaError, TypeError) as exc:
                            raise JournalIntegrityError(
                                f"Invalid journal row at {path}:{lineno}; inspect the retained bytes"
                            ) from exc
                        if tuple(saved.get(field) for field in ("target", "store_id", "command_id")) != key:
                            continue
                        saved_payload = {field: value for field, value in saved.items()
                                         if field not in {"ts", "session_id"}}
                        if saved_payload != payload:
                            raise JournalConflictError(
                                f"Journal command {validated['command_id']} has different content at {path}:{lineno}"
                            )
                        if found:
                            raise JournalIntegrityError(f"Duplicate journal command at {path}:{lineno}")
                        found = True
                        os.fsync(handle.fileno())
            if found:
                return False
            self._append_locked(validated)
            return True

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
        user_intent: str | None = None,
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
                user_intent=user_intent,
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
