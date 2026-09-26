"""Explicit read-only inspection of historical PatternDB files.

Current target experience is written and queried through TargetStore.
"""

import json
import sys
from pathlib import Path

from memory.schemas import validate_pattern_entry, SchemaError


class PatternDB:
    """Inspect historical patterns without creating files or current state."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def read_all(self, *, validate: bool = True) -> list[dict]:
        """Read all pattern entries. Corrupted lines are skipped with a warning."""
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"WARNING: patterns line {lineno} is corrupted (skipping): {e}",
                        file=sys.stderr,
                    )
                    continue

                if validate:
                    try:
                        validate_pattern_entry(entry)
                    except SchemaError as e:
                        print(
                            f"WARNING: patterns line {lineno} failed validation (skipping): {e}",
                            file=sys.stderr,
                        )
                        continue

                entries.append(entry)

        return entries

    def match(self, *, vuln_class: str | None = None,
              tech_stack: list[str] | None = None,
              calibrated: bool = False,
              calibration_path: str | Path | None = None) -> list[dict]:
        """Find patterns matching vuln class and/or overlapping tech stack.

        Args:
            vuln_class: Exact match on vuln_class field.
            tech_stack: Partial overlap match — returns patterns where ANY tech in
                        the query overlaps with the pattern's tech_stack.
            calibrated: B12d — when True, exclude patterns whose calibration
                        score has samples >= 5 AND precision < 0.2. Calibration
                        data lives in hunt-memory/pattern_calibration.jsonl
                        (or `calibration_path` if provided).
            calibration_path: alternate path for the calibration JSONL.
                              Defaults to the package's hunt-memory/ layout.

        Returns:
            Matching patterns sorted by payout (highest first), then recency.
        """
        patterns = self.read_all()

        if vuln_class is not None:
            patterns = [p for p in patterns if p.get("vuln_class") == vuln_class]

        if tech_stack is not None:
            query_set = {t.lower() for t in tech_stack}
            patterns = [
                p for p in patterns
                if query_set & {t.lower() for t in p.get("tech_stack", [])}
            ]

        if calibrated:
            try:
                from tools.pattern_calibration import excluded_pattern_ids, pattern_id_for
                bad_ids = excluded_pattern_ids(calibration_path)
            except Exception:
                bad_ids = set()
            if bad_ids:
                patterns = [p for p in patterns if pattern_id_for(p) not in bad_ids]

        # Sort: highest payout first, then most recent
        patterns.sort(
            key=lambda p: (p.get("payout", 0), p.get("ts", "")),
            reverse=True,
        )

        return patterns
