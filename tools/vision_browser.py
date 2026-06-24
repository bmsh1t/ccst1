#!/usr/bin/env python3
"""
vision_browser.py — vision-aware screenshot capture and lookup (B12b).

Adds two capabilities on top of tools/browser_evidence.py:

  1. capture_with_screenshot_sequence(target, url, seq=N)
       Captures a browser_evidence snapshot AND a sequence-tagged
       screenshot at evidence/<target>/browser/<dir>/screenshot_{seq}.png.

  2. find_latest_screenshot(target)
       Walks evidence/<target>/browser/ and returns the most recent
       screenshot_{seq}.png path, used by the read_browser_screenshot
       dispatcher tool when --vision is set.

Model capability detection:

  Vision-capable Ollama / Claude model heuristics live in
  model_supports_vision(model_name). The check fails closed
  (returns False) for unknown names so the screenshot tool is
  never exposed against a text-only model by accident.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
DEFAULT_MAX_SCREENSHOTS = 5


_VISION_MODEL_PATTERNS = (
    # Claude vision (Sonnet/Opus 4.x lines)
    re.compile(r"^claude-(opus|sonnet)-4", re.IGNORECASE),
    re.compile(r"^claude-3-(opus|sonnet|haiku)", re.IGNORECASE),
    # Ollama llava / bakllava / moondream
    re.compile(r"^llava\b", re.IGNORECASE),
    re.compile(r"^bakllava\b", re.IGNORECASE),
    re.compile(r"^moondream\b", re.IGNORECASE),
    re.compile(r"^minicpm-v\b", re.IGNORECASE),
    re.compile(r"^qwen2?-vl\b", re.IGNORECASE),
    re.compile(r"^qwen2\.5-vl\b", re.IGNORECASE),
)


def model_supports_vision(model_name: Optional[str]) -> bool:
    """Return True iff the model name matches a known vision-capable family.

    Fails closed for unknown names so the vision tool is only exposed when
    the active model definitely supports image input.
    """
    if not model_name:
        return False
    return any(pat.search(model_name) for pat in _VISION_MODEL_PATTERNS)


# ---------------------------------------------------------------------
#  R1: Sequence-tagged screenshot capture
# ---------------------------------------------------------------------

def _next_screenshot_seq(target_dir: Path) -> int:
    """Scan target_dir/**/screenshot_*.png and return next sequence number."""
    if not target_dir.exists():
        return 1
    pat = re.compile(r"screenshot_(\d+)\.png$")
    highest = 0
    for png in target_dir.rglob("screenshot_*.png"):
        m = pat.search(png.name)
        if not m:
            continue
        try:
            highest = max(highest, int(m.group(1)))
        except ValueError:
            continue
    return highest + 1


def capture_with_screenshot_sequence(
    target: str,
    url: str,
    *,
    session: str = "",
    label: str = "vision",
    evidence_root: str | Path | None = None,
    seq: int | None = None,
    max_screenshots: int = DEFAULT_MAX_SCREENSHOTS,
) -> dict:
    """Capture a browser_evidence snapshot and rename screenshot to
    screenshot_{seq}.png inside the capture dir.

    Returns a dict with keys:
      capture: the browser_evidence summary dict
      screenshot_seq: assigned sequence number
      screenshot_path: absolute path to screenshot_{seq}.png (or "" on no-capture)
      dom_path: absolute path to dom_{seq}.html (mirrors snapshot.txt for the LLM)
      capped: True if seq exceeded max_screenshots and capture was skipped
    """
    from tools.browser_evidence import capture_browser_evidence, _target_key  # noqa: E402

    target_name = _target_key(target)
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    target_dir = root / target_name / "browser"

    if seq is None:
        seq = _next_screenshot_seq(target_dir)
    if seq > max_screenshots:
        return {
            "capture": None,
            "screenshot_seq": seq,
            "screenshot_path": "",
            "dom_path": "",
            "capped": True,
        }

    summary = capture_browser_evidence(
        target=target,
        url=url,
        session=session,
        label=f"{label}-{seq:02d}",
        evidence_root=root,
        capture_screenshot=True,
    )
    capture_dir = Path(summary["evidence_dir"])

    # Rename the captured screenshot to screenshot_{seq}.png so the LLM
    # can correlate with dom_{seq}.html.
    orig_png = capture_dir / "screenshot.png"
    seq_png = capture_dir / f"screenshot_{seq}.png"
    if orig_png.is_file():
        try:
            shutil.move(str(orig_png), str(seq_png))
        except OSError:
            seq_png = orig_png  # fall back to original name

    # Mirror snapshot.txt → dom_{seq}.html for correlation, if present
    snapshot_txt = capture_dir / "snapshot.txt"
    dom_html = capture_dir / f"dom_{seq}.html"
    if snapshot_txt.is_file():
        try:
            dom_html.write_text(snapshot_txt.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            dom_html = snapshot_txt

    return {
        "capture": summary,
        "screenshot_seq": seq,
        "screenshot_path": str(seq_png) if seq_png.is_file() else "",
        "dom_path": str(dom_html) if dom_html.is_file() else "",
        "capped": False,
    }


# ---------------------------------------------------------------------
#  R2/R3: Lookup the latest screenshot for the dispatcher tool
# ---------------------------------------------------------------------

def find_latest_screenshot(
    target: str,
    *,
    evidence_root: str | Path | None = None,
) -> Optional[Path]:
    """Return the most recent screenshot_{seq}.png across all capture dirs."""
    from tools.browser_evidence import _target_key  # noqa: E402
    target_name = _target_key(target)
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    target_dir = root / target_name / "browser"
    if not target_dir.exists():
        return None
    pat = re.compile(r"screenshot_(\d+)\.png$")
    best: tuple[int, float, Path] | None = None
    for png in target_dir.rglob("screenshot_*.png"):
        m = pat.search(png.name)
        if not m:
            continue
        try:
            seq = int(m.group(1))
        except ValueError:
            continue
        mtime = png.stat().st_mtime
        if best is None or (seq, mtime) > (best[0], best[1]):
            best = (seq, mtime, png)
    return best[2] if best else None


def list_screenshots(target: str, *, evidence_root: str | Path | None = None) -> list[dict]:
    """List all screenshots with their seq + correlated DOM path."""
    from tools.browser_evidence import _target_key  # noqa: E402
    target_name = _target_key(target)
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    target_dir = root / target_name / "browser"
    if not target_dir.exists():
        return []
    pat = re.compile(r"screenshot_(\d+)\.png$")
    out: list[dict] = []
    for png in sorted(target_dir.rglob("screenshot_*.png")):
        m = pat.search(png.name)
        if not m:
            continue
        try:
            seq = int(m.group(1))
        except ValueError:
            continue
        dom = png.parent / f"dom_{seq}.html"
        out.append({
            "seq": seq,
            "screenshot_path": str(png),
            "dom_path": str(dom) if dom.exists() else "",
            "capture_dir": str(png.parent),
        })
    out.sort(key=lambda r: r["seq"])
    return out


# ---------------------------------------------------------------------
#  Tool exposure gate (R2)
# ---------------------------------------------------------------------

def should_expose_vision_tool(*, vision_enabled: bool, model_name: Optional[str]) -> bool:
    """Combined check for whether read_browser_screenshot should be exposed."""
    return bool(vision_enabled) and model_supports_vision(model_name)
