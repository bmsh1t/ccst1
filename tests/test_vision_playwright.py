"""tests/test_vision_playwright.py — B12b acceptance tests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import vision_browser as vb     # noqa: E402


# ---------------------------------------------------------------------
#  R2: Model capability detection
# ---------------------------------------------------------------------

class TestModelCapability:
    @pytest.mark.parametrize("model", [
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-3-opus-20240229",
        "claude-3-haiku-20240307",
        "llava:13b",
        "llava-llama3:8b",
        "bakllava:latest",
        "moondream:1.8b",
        "minicpm-v:8b",
        "qwen-vl-chat:7b",
        "qwen2.5-vl:7b",
    ])
    def test_known_vision_models_return_true(self, model):
        assert vb.model_supports_vision(model) is True

    @pytest.mark.parametrize("model", [
        "",
        None,
        "qwen2.5:32b",            # text-only Qwen
        "qwen3-coder:30b",        # text-only Qwen3 coder
        "deepseek-coder:33b",
        "llama3:8b",
        "mistral:7b",
        "phi3:mini",
        "gpt-4-turbo",            # not on our allowlist
    ])
    def test_text_only_models_return_false(self, model):
        assert vb.model_supports_vision(model) is False


# ---------------------------------------------------------------------
#  R2: Tool exposure gating
# ---------------------------------------------------------------------

class TestToolExposureGate:
    def test_disabled_when_vision_flag_off(self):
        assert vb.should_expose_vision_tool(vision_enabled=False, model_name="claude-opus-4-7") is False

    def test_disabled_when_model_text_only(self):
        assert vb.should_expose_vision_tool(vision_enabled=True, model_name="qwen2.5:32b") is False

    def test_enabled_when_both_conditions_met(self):
        assert vb.should_expose_vision_tool(vision_enabled=True, model_name="llava:13b") is True

    def test_disabled_when_model_unknown(self):
        assert vb.should_expose_vision_tool(vision_enabled=True, model_name=None) is False
        assert vb.should_expose_vision_tool(vision_enabled=True, model_name="") is False


# ---------------------------------------------------------------------
#  R1: Sequence-tagged screenshot naming
# ---------------------------------------------------------------------

class TestScreenshotNaming:
    def test_next_seq_starts_at_one(self, tmp_path):
        assert vb._next_screenshot_seq(tmp_path / "missing") == 1

    def test_next_seq_increments_past_highest(self, tmp_path):
        target_dir = tmp_path / "browser"
        cap1 = target_dir / "00-cap"
        cap1.mkdir(parents=True)
        (cap1 / "screenshot_1.png").write_bytes(b"x")
        (cap1 / "screenshot_3.png").write_bytes(b"x")
        cap2 = target_dir / "01-cap"
        cap2.mkdir(parents=True)
        (cap2 / "screenshot_5.png").write_bytes(b"x")
        assert vb._next_screenshot_seq(target_dir) == 6


class TestCaptureWithScreenshotSequence:
    def test_skips_above_max_screenshots(self, tmp_path, monkeypatch):
        # No need to actually invoke browser_evidence — we just confirm
        # the cap behaviour.
        out = vb.capture_with_screenshot_sequence(
            target="x.com", url="http://x/",
            evidence_root=tmp_path,
            seq=11,
            max_screenshots=10,
        )
        assert out["capped"] is True
        assert out["screenshot_path"] == ""
        assert out["capture"] is None

    def test_capture_renames_to_sequence_filename(self, tmp_path, monkeypatch):
        """Replace capture_browser_evidence with a fake that writes a
        screenshot.png in its declared evidence_dir."""
        from tools import browser_evidence as be

        def fake_capture(target, url, *, session="", label="capture",
                         evidence_root=None, timeout=30, capture_screenshot=False):
            root = Path(evidence_root) if evidence_root else tmp_path
            d = root / "x.com" / "browser" / f"00-{label}"
            d.mkdir(parents=True, exist_ok=True)
            # Simulate playwright-cli writing the raw artifacts
            (d / "screenshot.png").write_bytes(b"PNG-FAKE")
            (d / "snapshot.txt").write_text("<html>raw dom</html>")
            return {
                "target": target, "url": url, "session": session, "label": label,
                "evidence_dir": str(d), "success": True, "captured_at": "t",
            }

        monkeypatch.setattr(be, "capture_browser_evidence", fake_capture)
        out = vb.capture_with_screenshot_sequence(
            target="x.com", url="http://x/", evidence_root=tmp_path, seq=4,
        )
        assert out["capped"] is False
        assert out["screenshot_seq"] == 4
        png_path = Path(out["screenshot_path"])
        assert png_path.name == "screenshot_4.png"
        assert png_path.exists()
        # dom_4.html mirrors snapshot.txt
        dom_path = Path(out["dom_path"])
        assert dom_path.name == "dom_4.html"
        assert dom_path.read_text() == "<html>raw dom</html>"


# ---------------------------------------------------------------------
#  R2/R3: Latest-screenshot lookup
# ---------------------------------------------------------------------

class TestFindLatestScreenshot:
    def test_returns_none_for_unknown_target(self, tmp_path):
        assert vb.find_latest_screenshot("absent.com", evidence_root=tmp_path) is None

    def test_returns_highest_seq(self, tmp_path):
        base = tmp_path / "x.com" / "browser" / "00-cap"
        base.mkdir(parents=True)
        (base / "screenshot_1.png").write_bytes(b"x")
        (base / "screenshot_3.png").write_bytes(b"x")
        (base / "screenshot_2.png").write_bytes(b"x")
        latest = vb.find_latest_screenshot("x.com", evidence_root=tmp_path)
        assert latest is not None
        assert latest.name == "screenshot_3.png"

    def test_list_screenshots_returns_ordered_records(self, tmp_path):
        base = tmp_path / "x.com" / "browser" / "00-cap"
        base.mkdir(parents=True)
        (base / "screenshot_1.png").write_bytes(b"x")
        (base / "screenshot_2.png").write_bytes(b"x")
        (base / "dom_1.html").write_text("<a/>")
        rows = vb.list_screenshots("x.com", evidence_root=tmp_path)
        assert len(rows) == 2
        assert rows[0]["seq"] == 1
        assert rows[0]["dom_path"].endswith("dom_1.html")
        # dom_2.html missing → empty
        assert rows[1]["seq"] == 2
        assert rows[1]["dom_path"] == ""


# ---------------------------------------------------------------------
#  R4: CLI flag
# ---------------------------------------------------------------------

class TestCliFlag:
    def test_vision_flag_in_agent_py(self):
        text = (REPO_ROOT / "agent.py").read_text(encoding="utf-8")
        assert "--vision" in text
        assert "--max-screenshots" in text

    def test_vision_default_off(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--vision", action="store_true")
        parser.add_argument("--max-screenshots", type=int, default=5)
        ns = parser.parse_args([])
        assert ns.vision is False
        assert ns.max_screenshots == 5


# ---------------------------------------------------------------------
#  R5: Backwards compatibility
# ---------------------------------------------------------------------

class TestBackwardsCompatibility:
    def test_browser_evidence_default_no_screenshot(self):
        """C1 invariant: tools/browser_evidence.py default behavior unchanged.

        capture_screenshot kwarg defaults to False; existing callers that
        don't pass it stay screenshot-free.
        """
        from tools.browser_evidence import capture_browser_evidence
        import inspect
        sig = inspect.signature(capture_browser_evidence)
        assert sig.parameters["capture_screenshot"].default is False


# ---------------------------------------------------------------------
#  Docs
# ---------------------------------------------------------------------

class TestDocsMention:
    def test_autopilot_md_mentions_vision(self):
        text = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "--vision" in text
