"""Native reading replaces the retired JS material-preparation wrapper."""
from pathlib import Path
import ast
from tools import hunt


def test_native_reading_has_no_material_preparation_dependency():
    root = Path(__file__).resolve().parents[1]
    retired = {"js_reader", "surface_js_intel", "surface_source_intel", "source_intel", "intelligence_extractor"}
    assert not hasattr(hunt, "run_js_read")
    for name in retired:
        assert not (root / "tools" / f"{name}.py").exists()
    for path in (root / "tools").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            modules = [node.module or ""] if isinstance(node, ast.ImportFrom) else (
                [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
            assert not retired.intersection(module.split(".")[-1] for module in modules), path
    assert not (root / "agents/js-reader.md").exists()
    assert not (root / "commands/js-read.md").exists()
