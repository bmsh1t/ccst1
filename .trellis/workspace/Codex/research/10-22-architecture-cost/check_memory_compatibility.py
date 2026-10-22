"""Replay the existing synthetic acceptance recipe against this task's production sources."""
from pathlib import Path

root = next(path for path in Path(__file__).resolve().parents if (path / '.git').exists())
recipe = root / '.trellis/tasks/10-22-memory-recovery-reliability/research/check_memory_recovery.py'
source = recipe.read_text()
old_origin = "ORIGIN = Path('/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst')"
old_overlay = "'tools/recall_index.py', 'tools/target_store.py', 'tools/distill_target.py')"
assert old_origin in source and old_overlay in source and "COMMIT = '9d0675a'" in source
source = source.replace(old_origin, f'ORIGIN = Path({str(root)!r})')
source = source.replace("COMMIT = '9d0675a'", "COMMIT = 'd8a91a1eaf0eb71758565279c385b000de2761e9'")
source = source.replace(old_overlay, "'tools/recall_index.py', 'tools/target_store.py', 'tools/distill_target.py',\n"
                        "               'tools/experience_recall.py', 'tools/relation_recall.py', 'tools/coverage_matrix.py',\n"
                        "               'tools/surface_index.py', 'tools/surface_projection.py')")
source = source.replace('/tmp/ccst-memory-recovery-check-20261022',
                        '/tmp/ccst-architecture-memory-regression-20261022')
exec(compile(source, str(recipe), 'exec'), {'__name__': '__main__', '__file__': str(recipe)})
