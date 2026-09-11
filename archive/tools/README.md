
## 2026-09-11 归档（09-11-simple-efficient-refactor 零-A）

- `knowledge_value_review.py`（415 行）：三零孤儿——零代码/文档/命令引用
- `self_review.py`（214 行）：同上
- `distill_aggregate.py`（86 行）：corpus 蒸馏平行死线，随零-B 一起退役
- `vision_browser.py`（72 行）：仅一份 seam 文档提及（已同步删除）
- `../tests/test_knowledge_value_review.py`：随源归档；根 conftest.py 排除 archive/ 收集

## 零-B 随迁（2026-09-11）

- `../tools/../../archive` 下：`knowledge_candidates.py`（1,135）、`knowledge_lifecycle.py`（766）、
  `distill_reports.py`（499，活函数族已迁 `tools/corpus_projection.py`）+ 对应测试
- `../distill_rubrics/`：corpus 蒸馏提示词（零外部引用，随蒸馏管线退役）
- `../knowledge-governance/value-review.json`：knowledge_value_review 输出数据
