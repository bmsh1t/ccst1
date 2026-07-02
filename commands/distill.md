---
description: 从全量披露报告语料蒸馏可复用知识卡候选（corpus-scoped）。用法：/distill [--max N] [--batch-size N]
---

# /distill

从**全量 HackerOne 披露报告语料**蒸馏出值得教给 Claude 的知识卡候选。

这是 corpus-scoped 知识蒸馏，区别于 `/intel` 和 `disclosed-researcher` 的
target-scoped 横向情报：

| 命令 | 作用域 | 问题 |
|---|---|---|
| `/intel` · `disclosed-researcher` | target-scoped | 当前目标 / 同类目标已经在什么模式上拿过赏？ |
| `/distill` | corpus-scoped | 全量语料里，哪些可复用思路值得写成知识卡？ |

核心纪律：**工具只做确定性数据处理，两轮打分是 Claude 的推理工作。**
产出是**候选卡草稿**，进 `knowledge/candidates/` 复核队列，人工 `/kb promote`
后才进正式 `knowledge/cards/`。

## Workflow

### 1. fetch（一次性，可缓存）

```bash
python3 tools/distill_reports.py --fetch
```

下载数据集 parquet 到 `distill/cache/`（已 gitignore）。需要可选依赖 pyarrow；
未安装时工具会打印 `pip install pyarrow` 提示并干净退出，不崩溃。

### 2. prepare（确定性预处理）

```bash
python3 tools/distill_reports.py --prepare --max 500 --batch-size 25
```

- 丢空 / 纯占位 `vulnerability_information`
- 可选 `--substate resolved` 只留已解决报告
- 按 `id` 去重
- 归一化为打分所需最小字段集（丢弃 reporter/team PII、structured_scope）
- 分批写 `distill/work/batch_NNN.jsonl` + `manifest.json`

### 3. 第一轮打分（Claude，价值评分）

读取每个 `distill/work/batch_NNN.jsonl`，按
`tools/distill_rubrics/round1_value.md` 的四维 rubric 打分。
保留 `value_score >= 7`（高优先级）与 5-6（普通）。

### 4. 第二轮打分（Claude，Skill 价值判断 + 天花板检测）

对第一轮保留的报告，按 `tools/distill_rubrics/round2_skill.md` 判断
`is_ai_likely_known` / 场景频率 / 可迁移性，产出 `worth_skill` 与卡片字段。
把结果写成一个 JSON 文件，例如 `distill/work/scored.json`。

### 5. ingest（确定性收纳到 staging）

```bash
python3 tools/distill_reports.py --ingest distill/work/scored.json
```

把 `worth_skill = true` 的候选渲染成卡草稿写入 `knowledge/candidates/`。
工具**拒绝**写入 `knowledge/cards/`。emails / 长 token 有 backstop 脱敏。

### 6. 人工复核 + 晋升

人工过一遍 `knowledge/candidates/` 里的候选（数量远少于原始报告），挑真正
想要的，按 `/kb promote` 流程迁入 `knowledge/cards/` 并登记到
`knowledge/index.md`。

## 输出物

```text
distill/cache/            # 数据集 parquet（gitignored）
distill/work/batch_*.jsonl# 打分批次
distill/work/manifest.json# 批次清单 + rubric 指针
distill/work/scored.json  # Claude 两轮打分结果（人工/流程写）
knowledge/candidates/*.md # 候选卡草稿（复核队列）
```

## 纪律

- 候选是**未验证的思路**，不是发现，禁止直接用于测试。
- 只提炼思路（原理 / 触发信号 / 发散问题 / 停止条件），不写 payload、
  不写目标专属 exploit、不写凭证或 reporter PII。
- 候选进 `knowledge/candidates/`，正式卡只能经 `/kb promote` 人工晋升。
- 和 `rules/` 冲突时，以 `rules/` 为准。

## 相关

- `tools/distill_reports.py` — 确定性数据处理后端
- `tools/distill_rubrics/round1_value.md` · `round2_skill.md` — 两轮 rubric
- `knowledge/promotion-rules.md` · `card-template.md` — 晋升规则与卡模板
- `/kb promote` — 把候选晋升为正式知识卡
