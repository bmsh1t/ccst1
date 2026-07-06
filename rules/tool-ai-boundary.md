# Tool / AI Boundary

本规则定义工具与 Claude 的分工：工具负责证据、记忆、复现和格式一致性；Claude
负责攻击面价值判断、路线选择、攻击链联想、升级/降级解释和最终结论。

## 核心原则

```text
AI judges. Tools preserve evidence.
```

工具输出可以影响 Claude 的注意力，但不能替代 Claude 的判断。任何工具输出都必须可被
Claude 基于 raw evidence、业务语义、actor/object/session 关系、browser/source/JS
证据和最新上下文覆盖。

## 工具允许输出

- 原始请求 / 响应 / 截图 / HAR / JS/source 证据引用。
- 可复现命令、baseline / variant / diff 摘要。
- 来源、时间、采集方式、风险状态和停止条件。
- 去重、状态记录、ledger、checkpoint、case-state、queue。
- `advisory hint`、`review candidate`、`coverage hint`、`low-priority / reopenable hint`。

## 工具不得最终判断

- 某个攻击面“没有价值”。
- 某个 endpoint / host / lane 应永久跳过。
- 某个漏洞路线是最终优先级。
- 某个 `tested_clean` 等价于安全或漏洞不存在。
- scanner-negative 等价于测试完成。
- coverage gap 等价于必须执行的固定清单。
- 队列 final 状态不可被新证据重新打开。

## 命名与文案约束

Claude-facing 文案应优先使用：

- `AI Review Pool`
- `advisory score hint`
- `coverage hint`
- `surface-review`
- `low-priority / reopenable`
- `no finding proven in this runner scope`
- `candidate next action`

避免使用会训练 Claude 放弃判断的表达：

- `Kill List (skip)`
- `always P1`
- `must test`
- `score determines priority`
- `tested_clean = safe`
- `scanner-negative = complete`
- `No high-value matrix gap remains`

兼容旧 JSON 字段时，可以保留 `score`、`P1/P2`、`ranked-surface` 等字段，但
CLI/agent/command 文案必须说明它们只是 advisory hints。

## 正确分工

AI 负责：

- 判断当前业务目标和 crown jewels。
- 从证据中选择下一条最高价值 hypothesis。
- 组合 browser/source/JS/recon/scanner/ledger/case-state 证据。
- 判断工具标签是否被 raw evidence 或业务语义推翻。
- 生成链式 pivot、停止条件、降级理由和报告价值。

工具负责：

- 收集和合并证据。
- 稳定 replay、diff、raw evidence 保存。
- 去重、状态持久化、队列和 handoff。
- 暴露遗漏和矛盾点，但不把遗漏变成硬性流程锁。

## 回归要求

改动 `surface.py`、`checkpoint.py`、`coverage_matrix.py`、`action_queue.py`、
`validation_runner.py`、`context_pack.py`、`commands/*` 或 `agents/*` 时，必须确认：

- Claude-facing 输出仍明确“AI chooses / advisory / reopenable”。
- score/rank/gap/runner result 不会隐藏攻击面或终止探索。
- raw evidence 仍可追溯。
- 新证据可以 reopen 旧的 tested/dead-end/n/a 状态。
