# Tool / AI Boundary

工具负责证据、记忆、复现和格式一致性；价值判断、路线选择、攻击链联想、升级/降级
解释和最终结论必须结合 raw evidence、业务语义、actor/object/session 关系、
browser/source/JS 证据与最新上下文得出。工具输出只能提供候选和线索，不能替代判断。

## 工具输出

- 原始请求 / 响应 / 截图 / HAR / JS/source 证据引用。
- 可复现命令、baseline / variant / diff 摘要。
- 来源、时间、采集方式、风险状态和停止条件。
- 去重、状态记录、ledger、checkpoint、case-state、queue。
- `advisory hint`、`review candidate`、`coverage hint`、`low-priority / reopenable hint`。

## 工具不得替代判断

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

## 回归要求

改动 `surface.py`、`checkpoint.py`、`coverage_matrix.py`、`action_queue.py`、
`validation_runner.py`、`context_pack.py`、`commands/*` 或 `agents/*` 时，必须确认：

- Claude-facing 输出仍明确“AI chooses / advisory / reopenable”。
- score/rank/gap/runner result 不会隐藏攻击面或终止探索。
- raw evidence 仍可追溯。
- 新证据可以 reopen 旧的 tested/dead-end/n/a 状态。
