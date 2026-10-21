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
- `observed source facts`
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

兼容旧 JSON 字段时，可以容忍 `score`、`P1/P2`、`ranked-surface` 等字段。
新排序只使用已有来源事实、显式优先级或已记录状态，不再由路径词推测价值。
旧 rubric/关键词分数不能决定候选可见性、方法、补证要求或报告资格；仅改称
“advisory”不算删除。证据解释、角色组合和方法选择交给 Claude。

## 保留工具的标准

保留有明确协议、解析、采集、字节复现、证据保存或恢复价值的机械辅助。
没有独立准备/执行价值的重复业务包装、静态漏洞评级、固定下一步方法链和批次价值评分退役；
选源、方法、判断由现有 `src-hunter` 与原生模型完成，不再增加 controller。

包装上游本身不是删除理由。`wordlist_engine`、`osint_employees`、`eburst_lane`
保留为可选 helper：批量变异、来源整理、输入约束和有界 raw 回执有复用价值。
候选池（含兼容 `ranked.txt`）不等于审阅后 shortlist，推断姓名不等于确认账号，
EBurst 执行成功不等于接口可利用或凭据有效。它们不规定必跑路线。

源码 helper 仅获取和保存选定原件，secret/CI analysis 明示 `not_run`。
显式 scanner 仅保存有界 Nuclei 执行输入、raw、退出码及 residual，失败不等零发现成功。
Recon 批次按完成顺序保留 target 和来源计数，未采集的计数为 unknown。
这些产物不能自动写 Finding/Action/Coverage；历史证据、底座 owner 与恢复仍保留。

## 回归要求

改动 `surface.py`、`checkpoint.py`、`coverage_matrix.py`、`action_queue.py`、
`validation_runner.py`、`context_pack.py`、`commands/*` 或 `agents/*` 时，必须确认：

- Claude-facing 输出仍明确“AI chooses / advisory / reopenable”。
- score/rank/gap/runner result 不会隐藏攻击面或终止探索。
- raw evidence 仍可追溯。
- 新证据可以 reopen 旧的 tested/dead-end/n/a 状态。

## 谁思考（认知归属，2026-09-11 单一来源化）

命令参数分三类，命令文档用这三类标注：

- **AI 判断**：临场认知，机器不可推导也不可预填。claim 元数据全部判断字段
  （hypothesis_id / family / technique / expected_learning / kill_condition /
  decision_reason / skill_route / risk_tier；2026-09-14 起 `--id` 必填、无
  必填字段闸，AI 全量写、Queue 只验机械不变量）、result 判定、resolve 决策、
  报告影响评估。
- **机器推导**：可从已有原始材料读取的 endpoint/method/evidence_ref/
  baseline_ref；引用采集原件，不推测未记录的执行事实。
- **AI 判断（2026-09-13 修订）**：family/technique/skill_route/risk_tier 依据当前
  假设由 AI 填写——类别模板已退役；这些不是可凭类别机械推导的事实，风险标签
  也不构成危险操作的许可。
- **机械**：owner 上下文自动携带。target、repo_root、锁、witness、时间戳。

任何新 gate 不得把 AI 判断字段变成机械字段（分桶纪律的文档面）。
