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

新证据可重开调查方向；`completed/cancelled` 行动不改写。
blocked 恢复与关联新行动按 `skills/runtime-protocol.md#shared-memory-continuity`，保留历史和依据。

## 命名与文案约束

使用 observed facts、advisory、candidate 和条件化 reopenable 表述。
不把 score/rank、tested_clean、scanner-negative 或 gap 数量写成价值、安全或完成结论。
旧 JSON 的 score、P1/P2、ranked-surface 可兼容；排序只用来源事实、显式优先级或已记录状态。
路径词、rubric/关键词分数不能决定候选可见性、方法、补证或报告资格；仅改称 advisory 不算删除。

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
- 新证据可重新调查旧 tested/dead-end/n/a 的适用条件，保留原执行历史和真实证据。

## 谁思考

| 参数职责 | 约束 |
|---|---|
| AI 判断 | 所需的 hypothesis、family/technique、expected_learning、kill_condition、decision_reason、risk_tier 及 result/resolve/影响判断依当前证据填写，不由类别模板预填 |
| 原件事实 | endpoint/method/evidence_ref/baseline_ref 从实际材料读取，不推测未发生的执行 |
| 机械 | target、repo_root、锁、版本、witness、时间戳由现有 owner 处理 |

`claim --id` 显式指定行动；metadata 无必填认知字段闸，Queue 只验机械不变量。
兼容 skill_route 不构成强制路由记账；风险标签不是危险操作许可。任何新 gate 不得替代 AI 判断。
