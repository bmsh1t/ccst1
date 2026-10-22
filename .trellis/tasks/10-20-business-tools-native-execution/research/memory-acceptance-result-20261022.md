# 记忆系统全面验收：当前不通过（2026-10-22）

本轮合成样本的保存、持久化与多条查询路径通过，但中文 FTS 召回仍有回退；Autopilot 恢复、应用和更新记忆尚未达标。本轮发现三处可复现的机械/展示缺口；六个真实模型会话中，保存成功，Autopilot 相关续接和版本纠错未达标，明确只读及无关任务的状态隔离通过。

本次验收不修改生产代码。未读取、修改或运行项目 `tests/`；未操作真实目标、报告、个人 runtime 或已审知识。当前开发任务保持 `in_progress`，未安装依赖、推送或归档。

## 固定版本与证据

- 源码：`fb1704076e477cc67e24611f6b563089d5fa45c1`，分支 `refactor/10-11-capability-architecture`。
- 实验：`/root/ccst-runs/ccst-memory-acceptance-20261022-2o6iizpd`。
- 宿主：Claude CLI `2.1.304`，请求及宿主回报模型 `claude-opus-4-8`；未独立验证提供商内部模型路由。
- 机械结果：`memory-acceptance-mechanical-20261022.json`；journal：`memory-acceptance-journal-result-20261022.json`；宿主汇总：`memory-acceptance-host-result-20261022.json`。
- 机械脚本：`memory-acceptance-check-20261022.py`、`memory-acceptance-journal-20261022.py`。从固定提交提取生产 tools/memory；隔离数据、知识审核收据均是明确标注的合成 fixture。
- 真实会话：实验内 `sessions/<case>/visible.jsonl`、`result.json`、`process.json`、`host.json`；分组前状态及文件哈希在 `audit/controls-before.json`。源码哈希在 `run.json`。
- 留存的三个宿主脚本是本次运行配方，不是新增产品执行器；需配合原实验的 `run.json`、`cases.json` 等使用。原始 setup/init 配方留于实验根。

## 机械验收

主检查 13 个分区：10 通过、3 失败，成功断言 133 项，耗时约 13 秒。journal 另 61 项通过，1.095 秒。合计 **194 项成功断言、3 个失败判据**；不把“缺陷复现成功”计作功能通过。

| 能力 | 结果与已覆盖边界 |
| --- | --- |
| 保存与恢复 | 公开 CLI 在不同进程保存/恢复；旧经验超出最近窗口仍可检索；handoff 独立于最近五条；缺库拒绝且不初始化 |
| 幂等、竞争、故障 | 同 ID 同内容重放不加 revision；变内容冲突；journal 短写、fsync、确认丢失、损坏、rotation/purge、并发追加及补写；partial 保留已提交经验 |
| 纠错与来源 | 精确版本、不同条件不全局替代、refutes/supersedes、撤回不复活、依赖失效、basis/origin 区分、外部证据撤回及同 revision 改字节 |
| 目标隔离 | 两目标同 ID 不串记录；外 Store 来源和关系 seed 拒绝 |
| 文本索引 | 无索引/陈旧/损坏使用新来源；查询不偷偷建设；cursor 绑定来源和代次；显式更新失败只返回索引恢复命令，保留 save |
| 关系索引 | 显式构建、有限路径与翻页、陈旧图不冒充当前、跨目标拒绝；结果不授权执行 |
| 共享知识 | 审核收据与正文/审核实验原件字节绑定；篡改、退休、缺收据拒绝；Surface 建议也拒绝未审改动 |
| 蒸馏纠错 | 当前正文保留版本/纠错/来源状态，旧缺口已修复并实测通过 |
| 积累与完整性 | 1,000 条经验最早相关项仍命中；全量分页无重复/漏项；源码、SQLite integrity/FK 正常 |
| 中文检索 | **失败**：建 FTS 后丢失原先能命中的中文子串 |
| 纠错摘要 | **失败**：完整 handoff 有 disputed，简短下一意图 anchor 丢失警告 |
| 蒸馏长历史 | **失败**：45 条 observation 只显示 40 条，无 ledger continuation |

实际默认召回是词法，不是语义。同义改写“未登录导出账单”和“download bills without login”在本轮样本中均零命中；这是能力边界，不冒充语义模型错误。200/1,000 条未建索引查询分别 0.1155/0.2935 秒；1,000 条 FTS 构建 0.5885 秒、查询 0.3067 秒。单次测量不证明索引提速，更不代表多年积累成本；保存合成规模不是长期收益证据。

## 真实跨会话验收

预期答案未传给模型。A 获得合成原始笔记，结束后只复制目标 Store；B/C 删除原始材料及旧产物，使用独立 project、HOME、runtime、新 session ID。B 有记忆组还加入 30 条无关新经验，相关事实已超出最近窗口。空组新建空 Store。C 在模型启动前通过 owner 保存 r8 更新、条件 supersedes 和新 handoff，包含 `representation=rows_json`；不是要求模型猜隐藏信息。各组只允许本地分析，禁止目标请求，因此本轮证明范围是离线续接应用，不是实网调查能力。

| 会话 | 时间 / CLI turns | 结果 |
| --- | --- | --- |
| A 保存 | 66.842 秒 / 23 | **通过保存**。自主调用 target_memory，5 条 advisory note + 1 条有条件 handoff；不造执行或漏洞 |
| B 有记忆 Autopilot | 209.831 秒 / 6 | **失败**。仅 ListAgents/Glob；未调用 owner 恢复，未用已保存租户/对象/表示。只在回答贴泛化计划，要求的文件未落盘，无增量写回 |
| B 空记忆 Autopilot | 143.481 秒 / 13 | 对照也泛化，未凭空猜中目标细节；同样未写计划文件。不能证明“有记忆”带来收益 |
| C r8 纠错 Autopilot | 110.924 秒 / 17 | **失败**。反复找 scope 路径，写入泛化计划，未读 Store/r8 handoff，未出现 rows_json；`error_max_turns`。还写了“无旧分析文件，所以无旧结论可废止”，与现存经验矛盾 |
| D 无关概念任务 | 17.343 秒 / 1 | **隔离通过**。没有工具调用、没有目标事实泄漏或状态变化；未评价其 SHA-256 科普的全部措辞准确性 |
| E 明确只读恢复 | 45.662 秒 / 18 | **读取与只读通过，入口合规未通过**。通过原生 sqlite `mode=ro` 恢复租户、对象、表示、匿名基线和待授权步骤；未调用 owner CLI，故不证明完整来源健康/纠错语义被执行 |

只读与状态隔离结论覆盖目标 Store revision、业务记录及纳入快照的已有项目文件；不包括 SQLite WAL/SHM 辅助文件和 CLI 自身 HOME/runtime。

六组均无源码变更，SQLite integrity/FK 通过，无 observations/Findings/reports 新增。B/C/D/E revision 均不变。D/E 分组前已有文件哈希均不变。未见 WebFetch/WebSearch 调用；A/E 可见 Bash 均为本地读取或目标内保存，无目标请求。所有 stderr 均为空。六会话 CLI 报告成本合计 **$2.1927775**（CLI 计价估计，不是供应商结算单）。

本轮请求了 `/autopilot`，private runtime critical 同步通过；事后用同固定副本直接复查 bootstrap，三组均 `action=continue`，并未因 runtime drift/缺库拒绝。Bootstrap 紧凑输出不包含本例具体历史事实，因此后续主动恢复不可省。动态命令展开是否完整进入模型上下文未单独截取，不能把上述失败单因归结为某一提示词、原生 6k 或 Store。可见行为已经足以否定“当前自动续接稳定达标”。

## 问题优先级与后续最小方向

1. **P1：Autopilot 实际恢复链未落实。** B/C 没调用 owner，存储正确也没有用上。先在同宿主核对 native command 展开与 Shared Memory Continuity 的实际执行，避免继续堆记忆数据或扩充知识库；再做一次固定场景修复后验收。E 绕过 owner 直接查表也应纳入入口检查。
2. **P2：中文 FTS 造成召回回退。** `tools/recall_index.py:341` 的 unicode61 将连续中文当长词元；`_query_partition():457–473` 完整 MATCH 零命中仍选 FTS 通道，不补子串。例：保存“匿名访问财务导出被拒绝”，查询“匿名”，建索引前有、之后无。应在同一召回 owner 保持可达候选的一致性，再验证中英文排序与分页绑定。
3. **P2：下一意图摘要丢纠错状态。** `tools/target_memory.py:205–208` 仍将被 refutes 的 handoff 列入 advisory next_actions；完整 JSON/文本有 disputed。`tools/context_pack.py:640–646` 抽成文本 anchor 后省掉警告。应让摘要保留原 owner 状态/纠错引用，不另造一个“有效记忆”生命周期。
4. **P2：蒸馏 ledger 裁切无接续。** `tools/distill_target.py:64–80` 只为 Findings/Experience 建 windows；`:100` 的 ledger `[-40:]` 没有同等展开入口。45→40 本轮复现，不能让摘要代表完整证据。

本次职责是验收，未为了绿灯修改上述产品行为，也没有修改预期迁就模型结果。

## 限制与执行偏差

- 未安装 `sentence-transformers`，在所查模型位置未发现合规 manifest；没有 encoder/reranker 的真实正例、top-k 效果或模型离线安全全覆盖。缺模型降级已测。
- 未重做历史迁移/备份还原、真实大库、全部关系 claim 的条件/时间组合、真实知识晋升内容质量、长期多轮 compaction 或统计 A/B。当前结果不能宣称全能力或长期收益通过。
- 文件/进程通过 bubblewrap 隔离，独立只读探针确认 oracle、其它 session 和宿主仓库不可见；网络出口未硬隔离。CLI 默认工具列表也包含未用的网络/协作能力；未将工具许可表当沙箱。
- 只留可见 text/tool_use/tool_result，不存原始 thinking。无旧会话/个人凭据进入模型材料。provider 环境只继承具名变量，不输出值。
- 传入 `--max-turns 16`，A/E 回执 23/18、C 17 后结束；CLI turn 口径与可见 event 不一致。只认 6 分钟外层硬截止和实际回执，未声称 16 个 assistant event 硬限额通过。
- 首次机械扩展中缺库退出码与 partial 字段预期写错、异常格式化触发隔离 guard；按真实 CLI 契约修正 harness 后执行固定版本完整结果。新增产品失败判据不放宽。两次宿主 preflight 在任何模型调用前失败，修复了临时 archive Unicode 路径和首次 sync/prune 参数；六个正式模型样本各执行一次，未重跑筛选。
