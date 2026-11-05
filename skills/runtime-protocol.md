# Shared Runtime Protocol

本协议负责读取、恢复与写回；调查/迭代/报告按 6k rules，专项方法按 `src-hunter`，执行与续跑按当前命令。
各层按需使用，不串成固定流水线。

## Shared Knowledge Recall

- 完整加载 `CLAUDE.md` 的 6k 主契约与十一规则，接线见 `rules/README.md`、`docs/ccst-runtime-adapter.md`。
  SRC 开场读 `skills/src-hunter/知识库/打穿短表.md`，按特征展开完整方法；短表不限制表外探索。
- 当前方法直接读取 `skills/src-hunter/知识库/`，规则直接读取 `rules/`。
  首次实验前读完选中的方法，确定适用前提、关键对照、成立/证伪证据和停止/重开条件。
  索引/搜索命中不等于已读；截断时补完正文。先理解完整方法/捕获合同，再生成依赖请求或脚本，不将读取与依赖执行并行。
  有效全文可复用；缺文件明确报错，不以旧库/摘要补位。日常读取不需 catalog、manifest 或 `hot_method`。
- 新现象、条件变化、旧假设受挫时重新判断信息缺口；纯解释/规划不必查包。
  需要当前目标工作集时用 `python3 tools/context_pack.py --target TARGET --focus '当前问题'`。
  Pack 提供事实、证据与已审知识卡目录，选方法/路线仍由模型判断。
- 方法维护按完整 `rules/hunt-iter.md` 的准入门槛、三问和来源核对；主会话修改 checkout 的
  `skills/src-hunter/知识库/` 及必要索引，Git 保留差异。安装副本只读，子代理只提候选，私有原件不进共享正文。
  `knowledge/methods/clown/`、旧 manifest、`hot_method.py` 只用于显式历史读取/维护/恢复。
- 本地共享卡见 `knowledge/index.md` 或 `/kb`，继续遵守现有审核/晋升协议。
  短卡读全文，长卡读完整相关机制并展开来源。`--known-catalog VERSION` 仅用于已保留同版目录的卡召回，不是 Pack 参数。
  compaction 后从 owner 恢复事实并按需重读材料；摘要不证明已读。
- 本目标经验与已审共享知识的检索按 [Problem Recall](#problem-recall)。
  关系路径只是待验证假设，本身不创建 Action、不确认 Finding 或授权执行；主会话选定验证问题后按 Action 合同登记。

九专项按需读取，不抢占真实锁和待回收执行。历史 `related_skills` 标签用
`python3 tools/skill_reference_contract.py REFERENCE --repo-root ROOT --json` 解析当前路径，再原生 Read，不直接调用旧 Skill。
导航不改卡字节/审核版本、不选路或登记查阅；Queue/Store 不保存 Skill 注册或知识推荐状态。

## Native Skill Loading

`src-hunter` 保留原生 description 发现。Autopilot（含 Round）入口送达完整正文，Bootstrap 准入后调查，不重复调用 Skill。
同会话复用全文；压缩/重启由 SessionStart 恢复同源编号块，循环刷新恢复 owner 与记忆。缺失/预览/恢复失败明确报错。
自然语言/manual 用原生 Skill，无该工具就原生读完整文件。description、路径、hash 不代替正文；已送达不等于正确应用。
携带入口的目标类型/Scope、当前事实、模式及显式限制（未设为 unset）；不重判范围或改变启动顺序。
原生调用示例（填真实值；工具名/schema 以宿主为准）：
`Skill({"skill":"src-hunter","args":"目标类型/Scope=…；新目标或续接/已有材料=…；当前问题/事实=…；deep=…；显式限制或unset=…"})`。
具体方法仍按 Shared Knowledge Recall 完整读取。

## Shared Memory Continuity

普通对话、hunt、pickup、autopilot 都主动恢复、按需召回、重要节点写回；只读/预览不写，不扩大范围或改变事实标准。
开始、换目标、压缩/重启时从当前 owner 恢复意图、Scope/Auth、未完成工作、裁决和交接；同会话复用有效工作集，按执行节点刷新。
摘要/预览不是真源，未展示历史不等于没有经验。继承的工具限制用前核对相关当前命令，未核对标 inherited/unverified，不通读源码。
事件顺序按原时间戳、时区和精度；历史先后不证明当前可达性。

### 1. Target layer

最小恢复用 `python3 tools/target_memory.py show TARGET`，整体工作/覆盖用 `python3 tools/resume.py --target TARGET`。
Autopilot 的 `state.target_memory` / `recovery.state.target_memory` 是同一 owner 的绑定视图，有效时直接用；历史按 `experience_window` 或返回的 ID/命令展开。
换目标、上下文丢失或 owner 更新后重新恢复；文件名搜索/直接 SQL 不代替含纠错、条件和来源健康的 owner 视图。无关解释不查目标。
写回显式 `--target TARGET`；active pointer 只选择已初始化目标。缺库、legacy、damaged、fenced 按显式初始化/恢复处理，不猜空状态。
`current_handoff` 独立于历史窗口；`next_actions` 只取最新交接的显式 `next_intent`，不是 Queue。
用前对照当前 Action、conditions、review_state、source_health 和纠错；旧意图不重执行已完成工作。
disputed/superseded/needs_review 先核对当前证据，不阻止独立调查；Case premise 支撑判断前展开当前 Case。

### Problem Recall

选下一问题、复用结论或重试前检查依据：缺历史/压缩后依据不足则按问题召回；origin、身份、对象、表示或部署变化则核对经验与反证，旧阴性仅覆盖原条件。
当前依据充分时直接比较；同问题、来源、条件未变则复用，不按请求、工具次数或轮次重查。

用 `python3 tools/experience_recall.py query --target TARGET --query '当前问题' --compact`。
`current` 为独立当前事实，`recalled[].record` 含历史正文/条件/版本；同时消费 `counterevidence` 的纠错、依赖与来源。
条件文字或未命中反证不证明有效；partial/unavailable 不等于无经验。依赖信息被裁切时按来源 ID、精确 version 和页命令展开。
读取、游标、纠错和索引操作见 `commands/target.md#恢复与问题召回`。

### Cognitive Write Timing

| 触发 | 写回 |
|---|---|
| 执行返回/中断 | 即时保存 raw、operation/observation、真实回执；按 owner 完成 Candidate 登记、终态心跳及未知效果回收 |
| 稳定结论、反证、条件变化、证伪、转向/阻塞 | 保存影响后续判断的增量、证据及适用/重开条件；无增量不重复记 |
| 暂停、换目标、compaction、结束 | 保存未落盘判断和明确下一意图；需要续接时写结构化 handoff，完成判断仍归 Coverage/Closure |

内容、凭据引用、参数和重试按 `commands/target.md#交接与证据`，区分观察、假设、结论；子代理增量由主会话接受后写入。
读 Skill、模式/轮次变化、工具次数和 Checkpoint 不触发额外整理；Checkpoint 只读，不逐观察另写 note/classify/fusion/业务模型。
Candidate 和已确认 A 及时保存，不等 B/C；预算结束仍回收证据、cleanup、心跳和闭合。
跨目标知识走审核晋升，不后台提取聊天或自动共享私有事实。

## 2. Skill layer

新会话、角色或权限改变后，按 `rules/dig-scope-workflow.md` §4.2.3 的会话后规则重新判断业务对象与可检验路径。
缺双身份先核对授权范围内能否准备测试账号/对象；实际不可获得才记局部阻塞，不把匿名拒绝沿用到新身份。

### 2.1 三模式决策：Discovery / Exploitation / Validation modes

Discovery 主动补证据；Exploitation 检查已有信号及连接；Validation 证明 Candidate 的边界与影响。
三者按当前问题切换，不按固定阶段走，不因切换写新状态/心跳；真实 Round 的义务不变。

### 2.2 Web 深水区启发式路由

按问题读取完整方法或 `knowledge/playbooks/web2-evidence-contracts.md`：
`boundary -> baseline -> hidden surface -> primitive -> connector -> impact`。
每个连接保留支持/反对证据；HTTP 200、框架名、parser error 或工具命中单独只是 Signal。

### 2.3 层级归属标准

6k rules 管业务/报告，runtime adapter 管接口差异，原生推理选路，内部模块与方法资料提供专项/技巧/反例；工具执行，既有 owner 管证据、完成和发布。正文单源，其余引用。

## 3. Knowledge layer

索引用于发现，方法用于思考，已审知识用于有来源的复用；知识不保存当前目标状态。

## 4. Checks layer

结论、阶段总结和交接按 `rules/ccst/coverage-gate.md` 区分 Covered、Leads/Signals、Candidates、Blocked、Not applicable、Dead ends、Still unknown、Next actions。
已测范围须有实际入口、方法、身份/状态与证据；数量或无发现不证明覆盖。未测/缺材料/延期保持未知，暂缓不算证伪；匿名结果不外推到认证后，未发现入口不证明不存在。

## 5. Execution and write-back

调用前按 `docs/tool-index.md#execution-contract-lookup` 读匹配合同，参数不明读该子命令 `--help`。
证据、Action、Finding、裁决和交付经各 owner 登记；真实委派按 `src-hunter` handoff 交付，普通读取不填表。
首次原生执行前读完整 `docs/evidence-runners.md#在执行时捕获原件`，按其捕获、登记、消费回执和恢复。
无 Finding 的观察用 `validation_runner.py record-observation`，已有 Candidate 的证明用 `record-evidence`。
登记不建占位 Finding、不自动解决 Action 或关闭 Coverage；区分未执行、已执行未登记、未知效果。

执行结果（含后台终态、子代理交付）由主会话读取原件、接受增量并完成对应 owner 写回；
消费回执并完成入口要求的刷新后，判断新增事实、相关旧判断/阻塞和可执行工作；缺依据按 [Problem Recall](#problem-recall) 召回。
条件变化时指出前提及证据，展开相关 blocked/延期工作，比较已满足与仍缺的条件；新事实或主题相似不自动解除阻塞。
条件已满足的工作与独立问题一起比较，其余方向保留；预览不是全部，未审尾部仍未知。
重开 blocked 用原 Queue API（`resolve --status queued`），保留行动身份，以读取时的 Store/version 做 CAS；消费新版本回执后再 claim/resolve。
completed/cancelled 不改写；同一执行意图确需重试时另建 `repeat_of`/`repeat_reason` 关联行动，无新依据不重试已结束路径。
其他有价值工作保持可查询，低优先级不等于排除。读取/空轮询/播报不追加全量召回、整理表或认知写回；继续、等待、停止归入口。

### Stateful Continuity

登录→token→行动、泄露→使用、多轮 oracle 或连接绑定协议，依赖步骤保持同一进程/socket/浏览器上下文。
必须切换时显式导出/恢复完整状态，不假设 Cookie、nonce、token 或 oracle 轮次跨调用保留。

## 输出契约

首次用方法或转向前，用 1–2 句说明问题、已完整读取的方法/模块文件及关键对照。
重要结果、阻塞或长时间执行/等待时说明实测、待验证解释和下一步；工具 description 不代替进展。
使用实际证据和 owner 回执，不逐动作抄表或编造执行；未知效果待回收，专家自报不确认 Finding/完成 Action。
结束摘要按入口给一次，不以中途总结代替恢复或执行记录。

## 禁止事项

- 不以旧 active target 或压缩摘要代替当前目标、Scope/Auth 和 owner 事实。
- 不默认读全库，不用目录、推荐字段或工具信号冒充已读/已执行/已验证。
- 不把观察、Lead、假设升级为未经证据门的结论。
