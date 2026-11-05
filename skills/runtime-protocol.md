# Shared Runtime Protocol

本协议只定义事实恢复、知识读取和写回；6k 完整 rules 定义调查/迭代/报告正文，
`src-hunter` 接入专项方法，执行义务归对应命令。
不要求每个动作依次经过 Target/Skill/Knowledge/Checks，也不重复常驻契约。

## Shared Knowledge Recall

- `CLAUDE.md` 内嵌的 6k 主契约与十一份原规则完整加载，接线见 `rules/README.md` 和
  `docs/ccst-runtime-adapter.md`。SRC 开场先读 `skills/src-hunter/知识库/打穿短表.md`，
  按当前特征展开完整相关方法；短表是索引，不限制表外探索。
- 当前方法直接读取 `skills/src-hunter/知识库/`，规则直接读取 `rules/`。
  首次实验前读完选中的方法，确定适用前提、关键对照、成立/证伪证据和停止/重开条件。
  短表、目录、搜索命中或文件前缀只用于定位；输出截断就继续读取剩余正文。
  需要补读方法或捕获合同时，先接收并理解完整读取结果，再生成依赖它的请求/执行脚本；
  读取与依赖请求不能放在同一批并行工具调用中。
  已完整读取且仍有效的内容可复用。缺文件明确报告，不用旧库或摘要偷偷补位。
  日常读取不需要 catalog、manifest 或 `hot_method`。
- 新现象、条件变化、旧假设受挫时重新判断信息缺口；纯解释/规划不必查包。
  需要当前目标工作集时用 `python3 tools/context_pack.py --target TARGET --focus '当前问题'`。
  Pack 提供目标事实、证据与已审知识卡目录，不选方法，不把工具信号变成调查路线。
- 方法维护按完整 `rules/hunt-iter.md` 的准入门槛、三问与来源核对，由主会话审核后
  直接修改选定 checkout 的 `skills/src-hunter/知识库/` 正文和必要索引，以 Git 保留差异；
  安装目录副本只读，不在副本维护方法。子代理只提候选。
  私有原件不进共享正文。`knowledge/methods/clown/`、旧 manifest 和 `hot_method.py`
  仅供显式历史读取、维护或恢复，不更新当前原生方法。
- 本地共享卡见 `knowledge/index.md` 或 `/kb`，继续遵守现有审核/晋升协议。
  短卡全文读；长卡读取完整相关机制，再展开来源。卡召回的 `--known-catalog VERSION`
  只在当前上下文确实保留同版卡目录时使用；它不是 `context_pack.py` 参数。
  compaction 后从当前 owner 恢复事实并按需重读材料，不把摘要当已读证明。
- 本目标经验与已审共享知识的检索按 [Problem Recall](#problem-recall)。
  关系路径是待验证假设，不能写 Action/Finding 或授权执行。

九专项是 src-hunter 的内部按需模块；知识读取不抢占真实锁和待回收执行。
历史 related_skills 标签不是可直接调用的原生 Skill；需要定位时经
`python3 tools/skill_reference_contract.py REFERENCE --repo-root ROOT --json` 精确解析当前阅读路径，
再原生 Read 正文。该导航不改卡字节/审核版本，不选择路线或登记查阅。
Queue/Store 不持有 Skill 注册表或知识推荐状态。

## Native Skill Loading

唯一 `src-hunter` 保留原生 description 发现。显式 Autopilot（含 Round）由 Claude
宿主入口送达原文件完整正文；Bootstrap 准入后才能调查，无需依赖模型想起一次 Skill 调用。
同会话续跑复用上下文；压缩/重启通过 SessionStart 恢复同源编号块，循环状态刷新同时恢复 owner 与记忆。
完整正文可复用，不按 lane/round 重复加载；缺失、预览或恢复失败明确报错。
自然语言/manual 入口仍用原生 Skill；无该工具时原生读取完整文件。
description、路径或 hash 不能代替正文，正文送达也不证明方法已正确应用。
在同一会话中携带当前目标/Scope、事实、模式和显式限制（未设则 unset）应用它。
沿用入口已确定的目标类型与 Scope；加载技能不将域名重判为集团发现，启动顺序仍归当前命令。
原生调用示例（填入当前事实，不传占位符）：
`Skill({"skill":"src-hunter","args":"目标类型/Scope=…；新目标或续接/已有材料=…；当前问题/事实=…；deep=…；显式限制或unset=…"})`。
工具 schema 或安装命名空间不同则使用宿主实际暴露的名称。
方法读取按 Shared Knowledge Recall，加载 Skill 或短表不等于已经应用具体方法。

## Shared Memory Continuity

普通对话、hunt、pickup 与 autopilot 共用记忆责任：主动恢复、按需召回、重要节点写回，
不等用户说“记住”；明确只读/预览时不写。模式不改变事实标准或扩大执行范围。

开始、换目标、压缩或重启时从当前 owner 恢复意图、Scope/Auth、未完成工作、当前裁决和交接；
同会话续接复用有效工作集，按执行节点刷新事实。摘要和场景预览不是当前真源，缺历史展示不代表没有经验。
继承的工具限制/准入判断在使用前只查相关当前命令；未核对则标 inherited/unverified，
不通读源码。按原时间戳、时区和精度判事件顺序；历史先后不证明当前可达性。

### 1. Target layer

最小恢复：`python3 tools/target_memory.py show TARGET`；需要整体工作/覆盖时读
`python3 tools/resume.py --target TARGET`。原件与历史通过返回的 ID/命令展开。
Autopilot 启动的 `state.target_memory` 与恢复的 `recovery.state.target_memory`
携带同一 owner 的最小恢复视图与来源绑定，
当前有效时直接使用；更早的相关经验按其中 `experience_window` 命令查询/展开。
换目标、compaction 丢失或 owner 更新后重新恢复，不用文件名搜索或直接 SQL 代替
带纠错、适用条件与来源健康的 owner 视图。无关纯解释不要求查目标，明确只读不写回。
写回显式 `--target TARGET`；active pointer 只选择已初始化目标，不是意图/状态 owner。
缺库、legacy、damaged、fenced 按显式初始化/恢复流程处理，不猜空状态。
`current_handoff` 独立于有界历史；`next_actions` 只取最新交接的显式 `next_intent`，
不是 Queue。使用前对照当前 Action、conditions、review_state、source_health 和纠错关系；
已完成的工作不因旧 next_intent 重新执行。最新不等于仍适用；遇到
disputed/superseded/needs_review，先核对纠错和当前证据，不因此停止独立调查。
Case premise 只是预览，需要它支撑判断时展开当前 Case。缺关键依据按下节召回。

### Problem Recall

选择下一问题、复用旧结论或重复实验前，判断工作集是否含有需要的依据：

- 缺相关历史、准备重试旧路径或压缩后依据不足：按具体问题召回。
- origin、身份、对象、表示或部署条件变化：核对相关经验与反证；旧阴性只覆盖记录的条件，
  变化部分仍需验证。若当前工作集已含完整依据，可直接比较。
- 同问题、相关来源和条件未变化且正文/反证已充分读取：复用，不按请求、工具次数或轮次重查。

用 `python3 tools/experience_recall.py query --target TARGET --query '当前问题' --compact`。
`current` 是独立当前事实，`recalled` 是历史候选；一并消费 `counterevidence` 的相关纠错、
依赖与来源。紧凑输出的完整经验正文、条件和版本在 `recalled[].record`，不重复展示其别名。
条件文字和无反证命中均不证明结论有效。partial/unavailable 不等于没有经验；
依赖的信息仍被裁切时，按返回的来源 ID、精确 version 和该页命令展开后再用。
读取/展开、游标、纠错与索引的操作合同统一见 `commands/target.md#恢复与问题召回`。

### Cognitive Write Timing

| 触发 | 写回 |
|---|---|
| 执行返回/中断 | 即时保存 raw、operation/observation、真实回执；按 owner 完成 Candidate 登记、终态心跳及未知效果回收 |
| 稳定结论、反证、条件变化、证伪、转向/阻塞 | 保存影响后续判断的增量、证据及适用/重开条件；无增量不重复记 |
| 暂停、换目标、compaction、结束 | 保存未落盘判断和明确下一意图；需要续接时写结构化 handoff，完成判断仍归 Coverage/Closure |

写回内容、凭据引用、参数与重试按 `commands/target.md#交接与证据`，区分原始观察、
假设和技术结论。子代理交付增量，主会话接受后写入；只读/预览只返回建议。
不因读 Skill、模式变化、工具次数、lane/round 或 checkpoint cadence 追加认知整理，
不逐观察 note/classify/fusion/重写业务模型。Checkpoint 是只读快照，不是写回频率。
Candidate 和确认 A 的持久化不等 B/C；预算停止新工作，不停止回收、cleanup、心跳和闭合。
跨目标知识走审核晋升，不后台提取聊天、不自动共享目标私有事实。

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

业务规则在完整 6k rules，接口差异在其唯一 runtime adapter；核心组织原生推理，
专项判断在完整内部模块，技巧/反例/案例在方法资料；稳定执行在工具，证据、完成与
发布门在既有工程 owner。报告版式归 6k report-format。完整正文只有一处，其他入口引用。

## 3. Knowledge layer

索引用于发现，方法用于思考，已审共享知识用于有来源的复用；三者不混同。
知识不保存当前目标状态。

## 4. Checks layer

实验结论、阶段总结和交接按 `rules/ccst/coverage-gate.md` 区分 Covered、Leads/Signals、Candidates、
Blocked、Not applicable、Dead ends、Still unknown 和 Next actions。
已测范围写明实际入口、方法、身份/状态及证据；发现数、阅读数和无发现均不证明覆盖。
未测身份/状态、缺少的材料和延期实验保留未知；未做必要验证不写“已完成/已排除”，暂缓不等于证伪。
匿名结果不外推到认证后，未发现入口不等于入口不存在。

## 5. Execution and write-back

调用命令前读匹配执行合同：`docs/tool-index.md#execution-contract-lookup`。
通过既有 owner 登记证据、Action、Finding、技术裁决和交付；Checkpoint 不写这些状态。
普通同会话读取不填交接表；真实委派按 `src-hunter` 的 handoff 合同交付，主会话接受。

尚无 Finding 的观察走 `validation_runner.py record-observation`；已有 Candidate 的证明
走 `record-evidence`。完整捕获、登记、回执消费及失败恢复合同归
`docs/evidence-runners.md#在执行时捕获原件`，首次原生执行前读取。
观察登记不建占位 Finding、不自动解决 Action 或关闭 Coverage；区分未执行、已执行未登记和未知效果。
参数不确定先读所选子命令 `--help`。

执行结果（含后台终态、子代理交付）由主会话读取原件、接受增量并完成对应 owner 写回；
消费回执并完成当前入口要求的状态刷新后，再判断：确认了什么、哪些相关旧判断/阻塞需要重评、
当前有哪些可执行工作。复用有效工作集；缺依据按 [Problem Recall](#problem-recall) 召回。
条件变化先指出改变的具体前提及证据，再展开相关 blocked/延期工作，逐项比较已满足与仍缺的条件；
新增一项事实不等于全部阻塞解除，主题相似也不证明适用。预览窗口不代表全部；未审尾部仍是未知。
将条件已满足的相关工作与其它可执行问题一起比较；保留尚缺条件的方向，不因重评而自动重试。
重开同一 blocked 行动用原 Queue API（CLI `resolve --status queued`），保留行动身份，
用读取时的 Store/version 做 CAS 并消费新版本回执；后续 claim/resolve 使用对应当前回执。
completed/cancelled 不改写，同一执行意图确需重试时另建带 `repeat_of`/`repeat_reason` 的行动。
其他有价值工作保持可查询，低优先级不等于排除；无新依据不重试已结束路径。
普通读取、空轮询和播报不追加全量召回、整理表或认知写回。继续、等待和停止仍归当前入口。

### Stateful Continuity

For leak -> use, login -> token -> action, multi-round oracles and connection-bound
protocols, keep dependent steps in the same process/socket/browser context.
If a process change is necessary, explicitly export/restore complete state.
Cookies, nonces, tokens and oracle rounds do not survive a new invocation by assumption.

## 输出契约

首次使用方法或调查转向时，先用 1–2 句说明当前问题、已完整读取的知识库方法/专项模块文件和关键对照。
重要结果、阻塞或长时间执行/等待时区分实测现象与待验证解释，说明下一步；工具 description 不代替进展正文。
使用实际证据引用和 owner 回执，不重抄每个动作的 Target/Phase/Action/保存表。
未发生的执行不造回执；未知效果保持待回收，专家自报不确认 Finding 或完成 Action。
结束摘要按当前入口合同给一次，不把中途重复总结当作恢复或执行记录。

## 禁止事项

- 不以旧 active target 或压缩摘要代替当前目标、Scope/Auth 和 owner 事实。
- 不默认读全库，不用目录、推荐字段或工具信号冒充已读/已执行/已验证。
- 不把观察、Lead、假设升级为未经证据门的结论。
