# Shared Runtime Protocol

本协议只定义事实恢复、知识读取和写回；6k 完整 rules 定义调查/迭代/报告正文，
`src-hunter` 接入专项方法，执行义务归对应命令。
不要求每个动作依次经过 Target/Skill/Knowledge/Checks，也不重复常驻契约。

## Shared Knowledge Recall

- `CLAUDE.md` 内嵌的 6k 主契约与十一份原规则完整加载，接线见 `rules/README.md` 和
  `docs/ccst-runtime-adapter.md`。SRC 开场先读 `skills/src-hunter/知识库/打穿短表.md`，
  按当前特征展开完整相关方法；短表是索引，不限制表外探索。
- 当前方法直接读取 `skills/src-hunter/知识库/`，规则直接读取 `rules/`。
  保留前提、步骤、成功证据、反例和停止/重开条件；目录不能冒称正文已读。
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
- 经验与现场冲突时核对适用条件。按问题召回：
  `python3 tools/experience_recall.py query --target TARGET --query '当前问题'`。
  `current` 是独立当前事实，`recalled` 是本目标经验与已审共享知识，不互相顶替。
  partial/unavailable 不等于没有经验，登记目录也不是审核证明。
- 按 owner 返回的命令、来源 ID 和游标展开；query 排名游标不与 history 游标混用。
  精确版本纠错、来源、反证和关系使用 `commands/target.md` 的相关子命令。
  查询不构建索引、迁移或下载模型；显式建设才使用已提供的真实模型，缺模型明示 unavailable。
  关系路径是待验证假设，不能写 Action/Finding 或授权执行。

唯一 src-hunter 保留平台原生 description 发现；显式 Autopilot 调查使用它，加载与复用遵守
`commands/autopilot.md#investigation-skill`（round 共享同一入口）。先完成当轮 Bootstrap 与必要
执行恢复，再选择新调查；查知识不抢占真实锁和待回收执行。九专项是其内部按需模块。
历史 related_skills 标签不是可直接调用的原生 Skill；需要定位时经
`python3 tools/skill_reference_contract.py REFERENCE --repo-root ROOT --json` 精确解析当前阅读路径，
再原生 Read 正文。该导航不改卡字节/审核版本，不选择路线或登记查阅。
Queue/Store 不持有 Skill 注册表或知识推荐状态。

## Shared Memory Continuity

普通对话、hunt、pickup 与 autopilot 共用记忆责任：主动恢复、按需召回、重要节点写回，
不等用户说“记住”；明确只读/预览时不写。模式不改变事实标准或扩大执行范围。

开始、切换或续接时从当前 owner 恢复意图、Scope/Auth、未完成工作、当前裁决和交接；
有效工作集可复用。摘要和场景预览不是当前真源，缺历史展示不代表没有经验。
继承的工具限制/准入判断在使用前只查相关当前命令；未核对则标 inherited/unverified，
不通读源码。按原时间戳、时区和精度判事件顺序；历史先后不证明当前可达性。

### Cognitive Write Timing

| 触发 | 写回 |
|---|---|
| 执行返回/中断 | 即时保存 raw、operation/observation、真实回执；按 owner 完成 Candidate 登记、终态心跳及未知效果回收 |
| 稳定结论、反证、条件变化、证伪、转向/阻塞 | 保存影响后续判断的增量、证据及适用/重开条件；无增量不重复记 |
| 暂停、换目标、compaction、结束 | 保存未落盘判断和明确下一意图；需要续接时写结构化 handoff，完成判断仍归 Coverage/Closure |

不因读 Skill、模式变化、工具次数、lane/round 或 checkpoint cadence 追加认知整理；
不逐观察 note/classify/fusion/重写业务模型。Checkpoint 是只读快照，不是写回频率。
Candidate 和确认 A 的持久化不等 B/C；预算停止新工作，不停止回收、cleanup、心跳和闭合。
原始观察、假设、技术结论分开；dead-end 必须有条件和重开条件。跨目标知识走审核晋升，
不后台提取聊天、不自动共享目标私有事实。

### 1. Target layer

最小恢复：`python3 tools/target_memory.py show TARGET`；需要整体工作/覆盖时读
`python3 tools/resume.py --target TARGET`。原件与历史通过返回的 ID/命令展开。
写回显式 `--target TARGET`；active pointer 只选择已初始化目标，不是意图/状态 owner。
缺库、legacy、damaged、fenced 按显式初始化/恢复流程处理，不猜空状态。
参数、收据、失败重试和纠错详情见 `commands/target.md`，实际调用前只读相关合同。

`current_handoff` 独立于有界历史；`next_actions` 只取最新交接的显式 `next_intent`，
不是 Queue，旧意图不因仍可召回就变成待办。保存使用 `handoff --conditions ...`
`--next-intent ... --operation-ref OPERATION_ID:0`；operation-ref 可重复，必须绑定当前目标
已登记 observation。没有登记证据的内容仍是建议；补 expected 不补足证据、不确认 Finding。
纠错用精确版本的 link/retract-link，保留不同条件与历史，不自动完成其他 owner 工作。

## 2. Skill layer

`skills/src-hunter/SKILL.md` 是唯一调查入口；完整 6k rules 提供业务规则，专项只回答当前问题。
知识提供完整方法；工具保存执行事实；规则处理完成和交付。无固定六域前置表、调用表或路由审计。
加载 Skill/短表不等于已展开方法；选择新问题时读取并应用匹配正文，当前上下文完整可复用。
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
短卡全文读，长文读完整相关机制，再按需展开来源，不通读全库。知识不保存当前目标状态。

## 4. Checks layer

结束按 `rules/ccst/coverage-gate.md` 区分 Covered、Leads/Signals、Candidates、Blocked、
Not applicable、Dead ends、Still unknown 和 Next actions；无发现不是覆盖证明。

## 5. Execution and write-back

调用命令前读匹配执行合同：`docs/tool-index.md#execution-contract-lookup`。
通过既有 owner 登记证据、Action、Finding、技术裁决和交付；Checkpoint 不写这些状态。
普通同会话读取不填交接表；真实委派按 `src-hunter` 的 handoff 合同交付，主会话接受。

尚无 Finding 的原生观察走 `validation_runner.py record-observation`，按
`docs/evidence-runners.md#native-observation-registration` 保存原件、有序步骤和真实 operation 引用；
`result=""` 无裁决，不建占位 Finding、不自动解决 Action 或关闭 Coverage。
已有 Candidate 的证明仍走独立 `record-evidence`。登记失败只重试登记；同次执行补证沿用
attempt、完整快照和原 `expected_operation`，不重放未知网络效果，也不伪造 `:0` 引用。
参数不确定先读所选子命令 `--help` 或 evidence-runners 的速查；区分未执行、已执行未登记和未知效果。

### Stateful Continuity

For leak -> use, login -> token -> action, multi-round oracles and connection-bound
protocols, keep dependent steps in the same process/socket/browser context.
If a process change is necessary, explicitly export/restore complete state.
Cookies, nonces, tokens and oracle rounds do not survive a new invocation by assumption.

## 输出契约

使用实际证据引用和 owner 回执，不重抄每个动作的 Target/Phase/Action/保存表。
未发生的执行不造回执；未知效果保持待回收，专家自报不确认 Finding 或完成 Action。
结束摘要按当前入口合同给一次，不把中途重复总结当作恢复或执行记录。

## 禁止事项

- 不以旧 active target 或压缩摘要代替当前目标、Scope/Auth 和 owner 事实。
- 不默认读全库，不用目录、推荐字段或工具信号冒充已读/已执行/已验证。
- 不把观察、Lead、假设升级为未经证据门的结论。
