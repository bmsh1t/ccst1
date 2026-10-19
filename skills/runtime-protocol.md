# Shared Runtime Protocol

本协议只定义事实恢复、知识读取和写回；调查方法归 `src-hunter`，执行义务归对应命令。
不要求每个动作依次经过 Target/Skill/Knowledge/Checks，也不重复常驻契约。

## Shared Knowledge Recall

- 按信息缺口查方法：新现象、条件变化、旧假设受挫时重新判断；已读且有效的材料复用。
  纯解释/规划不必查包，目标事实不能用通用知识猜测；需要工作集时用
  `python3 tools/context_pack.py --target TARGET --focus '当前问题'`。
- 完整目录供 AI 自选，不用关键词、固定 top-k 或强制短表选路。知识没有覆盖的面仍可探索；
  query/body/header/cookie/path/文件等输入均在视野内，未测部分保持 unknown。
- 本地卡见 `knowledge/index.md` 或 `/kb`；6k 方法见 `knowledge/methods/clown/README.md`
  和 `knowledge/clown-hot-method-manifest.json`。用目录给出的 `read_command` 取得回答当前问题的
  完整方法：`hot_method.py --read RELATIVE --expected-manifest HASH --json` 在同一锁内捕获、
  校验并返回正文/上下文，不是先验 hash 再打开可变路径。目录不是已读证明；短表指针要展开
  完整相关方法，表外仍可调查，不必先读来源 SKILL。方法保持前提、顺序、成功证据、反例和停止/重开条件。
- `hot_methods` 的 guide/index、完整未排名目录及 manifest 版本不因 focus 或已知卡目录省略。
  从当前 CCST checkout 运行，或显式 `--repo-root`；安装的 Skill 不提供仓库定位，禁止猜其它副本。
  版本冲突重新取目录；`pending_update` 只显式 recover，读取不修复。missing/changed/invalid_manifest
  不冒充可用正文或技术阴性，也不阻断已有 Store 事实恢复；`origin_only` 只准 `--origin` 溯源，
  不当活动方法。`source_incomplete`/`private_source_unavailable` 明示缺损/无法独立复核，hash 正确不等于准入。
- A 维护按当前 `knowledge/methods/clown/references/hunt-iter.md` 完整门槛及三问：主会话独立核对
  实际来源，只由 `hot_method.py --apply` 发布唯一方法/必要索引并保留真实审核身份；子代理仅提议。
  私有原件不进共享版本，治理参考/Skill/Rules 和已审共享卡仍走各自审核，不借方法维护放宽。
- 卡召回接口的 `--known-catalog VERSION` 仅在当前上下文确实保留同版卡目录时使用，
  不是 `context_pack.py` 的参数，也不省略 6k 方法目录。compaction/summary 后不复用此标记，
  从当前 owner 恢复事实并重查需要的方法及引用，不信任压缩摘要中的旧选读判断。
- 经验与现场冲突时核对适用条件。按问题召回：
  `python3 tools/experience_recall.py query --target TARGET --query '当前问题'`。
  `current` 是独立的当前事实；`recalled` 是本目标经验与已审共享知识，不互相顶替。
  partial/unavailable 不等于没有经验，登记目录也不是审核证明。
- 按 owner 返回的命令、来源 ID 和游标展开；query 排名游标不与 history 游标混用。
  精确版本纠错、来源、反证和关系使用 `commands/target.md` 的相关子命令。
  查询不构建索引、迁移或下载模型；显式建设才使用已提供的真实模型，缺模型明示 unavailable。
  关系路径是待验证假设，不能写 Action/Finding 或授权执行。

Autopilot 先完成当轮 Bootstrap，再为选定工作补充方法；查知识不抢占真实锁和待回收执行。
唯一 src-hunter 通过平台原生 description 发现，九专项是其内部按需模块。
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

`skills/src-hunter/SKILL.md` 是唯一全局调查核心；专项只回答当前问题，不接管目标。
知识提供完整方法；工具保存执行事实；规则处理完成和交付。无固定六域前置表、调用表或路由审计。

### 2.1 三模式决策：Discovery / Exploitation / Validation modes

Discovery 主动补证据；Exploitation 检查已有信号及连接；Validation 证明 Candidate 的边界与影响。
三者按当前问题切换，不按固定阶段走，不因切换写新状态/心跳；真实 Round 的义务不变。

### 2.2 Web 深水区启发式路由

按问题读取完整方法或 `knowledge/playbooks/web2-evidence-contracts.md`：
`boundary -> baseline -> hidden surface -> primitive -> connector -> impact`。
每个连接保留支持/反对证据；HTTP 200、框架名、parser error 或工具命中单独只是 Signal。

### 2.3 层级归属标准

全局调查判断在唯一核心 Skill；专项判断在完整内部模块；技巧/反例/案例在方法资料；
稳定执行在工具；证据、完成和报告门在既有规则。完整正文只有一处，其他入口引用。

## 3. Knowledge layer

索引用于发现，方法用于思考，已审共享知识用于有来源的复用；三者不混同。
短卡全文读，长文读完整相关机制，再按需展开来源，不通读全库。知识不保存当前目标状态。

## 4. Checks layer

结束按 `rules/coverage-gate.md` 区分 Covered、Leads/Signals、Candidates、Blocked、
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
