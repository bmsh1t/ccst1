# Skills 四层运行协议

本协议定义 Target、Skill、Knowledge、Checks 与 Write-back 的共享责任，不要求每次
行动依次经过各层，也不替 Claude Code CLI 主会话选择具体测试类别。

本协议只定义共享路由，不重复加载或改写平台常驻契约。

## Claude Code CLI 职责边界

| 层 | 唯一职责 | 加载边界 |
|---|---|---|
| `CLAUDE.md` | 授权、AI/工具边界、状态 owner、入口路由 | 仓库启动时常驻 |
| 本协议 | 事实恢复、按需读取、执行与写回边界 | Context Pack 共享必读 |
| 全部 Skill（调查核心 `src-hunting` 与专项） | 决策契约、路线、证据门 | 原生 Skill 工具按需加载（description 路由） |
| 知识卡/参考资料 | 模式、技巧、证据门和发散思路 | 全量目录可发现，AI 按信息缺口读取 |
| Rules / checks | Coverage、Validation 和 Reporting gate | 按动作与阶段读取 |
| Tools / state owners | 确定性执行、原始证据、生命周期和恢复 | 调用或写回时执行 |

Claude Code CLI 当前主会话保留最终路线判断权。本协议、Skill/Card 和工具输出
都不能建立第二个 controller 或 target-state owner。

## Shared Knowledge Recall

记忆扩大思考的材料，不限制思考的边界；召回时机跟随信息缺口，不是固定顺序
里的一道工序。两种入口共用这一条判断：

- substantive 的判据只有一条：该动作会触及目标或写入 owner 状态（发请求、记录
  evidence、queue 写回）；纯解释、规划、复盘不触发召回。
- recall 跟随信息缺口，不跟随每个思维步骤：新现象、条件变化、旧假设受挫时召回；
  相关材料已在上下文中就直接思考，不重复调用。查包与否以信息增量为唯一判据，
  不引入“什么算基础知识”的类别判断。通用判断不需要先找到一张卡来证明可以
  思考——但当前目标、范围和 owner 事实（目标记忆、surface、coverage）仍必须
  读取/恢复，不能用通用知识猜测现场状态。需要目标状态或事实投影时按
  `commands/context-pack.md` 调用
  `python3 tools/context_pack.py --target TARGET --focus FOCUS`（卡片目录在
  Pack 中全量发布，选择权在 AI）。宽泛目标先沿既有目标上下文/发现入口补证据，
  不预选专项卡。
- 经验与当前证据冲突时，重新验证经验的适用条件，不默认任何一边。
- 所有用户可控输入（URL 参数、body、header、cookie、路径、JSON 字段、文件名……）
  都进入覆盖视野，不因历史经验只提到某些位置而忽略其他输入；验证顺序由当前证据
  决定，未测试部分在 Coverage 里明确保留为 unknown，不用抽样冒充完整覆盖。
- 目录路径不等于文件已读：选中的 Skill 和当前需要的卡若正文不在上下文中，先读取再
  行动；已读正文不重复加载。
- 同一 target/focus/实质证据可复用；目标、focus 或实质证据变化时重新判断并按需刷新。
  会话上下文压缩（compaction/summary）后，对话内既有的选读判断和 Pack 引用按过期处理：
  重建判断以当前磁盘上的 owner 状态为准，按当前 owner 重新核对事实与引用，不从压缩摘要里复用旧判断。
- Autopilot 先完成 bootstrap 和 state read，再在 substantive lane 选择后执行这条判断；bootstrap
  不等于已有匹配 Pack 或知识卡已读，也不因召回而抢占 owner 选定的初始工作。
- 从完整 `card_catalog` 按信息缺口选读，也可用 `knowledge/index.md` 或 `/kb` 查找。
  短卡读完整正文；长卡读包含前提、方法、证据门、反例和停止条件的完整判断单元，
  再按需展开来源。不设固定选卡或补读上限，不新增持久化加载状态。
- 按问题召回使用 `python3 tools/experience_recall.py query --target TARGET --query '当前问题'`。
  `current` 独立恢复当前目标/Scope、意图、交接、活动工作和裁决，不参与历史排序；`recalled`
  只含本目标经验与绑定当前发布字节审核回执的共享知识。登记目录仅是发现面，不是审核证明。
  `health` 区分知识、词法索引、本地语义/重排与当前事实的可用性；partial/unavailable 不等于无经验。
- 查询结果按自身 `pagination.next_cursor` 翻页，`--source-ref experience:ID` 或 `knowledge:ID`
  展开完整来源。原始历史页使用 `history --target TARGET --cursor CURSOR` / `--id EXPERIENCE_ID`；
  它使用 Store 游标，不能与 query 的来源/排序绑定游标互换。优先使用 owner 返回的完整命令。
- 索引只由显式 `index-build` / `relation-build` 建设；查询和 checkpoint 不构建、迁移或下载。
  模型必须是明确提供且已批准使用的本地目录（`--encoder-path` / `--reranker-path`）；未提供时
  明示 unavailable，不用哈希向量假冒语义。`relation-query --seeds @entities.json` 只接受精确实体，
  每条路径带来源/反证和条件缺口，始终是待验证假设，不授权执行、不写 Action/Finding。
  真实模型收益、默认组合与发布尚未验收，不能把入口存在当作通过。

卡片保持独立，提供模式、反例和证据提示；Skill 保留路线和证据门，不复制卡片正文。

Context Pack 全量发布 `card_catalog`；`knowledge_cards`、`deferred_knowledge_cards`、
`knowledge_card_recall` 恒空，仅保留字段兼容，不等待推荐或 deferred 补发。skill 推荐壳字段
（`selected_skill`/`skill_route`/`selected_skill_id`/`why_this_skill`）已删除，
skill 可发现性由平台技能面原生持有，pack 不发布 skill 目录。它们从来不是已选择的执行
状态，也不进入默认 `must_read` 或自动写入 Queue。Skill 的选择与加载由 AI 通过原生
Skill 工具完成（frontmatter description 是发现面）。Queue/Store 不持有 Skill 注册表、
不检查 Skill 文件或预设维度、不登记自报调用审计；`active_dimension` 与 Runner 的
`tested_dimensions` 继续分别表示实验意图与真实观察。

`hypothesis_seeds` 和 `alternative_angles` 是恒空的
兼容字段（静态建议已退役，2026-09-13 原生能力审计）：假设由 AI 在真实证据和
完整卡片上自己提出，不从 seed 生成 Queue 动作。Action Queue 的
`selected_knowledge_refs` 是 AI 的知识判断：可以引用 focus 匹配的任意卡，改选不属于
默认 refs 的卡不需要理由；唯一的机械校验是引用的卡文件必须真实存在（防笔误与伪造），
不校验与 item 默认 refs 的子集关系。

Context Pack 还可发布 `hot_methods` 只读指针：它们来自仓库登记的本地 clown 快照，
带 `source_id`、相对路径、期望/实际 hash 和 `ready`、`missing`、`changed` 或
`invalid_manifest` 状态。只有 `ready` 指针可供 AI 按信息缺口读取；指针不复制正文、
不写 Store、不生成 Action/Finding、不授予权限，也不把漂移源当成共享知识。源不可用时，
本仓 card catalog、目标事实、证据和经验仍是有效的恢复路径。

## 决策闭环

以下是可回退的判断环，不是固定执行顺序：

```text
Target context -> evidence-backed route -> smallest bounded action
              -> raw evidence / owner receipt -> next question / stop / reopen
```

认知整理和交接遵循下方 Cognitive Write Timing，不是每个动作的尾置步骤。

## Shared Memory Continuity

普通对话、`/hunt`、`/pickup` 与 `/autopilot` 共用本节的记忆责任：Claude 主动恢复、
按需召回并在重要节点写回，不等待用户输入“记住”或记忆命令。模式只决定是否持续自主
推进任务，不降低记忆能力，也不因保存记忆而扩大本轮执行范围；明确只读或预览时不写回。

开始、切换或续接目标工作时，从当前目标 owner 恢复事实、目标、假设、线索、下一步和
交接；已在上下文且仍有效的信息直接复用。摘要或 `/pickup` 的场景预览不替代真源，缺少
判断条件时按返回的目标记忆路径展开，不凭“没有运行历史”推断目标没有经验。

恢复时区分原始观察与继承判断。将旧交接中的工具限制、准入门槛或下一操作约束用于
行动或写入新交接前，只核对该操作的当前命令契约（如涉及 `/validate`，读
`commands/validate.md` 的相关段落），不全量读源码或命令文档；未核对的说法标为
“继承、未核实”，不能断言为当前限制。比较原记录时间戳判断事件先后，注明来源、时区
和精度；缺失或不可比较才保留顺序未知。记录中的先后关系不证明当前可达性，当前
可达性未知也不抹去可判定的历史顺序。

记忆分层契约见 `docs/architecture-contract.md#memory-contract`：观察、工作集、目标经验和
跨目标知识是责任分层，不是每轮要执行的四道命令。工作集留在当前上下文，其余材料保留
可展开引用；当前事实优先直读，相关经验按问题检索并保留适用条件。

### Cognitive Write Timing

状态连续性与学习复利都保留，只改变认知写回时机：

| 触发 | 应做的工作 | 不追加的仪式 |
|---|---|---|
| 请求/工具返回、执行完成或中断 | 即时保存原始证据、operation/observation 与真实回执；按 owner 合同登记 Candidate、resolve/kill、回收未知效果及终态心跳 | 不为普通观察逐条 note、classify/fusion、重写业务模型或手填结果表 |
| 稳定结论、新反证、适用条件改变、路径明确证伪或转向/阻塞 | 保存会影响后续判断的认知增量、证据引用、适用/重开条件；没有新增判断时复用已有记录 | 不因工具次数、lane/round 计数、模式切换或 checkpoint cadence 触发整理 |
| 暂停、切换目标、主动压缩上下文或结束 | 保存尚未落盘的重要判断和明确的下一意图；需要续接时写现有结构化 handoff；结束覆盖判断仍由 Coverage/Closure owner 持有 | 不把已存回执、旧摘要、无变化的判断重复写成新经验 |

这不是延迟执行落账：Candidate 已达到登记条件就保存，确认 A 不等待 B/C；Action
终态和 Round 心跳仍按原合同完成。读 Skill、自然转向和只读 Checkpoint 不产生额外记忆
写入要求。Checkpoint cadence 只控制只读状态快照，不是认知整理、蒸馏或晋升的频率。
若尚未保存的判断即将丢失，先走现有 handoff；明确只读/预览时仍不写回。

观察、假设、已验证结论各有 owner（Store observation / Experience 假设字段 /
validation+finding），不把猜测写成事实；dead-end 保留适用条件和重开条件。可复用经验
在事件或结束边界进入 `/distill` 草稿，通用知识仍经人工审核晋升，不新增后台提取、
自动共享或逐条聊天入库。

纠错通过 `target_memory.py link` / `retract-link` 绑定精确经验版本与条件，保留历史；
来源通过 `sources`、`version` 和 `entity` 展开。被反驳/替代/坏来源不是“从未发生”，
不同条件的阴性不互相覆盖；关系不会自动确认 Finding、完成 Action 或改变报告资格。

### 1. Target layer

以本轮明确的目标运行 `python3 tools/target_memory.py show TARGET`，确认目标意图、
最近经验的适用/重开条件和可展开 ID；Store 目标不能把旧 JSON 的 mode/phase
当作当前事实。
写回显式传 `--target TARGET`；需要无参入口时先用 `target_memory.py set TARGET` 设置正确的
active target（目标必须已初始化）。`/pickup` 与 Context Pack 是读取入口，不会替你切换 active target。
隔离数据根使用 `target_memory.py --repo-root ROOT --json COMMAND ...`（两个选项也可放在
子命令后）。写入 JSON 返回 `target` 和 Store `receipt`，重放保留原实体并标记 `replayed`；
`show --json` 返回同一记忆投影。`set --goal` 已提交但目标选择失败时，错误仍带收据和
`selection_status=failed`，使用原 command ID、内容及 expected revision 重试，不创建第二条意图。
目标尚未明确时先确认，不用旧 active target 替代当前用户意图。

`current_handoff` 是按 `created_at DESC, id DESC` 取得的最新交接，不受 5/20 条历史窗口影响。
`next_actions` 仅保留该交接显式 `next_intent`（未填则为空），不是 Queue 或执行优先级；
旧意图保留在历史中，不能因仍可召回就当作当前待办。用 `handoff --conditions ...
--next-intent ... --operation-ref OPERATION_ID:0` 写回，operation-ref 可重复且必须属于当前
目标的既有 observation；无绑定的正文证据位置仍只是建议。观察、判断、尚缺证据分别说明，
补 `expected` 不等于补足技术证据，记忆写入不确认 Finding、不自动晋升知识。
Autopilot 每次启动都按 `commands/autopilot.md` 执行当轮 Bootstrap，旧快照不能代替预检。

## 2. Skill layer

主会话根据目标和证据选择路线：`src-hunting` 唯一负责全局问题、竞争解释、实验和转向；
`web2-recon` 回答暴露面问题，Web/API 方法证据门在 `knowledge/playbooks/web2-evidence-contracts.md`，
`credential-attack` 负责有 preflight 的凭据验证，`triage-validation` 负责 Candidate
证明。Skill 提供决策契约，不把知识库或工具清单变成固定流程。

### 2.1 三模式决策：Discovery / Exploitation / Validation modes

Evidence-driven depth does not mean evidence-only testing。证据驱动用于决定哪里值得深入；
证据弱或覆盖薄时，Skill 必须使用 Discovery-driven discovery actively generate new evidence。

- **Discovery mode**：从浏览器观察的 APIs、JS/source routes、API docs、组件/CVE
  intelligence、角色/对象矩阵、业务工作流和历史记忆中补最小攻击面证据；目标是把
  `unknown` 推进为 `lead`、`signal`、`blocked` 或 `dead-end`。
- **Exploitation mode**：已有 host/path/parameter/component/behavior 信号时，只围绕
  该证据做最小 replay、差异、同类扩展或链式验证。
- **Validation mode**：Candidate 质量足够时，用最低影响证据证明安全影响并完成
  `/validate` 或报告前 gate。

模式切换不需要显式 review 仪式：三种模式是思考框架，AI 在 Evidence / Next question /
Stop condition 不再匹配当前模式时直接切换。已有受管理执行的 Round 心跳继续携带
`decision`/`next_action`；纯思考/读 Skill 不制造心跳，不因切换新建 checkpoint、
transition 字段或第二套状态机。

AI selection / override 是能力上限保护：当前 Skill 可以跳过建议路线、组合知识卡、创建
新的 action 类型，或局部重排模式顺序；选择在当前上下文中保留理由、下一步验证动作和
停止条件。真实 claim/委派仍按其 owner 合同填写 decision reason，不为每次选读另存表格。
执行事实由 Store attempt/operation 与原始材料引用证明；Skill 的选择和加载走
平台原生能力，Action 不要求路由字段或预设维度清单。

### 2.2 Web 深水区启发式路由

只有在目标证据命中复杂边界时，才读取 `knowledge/playbooks/web2-evidence-contracts.md` 或具体 reference。通用
决策形状为：

```text
boundary -> baseline -> hidden surface -> bug family -> primitive -> connector -> impact
```

链式推理保留证据、Primitive、Connector、影响假设、下一动作和停止条件；只有在
Cognitive Write Timing 的事件/边界才将需要续接的判断保存到现有 owner，不逐链填表。
框架名称、HTTP 200、元数据或 parser error 单独只能形成 Signal，不能越过 Evidence gate。

### 2.3 层级归属标准

原则是符合当前项目架构，Skill 不是越大越好：

| 内容类型 | 归属层 | 标准 |
|---|---|---|
| 会改变执行路线、判断顺序、阶段切换、升级/停止条件 | Skills | 只保留稳定决策结构 |
| 技巧、payload、bypass、案例、经验、发散思路、补充 checklist | 知识库 | 作为当前 Skill 的候选输入 |
| 大型案例、矩阵或深水细节 | `deep_refs` | 默认不加载，证据命中后读取 |
| 稳定、可重复、适合排队的动作 | Tools / action queue | 工具负责执行和原始结果 |
| 覆盖、验证或报告门槛 | Rules / checks | 由对应规则负责 |

具体 payload、WAF/SQLi/SSRF/上传绕过、工具参数和案例细节默认进入知识库或 `deep_refs`。
不确定归属时，先放知识库或 `deep_refs`，待多个目标复用后再晋升；不为“让 Skill 知道更多”扩写 Skill。任何新沉淀仍需保留 Evidence / Next action / Stop condition。

## 3. Knowledge layer

知识库只提供可复用模式、反例和发散问题，不指挥流程，也不保存当前目标状态。由
Shared Knowledge Recall 从 Context Pack 的完整 `card_catalog` 按信息缺口选读；常见 focus 包括
`sqli`、`auth-hidden`、`missing-param`、`path-pattern`、`api-idor`、`ssrf`、`graphql`
和 `upload`。具体卡片路径以 registry/Context Pack 返回为准；`knowledge/index.md`
与 `/kb` 是按需查找入口，不依赖推荐字段。

知识输出必须回到 `Evidence -> Hypothesis -> Next action -> Stop condition`；是否执行仍由
Skill 和检查层决定。不得默认全量读取卡片、原始日志或大型响应。

## 4. Checks layer

检查层负责覆盖、验证和报告状态，不复制动作安全规则或增加第二套门禁。结束前读取
`rules/coverage-gate.md`，分别交代 Covered、Leads / Signals、Candidates、Blocked、Not
applicable、Dead ends、Still unknown 和 Next actions。不得用“没有发现问题”替代覆盖摘要。

## 5. Execution and write-back

执行选择最低影响、最小必要的确定性动作；原始结果由现有工具和 owner 保存。未决工作通过
现有 `target_memory.py`、Action Queue、原生证据登记、Finding 裁决或 `/remember`（Checkpoint 只读）
写回，不在协议内创建第二份状态。

### Stateful Continuity

For dependent steps such as leak -> use, login -> token -> action, multi-round
oracles, browser workflows, or connection-bound protocols, keep all steps in
the same process, socket, or browser context. If a new process is required,
export and explicitly restore the complete session state. Never assume that
memory tokens, cookies, nonces, connection state, or oracle rounds survive a
new shell/tool invocation.

## 输出契约

同会话读 Skill 或执行工具不追加结果表：使用实际工具输出、原始证据引用与 owner 回执，
不要重新抄写 Target、Phase、Action、Coverage 或保存记录。没有发生的执行不造回执，
缺失的回执保持待回收/未决，不能以一句总结代替。

只有真实跨代理交接才按
`skills/src-hunting/SKILL.md#real-delegation-and-execution-handoff` 返回问题答案、证据增量、
支持/反对解释、未知/适用条件及建议 owner 动作；引用已保存事实，不填与问题无关的空栏。
专家自报不确认 Finding、不完成 Action；只有现有领域 owner 接受的事实生效。

调用结束的覆盖、候选、阻塞和下一步摘要由该入口的结束合同负责；不把“没有发现问题”
当覆盖结论，不用中途重复输出最终摘要来满足执行或恢复契约。

## 禁止事项

- 不得跳过目标层直接进入大范围测试。
- 不得默认全量读取知识库。
- 不得把 Lead 包装成 Candidate。
- 不得把推荐字段、单个 seed 或工具输出当成已执行状态。
