# Skills 四层运行协议

本协议定义共享的 Target -> Skill -> Knowledge -> Checks -> Write-back 路由，不负责
替 Claude Code CLI 主会话选择具体测试类别。

本协议只定义共享路由，不重复加载或改写平台常驻契约。

## Claude Code CLI 职责边界

| 层 | 唯一职责 | 加载边界 |
|---|---|---|
| `CLAUDE.md` | 授权、AI/工具边界、状态 owner、入口路由 | 仓库启动时常驻 |
| 本协议 | Target -> Skill -> Knowledge -> Checks -> Write-back | Context Pack 共享必读 |
| 全部 Skill（含 `bb-methodology`） | 决策契约、路线、证据门 | 原生 Skill 工具按需加载（description 路由） |
| 知识卡/参考资料 | 模式、技巧、证据门和发散思路 | 默认推荐 0-2 张，按信号读取 |
| Rules / checks | Coverage、Validation 和 Reporting gate | 按动作与阶段读取 |
| Tools / state owners | 确定性执行、原始证据、生命周期和恢复 | 调用或写回时执行 |

Claude Code CLI 当前主会话保留最终路线判断权。本协议、推荐 Skill/Card 和工具输出
都不能建立第二个 controller 或 target-state owner。

## Shared Knowledge Recall

两种入口共用这一条判断：

- substantive 的判据只有一条：该动作会触及目标或写入 owner 状态（发请求、记录
  evidence、queue 写回）；纯解释、规划、复盘不触发召回。
- substantive 动作是否查包以信息增量为唯一判据，不引入“什么算基础知识”的类别判断：
  当前上下文已覆盖该 focus 的卡片推荐与卡片正文（查包无新信息）即免重查，直接动手；
  尚未覆盖时按当前证据确定 focus，按 `commands/context-pack.md` 调用
  `python3 tools/context_pack.py --target TARGET --focus FOCUS`。目标记忆或磁盘目录
  不能代替 Pack。宽泛目标先沿既有目标上下文/发现入口补证据，不预选专项卡。
- 推荐路径不等于文件已读：选中的 Skill 和当前需要的卡若正文不在上下文中，先读取再
  行动；已读正文不重复加载。
- 同一 target/focus/实质证据可复用；目标、focus 或实质证据变化时重新判断并按需刷新。
  会话上下文压缩（compaction/summary）后，对话内既有的卡片推荐和 Pack 引用按过期处理：
  重建判断以当前磁盘上的 owner 状态为准，不从压缩摘要里复用旧推荐。
- Autopilot 先完成 bootstrap 和 state read，再在 substantive lane 选择后执行这条判断；bootstrap
  不等于已有匹配 Pack 或知识卡已读，也不因召回而抢占 owner 选定的初始工作。
- 默认推荐 0-2 张卡；查包返回不足时再使用已有 deferred recall、`knowledge/index.md` 或 `/kb`。
  推荐预算不限制有理由的显式补读，不新增持久化加载状态。

卡片保持独立，提供模式、反例和证据提示；Skill 保留路线和证据门，不复制卡片正文。

Context Pack 的 `selected_skill`、`skill_route` 和 `knowledge_cards` 是兼容推荐字段
（S1 原生加载铺开后 skill 两个字段为空，pack 只发布磁盘 skill 目录），不是已选择的执行
状态，也不进入默认 `must_read` 或自动写入 Queue。Skill 的选择与加载由 AI 通过原生
Skill 工具完成（frontmatter description 是路由面）；Claude 在实质 Action Queue claim 时
显式选择 Skill route；只有替换 action owner 已有 route 时才需要
`skill_override_reason`。

`hypothesis_seeds`、`alternative_angles` 和 `knowledge_card_recall` 只供判断与诊断。
它们不会凭建议生成 Queue 动作，也不会把首个 seed 记成已选择假设。Action Queue 的
`selected_knowledge_refs` 是 AI 的知识判断：可以引用 focus 匹配的任意卡，改选不属于
默认 refs 的卡不需要理由；唯一的机械校验是引用的卡文件必须真实存在（防笔误与伪造），
不校验与 item 默认 refs 的子集关系。

## 决策闭环

以下是可回退的判断环，不是固定执行顺序：

```text
Target context -> evidence-backed route -> smallest bounded action
              -> owner write-back -> next question / stop / reopen
```

记忆分层契约见 `docs/architecture-contract.md#memory-contract`：L1 观察、
L2 工作集、L3 目标经验、L4 跨目标知识都落在既有 owner 上。运行时遵守
三条层间流转：工作集只保留当前决策所需（其余留指针按引用展开）；只在
重要节点（假设证伪、稳定结论、阶段切换、会话暂停/handoff）做 L3/L4 巩固
写回——普通观察进 Ledger 即止，不强制走提炼管线；召回以当前问题为驱动，
先目标经验后跨目标知识，经验必须带适用条件。

### 1. Target layer

先读取 `memory/goals/active.json`，或运行 `python3 tools/target_memory.py show`，确认
target、mode/phase、active goal、current hypothesis、leads、next actions 和 dead ends。
没有 active target 时，先建立目标上下文，不直接进入大范围动作。

### 2. Skill layer

主会话根据目标、阶段和证据选择路线：`bug-bounty` 负责协调，`bb-methodology` 负责
假设与轮换，`web2-recon` 负责攻击面，`web2-vuln-classes` 负责具体类别，
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
Stop condition 不再匹配当前模式时直接切换；checkpoint 的 round lane 心跳
（`decision`/`next_action` 字段）已携带该次切换的落地理由，不新增 transition
字段或第二套状态机。

AI selection / override 是能力上限保护：当前 Skill 可以跳过建议路线、组合知识卡、创建
新的 action 类型，或局部重排模式顺序；选择必须说明 decision reason、下一步验证动作和
停止条件。Skill route 及 required dimensions 是 substantive Action Queue 的最小执行证据。

### 2.2 Web 深水区启发式路由

只有在目标证据命中复杂边界时，才读取 `rules/playbook-router.md` 或具体 reference。通用
决策形状为：

```text
boundary -> baseline -> hidden surface -> bug family -> primitive -> connector -> impact
```

每个链式假设都记录 `Evidence / Primitive / Connector / Impact hypothesis / Next action /
Stop condition`。框架名称、HTTP 200、元数据或 parser error 单独只能形成 Signal，不能越过
Evidence gate；细节回到现有 owner，不在本协议中复制。

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
Shared Knowledge Recall 按证据通过 Context Pack 选择 0-2 张卡；常见 focus 包括
`sqli`、`auth-hidden`、`missing-param`、`path-pattern`、`api-idor`、`ssrf`、`graphql`
和 `upload`。具体卡片路径以 registry/Context Pack 返回为准；`knowledge/index.md`
只在召回不足时作为目录回退。

知识输出必须回到 `Evidence -> Hypothesis -> Next action -> Stop condition`；是否执行仍由
Skill 和检查层决定。不得默认全量读取卡片、原始日志或大型响应。

## 4. Checks layer

检查层负责覆盖、验证和报告状态，不复制动作安全规则或增加第二套门禁。结束前读取
`rules/coverage-gate.md`，分别交代 Covered、Leads / Signals、Candidates、Blocked、Not
applicable、Dead ends、Still unknown 和 Next actions。不得用“没有发现问题”替代覆盖摘要。

## 5. Execution and write-back

执行选择最低影响、最小必要的确定性动作；原始结果由现有工具和 owner 保存。未决工作通过
现有 `target_memory.py`、Action Queue、Evidence Ledger、Finding、Checkpoint 或 `/remember`
写回，不在协议内创建第二份状态。

### Stateful Continuity

For dependent steps such as leak -> use, login -> token -> action, multi-round
oracles, browser workflows, or connection-bound protocols, keep all steps in
the same process, socket, or browser context. If a new process is required,
export and explicitly restore the complete session state. Never assume that
memory tokens, cookies, nonces, connection state, or oracle rounds survive a
new shell/tool invocation.

## 输出契约

5 必填字段由 AI 手打（判断性内容：证据、候选、终态、残余未知、下一步）；
其余 8 个字段定义保留，但由 checkpoint / pack / queue owner 自动记录，
AI 无需手打——需要时可引用 owner 已有字段而不是重抄：

```text
SKILL RESULT
- Evidence:            (必填)
- Candidates:          (必填)
- Dead ends:           (必填)
- Still unknown:       (必填)
- Next actions:        (必填)
- Target:              (owner: pack/state 自动记录)
- Skill:               (owner: queue skill_route 自动记录)
- Phase:               (owner: state 自动记录)
- Hypotheses:          (owner: queue hypothesis 字段自动记录)
- Actions taken:       (owner: queue/ledger 自动记录)
- Coverage update:     (owner: coverage_matrix 自动记录)
- Leads / Signals:     (owner: evidence_ledger 自动记录)
- Write-back:          (owner: 各 owner 写回即记录)
```

必填字段的最低标准：Evidence 引用可定位的原始请求/响应或 evidence ref；
Candidates 不得把 Lead 包装成 Candidate；Dead ends 与 Still unknown 不得用
"没有发现问题"替代覆盖摘要；Next actions 是可执行的下一步。

## 禁止事项

- 不得跳过目标层直接进入大范围测试。
- 不得默认全量读取知识库。
- 不得把 Lead 包装成 Candidate。
- 不得把推荐字段、单个 seed 或工具输出当成已执行状态。
