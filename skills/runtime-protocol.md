# Skills 四层运行协议

本协议定义共享的 Target -> Skill -> Knowledge -> Checks -> Write-back 路由，不负责
替 Claude Code CLI 主会话选择具体测试类别。

本协议只定义共享路由，不重复加载或改写平台常驻契约。

## Claude Code CLI 职责边界

| 层 | 唯一职责 | 加载边界 |
|---|---|---|
| `CLAUDE.md` | 授权、AI/工具边界、状态 owner、入口路由 | 仓库启动时常驻 |
| 本协议 | Target -> Skill -> Knowledge -> Checks -> Write-back | Context Pack 共享必读 |
| `bb-methodology` | 假设选择、轮换、停止和交接 | 会话开始、停滞或需要选路时按需 |
| 专项 Skill | 当前路线的决策、观察和写回契约 | 按证据推荐后读取 |
| 知识卡/参考资料 | 模式、技巧、证据门和发散思路 | 默认推荐 0-2 张，按信号读取 |
| Rules / checks | Coverage、Validation 和 Reporting gate | 按动作与阶段读取 |
| Tools / state owners | 确定性执行、原始证据、生命周期和恢复 | 调用或写回时执行 |

Claude Code CLI 当前主会话保留最终路线判断权。本协议、推荐 Skill/Card 和工具输出
都不能建立第二个 controller 或 target-state owner。

Context Pack 的 `selected_skill`、`skill_route` 和 `knowledge_cards` 是兼容推荐字段，
不是已选择的执行状态，也不进入默认 `must_read` 或自动写入 Queue。Claude 在实质
Action Queue claim 时显式选择 Skill route；只有替换 action owner 已有 route 时才需要
`skill_override_reason`。

`hypothesis_seeds`、`alternative_angles` 和 `knowledge_card_recall` 只供判断与诊断。
它们不会凭建议生成 Queue 动作，也不会把首个 seed 记成已选择假设。Action Queue 的
`selected_knowledge_refs` 可以为空；非空引用必须来自 action 的 `knowledge_refs`，改选
其它引用时记录 `knowledge_override_reason`。

## 决策闭环

以下是可回退的判断环，不是固定执行顺序：

```text
Target context -> evidence-backed route -> smallest bounded action
              -> owner write-back -> next question / stop / reopen
```

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

每次在三种模式之间切换，先做一次 compact transition review：`Evidence state / Next question / Stop condition`。复核结果继续写入现有 Evidence 或 `Action Queue`，不新增 transition 字段或第二套状态机。

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

知识库只提供可复用模式、反例和发散问题，不指挥流程，也不保存当前目标状态。按证据
从 `knowledge/index.md` 选择 1-2 张卡；常见入口包括：

- `knowledge/cards/sqli-hidden-surfaces.md`
- `knowledge/cards/auth-hidden-switches.md`
- `knowledge/cards/missing-parameter-discovery.md`
- `knowledge/cards/path-pattern-management-exposure.md`
- `knowledge/cards/api-idor.md`, `knowledge/cards/auth-access.md`
- `knowledge/cards/ssrf-url-fetch.md`, `knowledge/cards/upload-parser.md`
- `knowledge/cards/graphql.md`, `knowledge/cards/websocket-realtime-api.md`
- `knowledge/cards/grpc-api-boundaries.md`, `knowledge/cards/web-llm-tool-chains.md`

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

## 输出契约

```text
SKILL RESULT
- Target:
- Skill:
- Phase:
- Evidence:
- Hypotheses:
- Actions taken:
- Coverage update:
- Leads / Signals:
- Candidates:
- Dead ends:
- Still unknown:
- Next actions:
- Write-back:
```

## 禁止事项

- 不得跳过目标层直接进入大范围测试。
- 不得默认全量读取知识库。
- 不得把 Lead 包装成 Candidate。
- 不得把推荐字段、单个 seed 或工具输出当成已执行状态。
