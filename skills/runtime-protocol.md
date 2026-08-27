# Skills 四层运行协议

本协议定义共享的 Target -> Skill -> Knowledge -> Checks -> Write-back 路由，不负责
替 Claude Code CLI 主会话选择具体测试类别。

本协议只定义共享路由，不重复加载或改写平台常驻契约。

## Claude Code CLI 职责边界

| 层 | 唯一职责 | 加载边界 |
|---|---|---|
| `CLAUDE.md` | 授权、AI/工具边界、状态 owner、入口路由 | 仓库启动时由 Claude Code CLI 常驻加载 |
| 本协议 | Target -> Skill -> Knowledge -> Checks -> Write-back | Context Pack 共享必读契约 |
| `bb-methodology` | 假设选择、轮换、停止和交接 | 会话开始、换目标、停滞或需要选路时按需加载 |
| 专项 Skill | 特定输入、观察、安全和写回步骤 | Context Pack 推荐，Claude 按当前证据选择后读取 |
| 知识卡/参考资料 | 模式、技巧、证据门和停止条件 | 默认推荐 0-2 张，Claude 按信号读取 |
| Rules / checks | Coverage、Validation 和 Reporting gate | 按当前动作与阶段读取 |
| Tools / state owners | replay、diff、raw evidence、生命周期和恢复 | 确定性执行或写回时调用 |

Claude Code CLI 当前主会话保留最终路线判断权；本协议、推荐 Skill/Card 和工具输出都不能
建立第二个 controller 或 target-state owner。

Context Pack 的 `selected_skill`、`skill_route` 和 `knowledge_cards` 是兼容推荐字段，不是
已选择的执行状态，也不进入默认 `must_read` 或自动写入 Queue。Claude 在 substantive
action claim 时显式选择 Skill route；首次选择不是 override，只有替换 action owner 已有
route 时才需要 `skill_override_reason`。

`hypothesis_seeds`、`alternative_angles` 和 `knowledge_card_recall` 同样只供 Claude 判断与
诊断。Context Pack 保留三者，Checkpoint 保留 seed/recall 投影，但不会仅凭建议生成 Queue
动作或把首个 seed 记成已选择假设。

Action Queue claim 的 `selected_knowledge_refs` 可以省略或为空；只有实际使用知识卡时才记录。
非空引用必须来自 action 的 `knowledge_refs`，改选其它引用时记录 `knowledge_override_reason`。

## 运行顺序

```text
1. 目标层：确认当前目标和上下文
2. Skills 层：Claude 主会话选择一个 Skill 作为当前执行契约
3. 知识库层：Skill 按需读取知识卡，用于回忆、联想和思路变形
4. 检查层：覆盖基线审计
5. 执行与写回：低风险验证、记录线索、沉淀经验
```

## 1. 目标层：先收敛

执行 Skill 前，先读取：

```text
memory/goals/active.json
```

或运行：

```bash
python3 tools/target_memory.py show
```

确认：

- 当前 target
- mode / phase
- active goal
- current hypothesis
- active leads
- next actions
- dead ends

如果没有 active target，先让用户或当前命令目标建立目标层上下文。

## 2. Skills 层：选择执行路径

Claude Code CLI 主会话根据目标、阶段和证据选择当前 Skill；Skill 提供该路径的决策或
执行契约：

- `bug-bounty`：端到端协调、跨 Skill 路由、链式思考
- `bb-methodology`：会话路线、阶段判断、迷路时重新定向
- `web2-recon`：资产和攻击面发现
- `web2-vuln-classes`：具体漏洞类别验证思路
- `triage-validation`：Candidate 到 Validated Finding 的验证 gate

Claude 主会话用 Skill 约束当前流程、工具、检查层和写回结果，并保留接受、替换或组合
建议的最终判断权。Skill 不应把知识库当成默认全量上下文，也不应让知识卡反过来接管
执行顺序；只在需要扩展、变形或补充思路时读取知识库。

## 2.1 三模式决策：Discovery / Exploitation / Validation modes

Evidence-driven depth does not mean evidence-only testing. 证据驱动用于决定
哪里值得深入，不是要求“没有现成证据就不行动”。当证据弱、覆盖薄或攻击面仍
不清楚时，Skill 必须进入 Discovery-driven discovery，通过安全的攻击面扩展
actively generate new evidence。

- **Discovery mode**：没有强信号时主动扩面。优先从浏览器 XHR/API、JS/source
  routes、API docs/leaks、Postman/OpenAPI、隐藏参数、路径命名规律、组件版本、
  角色/对象矩阵、业务工作流、缓存 recon 和历史 target memory 中产生新证据。
  目标是把 `unknown` 推进为 `lead` / `signal` / `blocked` / `dead-end`，
  不是随机扫工具或凑步骤。
- **Exploitation mode**：已有明确 host/path/parameter/component/behavior
  信号时，围绕该证据做最小安全深入，例如 replay、role/object diff、sibling
  expansion、parser/bypass、CVE applicability、OAST 低风险证明或链式验证。
- **Validation mode**：只有 Candidate 质量足够时进入验证。使用最低影响证据
  证明实际安全影响，并完成 `/validate` 或报告前 gate。

每次在三种模式之间切换，先做一次 compact transition review：`Evidence state /
Next question / Stop condition`。复核结果继续写入现有 Evidence 或
Action Queue，不新增 transition 字段或第二套状态机。

AI selection / override 是能力上限保护：当前 Skill 可以跳过推荐路线、组合多张知识卡、
创建新的 action 类型，或把 Discovery / Exploitation / Validation 顺序局部
重排；选择必须说明 decision reason、下一步验证动作和停止条件；只有
替换 action owner 已有 route 才需要 override reason。Skill route
及其 required dimensions 是 substantive Action Queue 的最小执行证据；工具、知识卡
和 checklist 仍是可替换的决策输入，不是固定工具清单。

## 2.2 Web 深水区启发式路由

当 Web 目标出现复杂边界、parser mismatch、token/SSO、upload/parser、SSRF、
prototype pollution、source/config leak、低价值 primitive 或链式升级信号时，
当前 Skill 可以使用项目内已蒸馏的边界优先路由结构：

```text
boundary -> baseline -> hidden surface -> bug family -> primitive -> connector -> impact
```

这属于 Skill 层增强，不是知识库接管流程。使用要求：

- 先有目标证据，再读取 `rules/playbook-router.md`、具体知识卡或项目内 `deep_refs`。
- 只借鉴边界识别、pattern map、chain shape、bypass 思维和 primitive 建模。
- 框架信号仍回到现有 owner：`/_next/image` 路由 SSRF fetch gate，`/_next/data` 路由 IDOR actor/object
  diff，Actuator 路由管理响应形态，ViewState 路由完整性/真实消费，legacy auth 路由策略差异；
  不因技术栈名称加载整套框架 Skill。
- OData 与 LDAP/XPath 只有出现协议、operator、错误或 source 证据时才加载专项 reference 卡；
  metadata、HTTP 200、格式识别或 parser error 单独只能是 Signal。
- 每个链式假设必须写成 `Evidence / Primitive / Connector / Impact hypothesis /
  Next action / Stop condition`。

## 2.3 层级归属标准

新增文章、CTF 技巧、实战复盘、工具经验或外部资料时，必须先判断放入哪一层。
原则是符合当前项目架构，保持渐进加载；Skill 不是越大越好。

| 内容类型 | 归属层 | 标准 |
|---|---|---|
| 会改变执行路线、判断顺序、阶段切换、升级/停止条件 | Skills | 只提炼稳定决策结构，不搬运大量案例、payload 或工具参数。 |
| 提供技巧、payload、bypass、案例、经验、发散思路、补充 checklist | 知识库 | 写成知识卡、payload pack 或 playbook，作为当前 Skill 的候选输入。 |
| 内容很大、场景很深、包含长案例或矩阵 | `deep_refs` | 默认不加载，只在证据命中具体卡片或 router 时按需读取。 |
| 能稳定自动执行、可重复、适合结构化排队 | Tools / action queue | 做成工具、脚本或 `tools/action_queue.py` action 类型，不让 Skill 手写重复步骤。 |
| 会影响覆盖门槛、验证或报告 gate | Rules / checks | 写入 `rules/` 或对应检查命令；不要埋在知识卡里。 |

决策补充：

- 只有能增强“怎么判断、何时切换、何时停、如何串链”的内容，才进入 Skill。
- 具体 payload、WAF/SQLi/SSRF/上传绕过、工具参数和案例细节，默认进入知识库或
  `deep_refs`。
- 不确定归属时，先放知识库或 `deep_refs`，待多个目标复用后再晋升到 Skill。
- 不为“让 Skill 知道更多”扩写 Skill；Skill 应保持精简、强路由、低上下文占用。
- 任何新沉淀都必须保留 Evidence / Next action / Stop condition，避免变成固定清单。

## 3. 知识库层：按需发散

知识库层是 Skills 的回忆和联想层。它不负责指挥流程，也不保存当前目标状态；它只提供可复用的模式、反例、发散问题和最小验证思路，让当前 Skill 在不丢失主线的前提下扩展攻击面。

需要发散时，先读取：

```text
knowledge/index.md
```

再按当前证据选择 1-2 张知识卡，例如：

- API / 多租户 / 对象 ID：`knowledge/cards/api-idor.md`
- 认证 / 角色 / 组织边界：`knowledge/cards/auth-access.md`
- 隐藏认证参数 / 登录分支开关：`knowledge/cards/auth-hidden-switches.md`
- JWT / OAuth / SAML / SSO token 边界：`knowledge/cards/auth-sso-token-edge-cases.md`
- 缺参信号 / 隐藏参数发现：`knowledge/cards/missing-parameter-discovery.md`
- 目录命名规律 / 管理面暴露：`knowledge/cards/path-pattern-management-exposure.md`
- URL fetch / webhook / import：`knowledge/cards/ssrf-url-fetch.md`
- GraphQL / subscription / global ID：`knowledge/cards/graphql.md`
- SQLi 非显式输入面：`knowledge/cards/sqli-hidden-surfaces.md`
- 上传 / 导入 / 解析器链：`knowledge/cards/upload-parser.md`
- 上传执行 / 受控 RCE：`knowledge/cards/upload-to-execution.md`, `knowledge/cards/controlled-rce-impact.md`
- Node / prototype pollution / VM sink：`knowledge/cards/node-prototype-pollution.md`
- Race / 并发状态差异：`knowledge/cards/race-conditions.md`
- gRPC / gRPC-Web / gateway：`knowledge/cards/grpc-api-boundaries.md`
- Cognito Identity Pool / 匿名 STS：`knowledge/cards/cloud-cognito-identity-pool.md`
- Kubernetes API / kubelet / RBAC：`knowledge/cards/k8s-control-plane-boundaries.md`
- 覆盖缺口：`knowledge/cards/coverage-prompts.md`
- 连续低价值方向：`knowledge/cards/dead-ends.md`

如果证据命中 Web 深度路由，再读取：

```text
rules/playbook-router.md
```

知识库输出必须回到：

```text
Evidence -> Hypothesis -> Next action -> Stop condition
```

其中 `Next action` 只是给当前 Skill 的候选动作，是否执行、何时执行、用什么工具执行，仍由 Skill 和检查层共同决定。

## 4. 检查层：覆盖与验收

动作安全继承平台常驻契约；本层只负责覆盖、验证和报告状态，
不复制动作安全规则或增加第二套门禁。

结束前检查覆盖基线：

```text
rules/coverage-gate.md
```

不能直接说“全面测试完成”。必须交代：

- Covered
- Leads / Signals
- Candidates
- Blocked
- Not applicable
- Dead ends
- Still unknown
- Next actions

## 5. 执行与写回

执行优先做低风险、最小必要验证；不要因为“敏感但不破坏”的方向而停止探索。

写回目标层：

```bash
python3 tools/target_memory.py lead "..."
python3 tools/target_memory.py next "..."
python3 tools/target_memory.py dead-end "..."
python3 tools/target_memory.py handoff "..."
```

可复用经验晋升前读取：

```text
knowledge/promotion-rules.md
```

验证后的发现再进入：

```text
/remember
```

## 输出模板

核心 Skill 结束时优先使用：

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
- 不得用“没有发现问题”替代覆盖摘要。
- 不得把 Lead 包装成 Candidate。
