# Skills 四层运行协议

本协议定义核心 Skills 如何接入目标层、知识库层和检查层。

执行本协议时，默认继承 `CLAUDE.md` 中的 Authorization Posture 和
Operator Profile：在当前目标上下文内按授权渗透测试工程师推进工作；同时
`rules/red-lines.md` 始终是更高优先级的安全边界。

## 运行顺序

```text
1. 目标层：确认当前目标和上下文
2. Skills 层：当前 Skill 作为流程指挥者，选择执行路径
3. 知识库层：Skill 按需读取知识卡，用于回忆、联想和思路变形
4. 检查层：红线过滤和覆盖基线审计
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

Skills 层是四层体系的流程指挥者。当前 Skill 根据目标、阶段和证据决定下一步：

- `bug-bounty`：端到端协调、跨 Skill 路由、链式思考
- `bb-methodology`：会话路线、阶段判断、迷路时重新定向
- `web2-recon`：资产和攻击面发现
- `web2-vuln-classes`：具体漏洞类别验证思路
- `triage-validation`：Candidate 到 Validated Finding 的验证 gate

Skill 负责指定流程、选择工具、调用检查层和写回结果。Skill 不应把知识库当成默认全量上下文，也不应让知识卡反过来接管执行顺序；只在需要扩展、变形或补充思路时读取知识库。

## 3. 知识库层：按需发散

知识库层是 Skills 的回忆和联想层。它不负责指挥流程，不保存当前目标状态，也不定义红线；它只提供可复用的模式、反例、发散问题和最小验证思路，让当前 Skill 在不丢失主线的前提下扩展攻击面。

需要发散时，先读取：

```text
knowledge/index.md
```

再按当前证据选择 1-2 张知识卡，例如：

- API / 多租户 / 对象 ID：`knowledge/cards/api-idor.md`
- 认证 / 角色 / 组织边界：`knowledge/cards/auth-access.md`
- 隐藏认证参数 / 登录分支开关：`knowledge/cards/auth-hidden-switches.md`
- 缺参信号 / 隐藏参数发现：`knowledge/cards/missing-parameter-discovery.md`
- 目录命名规律 / 管理面暴露：`knowledge/cards/path-pattern-management-exposure.md`
- URL fetch / webhook / import：`knowledge/cards/ssrf-url-fetch.md`
- GraphQL / subscription / global ID：`knowledge/cards/graphql.md`
- SQLi 非显式输入面：`knowledge/cards/sqli-hidden-surfaces.md`
- 上传 / 导入 / 解析器链：`knowledge/cards/upload-parser.md`
- Race / 并发状态差异：`knowledge/cards/race-conditions.md`
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

## 4. 检查层：先刹车，再验收

执行前检查红线：

```text
rules/red-lines.md
```

以下情况必须先做红线判断：

- 高频、并发、压力、资源耗尽
- `POST` / `PUT` / `PATCH` / `DELETE`
- GraphQL mutation、admin action、workflow dispatch
- 支付、退款、转账、订单、发货、钱包、积分、优惠券
- 账号、权限、组织成员、配置修改
- 短信、邮件、Webhook、外部消息批量发送
- CI/CD、生产部署、secret 外传

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

执行只做低风险、最小必要验证。

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
- Red-line check:
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
- 不得用覆盖基线绕过红线。
- 不得用“没有发现问题”替代覆盖摘要。
- 不得把 Lead 包装成 Candidate。
- 不得执行 DDoS、高压流量或破坏性状态改变。
