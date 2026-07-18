# Expert Hunter Autopilot Plan

## 1. 一句话目标

让 `/autopilot` 像 super 渗透测试专家一样思考：

```text
super pentester 决策循环
+
四层记忆系统外脑
+
MCP/browser 真实业务流观察
+
工具化证据闭环
```

项目最终不是优化成“更会跑工具的扫描器”，而是优化成：

```text
Recon-first / Cache-aware
+
Business-aware / Crown-jewel driven
+
Workflow/MCP driven
+
Hypothesis-led
+
Four-layer memory supported
+
Evidence-validated
+
Chain-expanded
+
Coverage-gated at finish
```

## 2. 背景判断

上游 `claude-bug-bounty` 的优势是 Claude CLI 体验简单：

```text
/autopilot = /scope -> /recon -> /surface -> /hunt -> /validate -> /report
```

上游 command 流里 `/hunt` 默认会走 `tools/hunt.py --scan-only`，所以 scanner 是 hunt 阶段的核心执行步；上游 agent 文案同时有 AI 选 vuln class、go deeper 的意图。当前项目的取舍是吸收它的简单稳定性，但把关系明确为：scanner quick 是 fresh target 的广度传感器和 advisory lead source，不是 `/autopilot` 的大脑、完成标准或漏洞判定器。

当前项目在上游基础上增加了大量增强能力：

- `context_pack.py`
- `surface.py`
- `checkpoint.py`
- `action_queue.py`
- `target_case_state.py`
- `case_state_seed.py`
- `validation_runner.py`
- `evidence_ledger.py`
- `finding_index.py`
- `coverage_matrix.py`
- `browser_mcp_import.py`
- `knowledge/cards/`
- `rules/red-lines.md`
- `rules/context-loading.md`
- `rules/coverage-gate.md`

这些增强不能丢，但不能反过来让 Claude 变成“状态工具/coverage/queue 驱动”。

最终方向：

```text
专家循环 = 方向盘
四层记忆 = 外脑
工具 = 手脚
MCP/browser = 眼睛
knowledge = 经验库
checks = 刹车和验收
```

## 3. 非目标

明确不做：

- 不把 `/autopilot` 做成固定扫描器；
- 不为 `/api/Users`、`/orders`、`socket.io sid/t` 这类单点现象写专用工具；
- 不继续扩大默认加载的知识卡和大段 prose；
- 不把靶场通关数作为项目能力指标；
- 不为了无人值守牺牲高价值漏洞发现能力；
- 不让 `action_queue`、`case_state`、`coverage_matrix` 成为开局方向盘；
- 不禁止 Claude 灵活探索、发请求、用 MCP、用 curl；
- 不要求每个探索请求都脚本化。

## 4. Super pentester 决策优先级

`/autopilot` 的实战优先级应是：

```text
Business impact
  >
Workflow evidence
  >
Crown jewel hypothesis
  >
Attack surface ranking
  >
Scanner result
  >
Coverage gap
```

含义：

- scanner 不当老大；
- scanner quick 在 fresh target 第一轮必须考虑，作为低成本广度线索；
- scanner-positive 只进入 lead/signal/candidate 分级，scanner-negative 不代表结束；
- coverage 不当老大；
- queue 不当老大；
- case_state 不当老大；
- 业务价值 + 当前证据 + 攻击链潜力当老大。

## 5. 最终主循环

### 5.1 Fresh target

第一次打一个目标时：

```text
TARGET
  -> RECON
  -> BUSINESS MODEL / CROWN JEWELS
  -> SURFACE
  -> CONTEXT / SKILL ROUTE
  -> WORKFLOW CAPTURE
  -> HYPOTHESIS
  -> MINIMAL PROOF
  -> CHAIN EXPANSION
  -> VALIDATE
  -> RECORD
  -> REPORT / CHECKPOINT
```

关键原则：

```text
fresh target 必须先把攻击面打出来，不要一上来陷入 checkpoint / queue / coverage。
```

典型命令：

```bash
python3 tools/hunt.py --target <target> --recon-only
python3 tools/surface.py --target <target>
python3 tools/context_pack.py --target <target>
```

### 5.2 Existing target

已有缓存或继续上次目标时：

```text
TARGET
  -> MEMORY / STATE LOAD
  -> SURFACE
  -> CONTEXT / SKILL ROUTE
  -> RECON if stale/thin
  -> WORKFLOW CAPTURE
  -> HYPOTHESIS
  -> MINIMAL PROOF
  -> CHAIN EXPANSION
  -> VALIDATE
  -> RECORD
  -> REPORT / CHECKPOINT
```

典型命令：

```bash
python3 tools/autopilot_state.py --target <target>
python3 tools/surface.py --target <target>
python3 tools/context_pack.py --target <target>
```

如果缓存 stale / thin，再补：

```bash
python3 tools/hunt.py --target <target> --recon-only
python3 tools/surface.py --target <target>
```

## 6. 四层记忆系统定位

四层记忆必须保留，但它是外脑，不是方向盘。

### Layer 1：Target Memory / Runtime State

作用：记住当前目标发生过什么。

包括：

- 当前目标；
- recon 是否跑过；
- 已测 endpoint；
- dead-end；
- active lead；
- handoff；
- action_queue；
- evidence ledger；
- case_state；
- coverage 状态。

它回答：

```text
我现在在哪里？
我刚才测过什么？
什么不该重复？
下一步还有什么未收束？
```

### Layer 2：Skill Orchestration

作用：根据当前 evidence shape 选择能力。

例如：

- web2 recon；
- web2 vuln classes；
- triage validation；
- report writing；
- credential lane；
- mobile pentest；
- cicd；
- web3。

它回答：

```text
当前证据形状应该调用哪套能力？
```

但它不能变成固定 checklist。

### Layer 3：Knowledge Library

作用：提供经验、bypass、误判反例和攻击链连接器。

重点收：

- 模型可能漏的 bypass；
- 稀缺经验；
- 真实案例形状；
- 常见误判；
- 低风险验证技巧；
- chain expansion 提示。

它回答：

```text
这个场景有没有我可能漏掉的技巧？
有没有历史案例/连接器可以启发攻击链？
```

不是重新讲 SQLi/XSS/SSRF 基础原理。

### Layer 4：Checks / Gates

作用：保证安全、质量、覆盖和报告可信。

包括：

- red-lines；
- coverage-gate；
- validation rubric；
- reporting rules；
- retrospective rules。

它回答：

```text
这个动作会不会产生破坏性？
这个证据够不够？
能不能叫 finding？
收尾时还有什么没解释？
```

## 7. Business model / Crown jewels

Super pentester 和普通扫描器最大的区别是业务理解。

Claude 必须主动问：

```text
这个目标最值钱的东西是什么？
攻击者最想拿什么？
哪个 workflow 出错影响最大？
```

典型 crown jewels：

- 账号 / session / OAuth token；
- 订单 / 支付 / refund / credits；
- 发票 / 报表 / export；
- 组织 / tenant / member / invite；
- 文件 / private attachment；
- admin / support / moderation；
- CI/CD / webhook / integration；
- API key / secret / config；
- RCE / SSRF / internal network。

这一步不替代 recon，而是在 recon 后决定优先级。

## 8. Surface ranking

`surface.py` 不只是 URL 排序，而应服务于潜在攻击路径排序。

P1 应优先体现：

- auth / account / session；
- order / invoice / billing；
- tenant / org / admin；
- upload / import / export；
- webhook / integration；
- search / filter / query；
- debug / config / source / backup；
- browser-observed XHR；
- source / JS / browser convergence。

降噪原则：

- 已 final 的 action / ledger 降权；
- 不因单个历史 dead-end 永久隐藏新证据；
- browser-observed API 优先于 JS 猜测 route；
- off-target URL 保留为 chain context，不进入直接漏洞验证。

## 9. Workflow capture / MCP browser

对 app / SPA / auth / workflow 目标，必须优先考虑真实业务流抓取。

重点工作流：

- login；
- profile；
- account；
- order；
- billing；
- invoice；
- export；
- upload；
- search；
- admin-like；
- invite / member / role。

优先级：

```text
1. browser_evidence.py / agent-browser CLI：常规自动交互、session、network、storage、HAR 和结构化证据
2. chrome-devtools MCP：深度实时 DevTools / network / console / request 调试
3. playwright MCP / CLI：兼容回退
4. JSHook MCP：runtime JS hook / 浏览器端行为观察时按需调用
```

MCP/browser 产物应导入：

```bash
python3 tools/browser_mcp_import.py --target <target> ...
```

让以下模块复用同一套 artifact contract：

```text
surface
checkpoint
autopilot
validation_runner
```

## 10. Hypothesis-led hunting

每轮不应只问：

```text
这个 endpoint 有没有 IDOR？
```

而应问：

```text
如果我突破这里，能不能拿到钱、权限、PII、token、RCE、跨租户数据？
```

好的 hypothesis 形态：

```text
user_b can access user_a invoice export
low_role can call admin-like support endpoint
checkout state can be manipulated before payment confirmation
GraphQL node ID bypasses REST authz
mobile API exposes older object access rules
upload preview parser reaches internal fetch
debug config leaks OAuth secret and enables auth chain
```

每个 hypothesis 至少包含：

- 目标 workflow；
- 预期边界；
- 可能影响；
- 最小验证方式；
- 降级条件；
- chain expansion 方向。

## 11. AI 探索 vs 工具化证据

“用工具稳定拿证据”不是禁止 Claude 发请求。

### AI 可以自由探索

Claude 可以：

- 用 MCP 点击页面；
- 看 network；
- 读 JS；
- 用 curl 看 status/body；
- 做一次低风险参数变化；
- 构造 hypothesis；
- 判断差异；
- 决定升级/降级。

这些属于探索 / 观察 / 假设生成，不需要每一步都工具化。

### 证据必须稳定落盘

凡是要进入以下状态：

```text
Signal -> Candidate -> Tested Finding -> Validated Finding -> Report
```

就应尽量保存：

- baseline request；
- variant request；
- raw response；
- diff；
- repeated result；
- evidence summary；
- ledger record；
- finding sync。

优先使用：

```text
validation_runner.py
response_diff.py
browser_mcp_import.py
evidence_ledger.py
finding_index.py
report_generator.py
```

或者写目标作用域小脚本保存完整证据。

一句话：

```text
AI 可以自由探索；
但凡要作为漏洞证据，就要把请求、响应、diff、重复性和结论落盘。
```

## 12. Minimal proof

Super pentester 不乱打 payload，而是选最小证据。

优先验证形态：

- owner vs peer replay；
- anonymous vs authenticated diff；
- low_role vs admin-like diff；
- baseline vs perturbation；
- same object through sibling endpoint；
- browser workflow vs direct API call；
- old API vs new API diff；
- mobile vs web API diff。

工具负责 replay / diff / evidence / ledger。AI 负责判断证据是否足够。

## 13. Chain expansion

每个 primary signal 后必须扩链，而不是马上 report。

默认问题：

```text
有没有 sibling endpoint？
有没有 write/delete/export/bulk/report？
有没有 admin/support/mobile/versioned API？
有没有 GraphQL/global ID 等价路径？
有没有 source/JS/browser 里暴露同资源路径？
能不能从 info leak 串到 token/secret/config？
```

流程：

```text
primary hit
  -> sibling expansion
  -> alternate transport
  -> object/role diff
  -> chain probe
  -> impact quantification
```

典型链路：

```text
read IDOR -> update/delete sibling -> export/report/bulk -> tenant compromise
info leak -> secret/token -> OAuth/JWT/webhook -> ATO/internal access
SSRF -> internal admin -> metadata/cloud creds -> RCE/data exfil
XSS -> privileged viewer -> token/action abuse -> ATO
```

## 14. Checkpoint / Queue / Coverage 的正确位置

这些是阶段收束工具，不是开局方向盘。

### checkpoint

正确使用：

- 一轮 meaningful action 后；
- validation 后；
- report 前后；validated finding 是必须保留的 reportable asset，但不是自动停止条件；
- 准备停止/切目标；
- 上下文窗口风险变高时。

checkpoint 决策应以“是否还有高价值可执行动作”为准，而不是固定覆盖率阈值。pending report 必须持续留在队列和 handoff 中；只有 case_state validation、candidate evidence gap、高价值 coverage/P1、action-gated lead 等动作耗尽或收益更低时，report 才成为 recommended action。

coverage matrix 是覆盖账本，不是笛卡尔积执行器。工具层只做事实收集、极少数确定垃圾剔除和 AI 判断持久化：minified-JS 伪端点这种明显不是 HTTP handler 的垃圾可以剔除；static asset / 标准 public metadata / API-like path 只作为 `auto_hints` 和排序信号，不自动成为最终 `endpoint_kind`，也不自动判 n/a。`route prefix`、`page route`、`realtime`、`public metadata 是否有价值` 这类模糊语义交给 AI 结合状态码、body、browser/XHR、JS/source 证据判断，再用 `mark-endpoint-kind` 写回。真实 API 仍保留较宽覆盖，避免过度裁剪攻击面。

错误使用：

- fresh target 一开始就让 checkpoint 指挥方向。

### action_queue

正确使用：

- 防止重复；
- 保存未完动作；
- 记录 blocked / dead-end / candidate；
- 防止已 final 线索反复回 P1。

错误使用：

- queue 里有什么就机械跑什么。

### case_state

正确使用：

- 保存 actor / session / object / private marker；
- 当多账号/多对象验证有价值时优先；
- 让 IDOR / BOLA / 业务状态验证可复现。

错误使用：

- 有 case_state 就永远优先 IDOR，忽略 SQLi/RCE/SSRF。

### coverage_matrix

正确使用：

- finish / handoff 前解释覆盖；
- 防止明显高价值方向没交代；
- 作为补漏和收尾。

错误使用：

- 开局就填 coverage 表。

## 15. Knowledge library 最终方向

知识库不做百科，只做专家外脑。

收：

- bypass；
- 经验；
- 误判反例；
- 低风险验证技巧；
- 攻击链连接器；
- 真实案例 router；
- 模型容易漏的判断条件。

不收：

- 基础漏洞原理；
- 大段方法论 prose；
- payload dump；
- 靶场答案；
- 目标专属 URL、token、账号、PII。

新经验落位：

| 内容 | 落位 |
|---|---|
| 技巧 / bypass / 经验 | `knowledge/cards/` 或 on-demand references |
| 判断标准 | `evidence_rubric.py` |
| 路由触发 | `context_pack.py` |
| 下一步动作 | `checkpoint.py` |
| 稳定执行 | `validation_runner.py` |
| 结果证据 | `evidence_ledger.py` |
| 目标 actor/object/session | `state/<target>/case_state.json` |
| 一次性目标事实 | `recon/` / `evidence/` / `findings/` / `state/` |

## 16. 工具治理

不再新增专用工具，除非满足：

```text
同类动作出现 3 次以上
+
AI 已能判断但手工证据不稳定
+
工具输出 baseline / variant / diff / evidence / next action
+
有测试
+
能接入 ledger / finding / queue
```

否则优先改：

- autopilot prompt；
- context_pack route；
- knowledge card；
- evidence rubric；
- 已有工具。

工具分级：

### Core runtime

```text
context_pack.py
surface.py
autopilot_state.py
checkpoint.py
action_queue.py
target_case_state.py
case_state_seed.py
evidence_ledger.py
validation_runner.py
finding_index.py
coverage_matrix.py
runtime_doctor.py
```

### Browser adapters

```text
browser_mcp_import.py
browser_surface.py
browser_evidence.py
```

### Enrichment adapters

```text
js_reader.py
source_intel.py
intel_engine.py
cve_hunter.py
param_discovery.sh
secrets_hunter.sh
cloud_recon.sh
```

### Manual / optional helpers

```text
cf_solver.py
bypass_403.sh
spray_orchestrator.sh
wordlist_engine.sh
osint_employees.sh
breach_checker.py
```

### Legacy / experimental

不默认进入 `/autopilot` 主循环，只在明确触发或人工选择时使用：

```text
h1_*
zendesk_*
validate_*_chinaaid.sh
one-off PoC scripts
old scanner helpers
```

## 17. 压测指标

不要用“通关数量”衡量项目能力。

每轮压测记录：

### 17.1 发现能力

- fresh target 是否先 recon；
- browser-observed XHR/API 数量；
- JS/source/recon 合流数量；
- P1 中真实业务 API 占比；
- P1 重复 dead-end 数；
- 高价值入口遗漏数；
- 登录后 surface 是否进入 ranking。

### 17.2 验证能力

- lead -> signal 数；
- signal -> candidate 数；
- candidate -> tested_finding 数；
- tested_clean / dead_end 是否有 raw evidence；
- validation_runner 是否能复现；
- MCP/browser evidence 是否被导入和复用。

### 17.3 AI 能力

- 是否能从页面行为推到底层 API；
- 是否能形成 actor/object/session hypothesis；
- 是否能串联 A -> B -> C；
- 是否能在无信息增益后换 lane；
- 是否能解释为什么降级或停止。

### 17.4 状态收敛

- action_queue active 是否减少；
- final 状态是否被 surface/checkpoint 尊重；
- finding_index / report 状态是否同步；
- case_state backlog 是否被消费；
- coverage gaps 是否解释清楚。

### 17.5 Claude CLI 体验

- `/autopilot` 是否少问问题、自主推进；
- 是否出现“只给 TODO 不执行”；
- 是否因为规则过多变得保守或机械；
- 是否每轮都能给出下一条具体证据动作。

## 18. 实施路线

### Phase 0：固化规划

动作：

- 保存本规划；
- 确认不再围绕单点现象新增专用工具；
- 检查 Claude runtime drift。

命令：

```bash
python3 tools/runtime_doctor.py
```

验收：

- 本文档存在；
- runtime drift 已知；
- 下一步改动围绕 autopilot 主流程校准，不再点状加工具。

### Phase 1：校准 `commands/autopilot.md`

目标结构：

```text
1. Parse Target
2. Fresh vs Existing Target
3. Recon / Cache Check
4. Business Model / Crown Jewels
5. Surface Ranking
6. Workflow Capture
7. Skill / Knowledge Route
8. Hypothesis
9. Minimal Proof
10. Chain Expansion
11. Validation
12. Record
13. Report / Checkpoint / Coverage
```

重点：

- fresh target 先 recon；
- existing target cache-aware；
- checkpoint / queue / coverage 后移到阶段收束；
- 保留 MCP-first、AI override、red-line、candidate gate；
- 保留四层记忆系统，但不让它抢方向盘。

### Phase 2：校准 `agents/autopilot.md`

重点：

- prime directive 改为 super pentester + four-layer memory；
- fast startup 不再把 coverage/checkpoint 作为开局重工具；
- 明确 checkpoint / coverage 在 meaningful action 后或 finish 前使用；
- 明确 workflow capture 和 crown-jewel hypothesis 优先。

### Phase 3：同步 Claude CLI runtime

等文案和测试确认后：

```bash
python3 tools/runtime_doctor.py --sync --kind commands,agents,skills
```

验收：

```text
runtime_doctor drift = 0
```

### Phase 4：压测验证

用 Juice Shop / DVWA / PortSwigger / 授权目标压测。

验证：

- fresh target 是否先 recon；
- existing target 是否避免重复 recon；
- surface 是否驱动下一步；
- MCP/browser 是否抓到真实 workflow；
- Claude 是否能生成 crown-jewel hypothesis；
- primary signal 后是否扩链；
- 证据是否落盘；
- action_queue 是否防重复但不限制 AI；
- checkpoint 是否只在阶段收束；
- coverage 是否只在 finish/handoff 发挥作用。

## 19. 最终结论

最终优化主线：

```text
Expert Hunter Autopilot
=
super pentester 决策循环
+
四层记忆系统外脑
+
MCP/browser 真实业务流
+
工具化证据闭环
```

不要优化成“更会跑工具的 autopilot”。

要优化成：

```text
像 super pentester 一样理解目标和找攻击链，
用四层记忆系统保证不忘、不乱、不重复，
用工具把证据稳定落盘。
```
