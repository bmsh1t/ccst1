---
name: web2-vuln-classes
description: Use when evidence or focus names a concrete Web/API bug-class lane — IDOR/access control, JWT/OAuth/SAML, GraphQL, SQLi/NoSQL, SSRF, upload, SSTI, deserialization/ViewState, XXE, path traversal, smuggling, cache poisoning/deception, race, browser boundary, WebSocket, LLM tool flow, or controlled RCE. Answers which lane's evidence gates, card recall, and stop conditions apply after the lane is chosen; general technique knowledge and exact test syntax stay with the model, and it never runs a class checklist or bypasses triage-validation before reporting.
---

# WEB2 VULN CLASSES — Routing Layer

This Skill is the decision layer after Claude selects a concrete Web/API bug-class
lane. General technique knowledge and exact test-input syntax come from the model;
this file keeps project-specific routing, evidence gates, and lifecycle boundaries.

## Runtime Contract

1. Read target memory first: current surface, hypothesis, active leads, and dead ends.
2. Pick one evidence-backed lane; do not run a generic class checklist.
3. Establish a baseline before changing one boundary at a time.
4. Use the model's least invasive test input for the observed parser, identity,
   state, cache, browser, or transport boundary; use one changed axis at a time.
5. Save target-bound raw evidence for every Candidate and queue executable actions.
6. Use `triage-validation` before reporting; a framework name, status code, or
   parser error alone remains a Lead/Signal.
7. Write the result to the existing owner and leave a concrete next action or stop reason.

## Four-Layer Memory Hooks

Use `skills/runtime-protocol.md#shared-knowledge-recall` for card recall from either
entrypoint. Context Pack selects cards; this Skill supplies the boundary decision and
evidence gate. A recommendation is not a file read, and this Skill keeps no card map.

Cards provide patterns, counterexamples, and evidence prompts. They do not own
the target state or force an execution sequence.

## Boundary-First Pattern Router

Use the distilled project decision shape, not a fixed technique route:
`boundary -> baseline -> hidden surface -> bug family -> primitive -> connector -> impact`.
Keep this as an AI reasoning aid; do not import flag hunting, admin-bot assumptions,
DoS/ReDoS, persistent shell, or broad payload spraying into real targets.

At each pivot record `Evidence`, `Primitive`, `Connector`, `Impact hypothesis`,
`Next action`, and `Stop condition`. Use explicit `Primitive:` and `Connector:`
entries. The model may skip, combine, or invent a
branch when the observed evidence justifies it.

### Target Profile First Branch

从目标画像出发的注意力分布，不是决策树也不排除任何类别；每一行只是
"这类目标的历史高价报告集中在哪里"，模型保留完整的选择与倒序自由。

| 目标特征 | 高危面分布（按历史高价报告） |
|---|---|
| Java 栈 + JSON API | deserialization > authz > SSRF |
| 文件处理链（上传/转换/导入） | parser 链 > deserialization > 越权 |
| 支付/订单工作流 | 状态机 > 幂等/并发 > 越权 |
| 多租户 SaaS | 租户隔离 > 对象级越权 > 注入 |
| 复杂认证（SSO/MFA/恢复流） | token 边界 > 恢复流接管 > 会话固定 |
| 移动端 API 后端 | 旧版 API 越权 > 参数污染 > 批量接口 |

### Pattern Map

| Signal | Route |
|---|---|
| Object ID, tenant/org/user/account/invoice/order IDs | IDOR / object authorization |
| Token, callback, redirect, JWK/JKU/KID, SAMLResponse | JWT/OAuth/SAML/SSO |
| Query, sort, filter, report, export, header/cookie/path input | SQLi/NoSQL hidden surface |
| URL fetch, webhook, import, preview, callback | SSRF URL fetch; internal impact only after server-side proof |
| Upload, import, convert, preview, SVG/Office/XML | Upload parser; safe verification and read-back before storage, access, and execution proof |
| Template syntax, command output, shell primitive | SSTI/command/controlled RCE |
| ASP.NET `__VIEWSTATE` / ViewState / machineKey | Insecure deserialization / ViewState integrity |
| JSON body with `@type`/type-field shape, Java/fastjson/Jackson/Shiro stack signal | Insecure deserialization (Java) |
| CL/TE, host header, proxy trust, cache key, unkeyed header | Proxy/cache/smuggling |
| Origin, postMessage, DOM, CORS, clickjacking | Browser boundary |
| WS handshake/frame/subscription | WebSocket / realtime API |
| Source/config/secret/file read signal | Info disclosure / path traversal / management exposure |

## Focused Route Notes

### Object-Level Auth Matrix

Compare the same target-bound action across two owned identities, object IDs,
methods, fields, and workflow states. A stable 403/404 or no server-side delta is
a stop condition; introspection or a UI difference is not an authorization proof.
多 session 场景用矩阵方法：对每个高价值端点在 owner/peer（必要时 cross-tenant）
上下文各发一次同样请求，只比较身份/对象/角色差，纯状态码差保持 Signal。
机器重放用 request-diff owner/peer 对（`active_dimension=header:authorization`），
匿名暴露用无凭据 vs 有凭据对；越权与否由 validate gates 判断。

### Access-Control Boundary Matrix

Use raw replay for URL, method, path/header rewrite, and other observed access
boundaries. The method diff -> path/header rewrite -> raw replay branch is optional
evidence-driven routing, not a fixed dictionary. Use Playwright request/raw replay
when browser fetch cannot preserve the observed request.

### Missing Parameter Signal Lane

Use target material, schemas, source, and parser errors to build a target-specific wordlist.
Test one low-impact parameter at a time; Do not bulk-enumerate real users,
PII, passwords, addresses, or tokens. Preserve the raw differential and request
the `missing-param` focus through the shared recall rule.

### Management Exposure Lane

Use target naming and observed routes for read-only fingerprinting and an auth
boundary check. Do not import keys into cloud panels or take resource control;
record minimal config evidence and a validation plan.

### SQLi Lane Flow

示例输入面按证据选择，不是固定顺序; not a fixed checklist. When ordinary
parameters are quiet, check observed hidden surfaces such as headers, path segments,
or second-order inputs; establish a baseline and require a boolean/length or
time/OOB differential. A DNS-only SSRF signal needs a second signal proving a
server-side fetch before impact routing. Change one boundary at a time and stop on
unstable or WAF-only output; the model chooses syntax from the observed query shape.
For request specs, encode query/path/form values structurally and keep JSON as
JSON; do not hand-encode twice or treat an encoding-only response change as a
finding. 时间型信号用交错 baseline/variant 采样验证趋势（中位数/MAD 稳定才算
数；单次慢响应、`429`、WAF 块页、传输错误保持 partial）。

### Hidden Auth Switch Lane

Start with an owned/test account baseline across the visible flow and any observed
provider, channel, or role selector. Do not silently fall into password brute force.
If credential testing is selected, route to `skills/credential-attack/` or a
controlled `/spray` run with lockout, rate limits, and stop conditions.

### GraphQL Lane

发现 GraphQL endpoint 后做有界 introspection（schema/operation 名称、`node(id)`
可枚举性），双角色对象对照用 `validation_runner.py request-diff` owner/peer 对；批量/alias 只测最小次数，订单生命周期 mutation 只记录不执行。

### Workflow Perturbation Lane

捕获到 ≥2 个有序同目标业务请求时，按步做单变量 remove/repeat 扰动：每步只
删除或重复一个参数/步骤，短时效 token（CSRF/session 刷新）按观察到的来源
重新提取，raw 流量落私有证据；响应差异在 AI 审查影响与可重放性前保持
Candidate。

### JWT / Token AI-Owned Lane

令牌伪造类证据的机器证明通道：`request-diff` 保存精确
请求对（见 `knowledge/cards/auth-sso-token-edge-cases.md`）；
身份/权限 delta 之外的差异（可 decode、状态/长度、反射 marker）保持
Signal/Candidate。

### Java Deserialization Lane

进入条件是形态信号（`@type`/type-field 输入面、序列化对象标记、Java 栈 +
JSON content-type），不是已确认的漏洞词。版本矩阵与会话中段的可靠召回锚见
`knowledge/cards/insecure-deserialization.md`。

### Webhook / Callback Lane

Webhook/callback 注册面同时是 SSRF URL fetch 入口、签名验证绕过面和
并发重放面（幂等/限流/状态迁移），三个方向共享同一证据基线。

## Chain Shapes

Treat these as connector examples, not an allowlist:

| Primitive | Connector | Validated impact |
|---|---|---|
| Open redirect | OAuth callback / token leakage | Account or code boundary proof |
| SSRF callback | Internal service / metadata credential | Raw data or control-plane impact |
| Upload parser | Stored file / converter | Parser or controlled execution proof |
| GraphQL introspection | Node/global ID / mutation auth | Object or field authorization proof |
| XSS | Session action / admin browser | Sensitive action or data proof |
| Request smuggling | Cache, capture, or auth boundary | Victim-facing request/response proof |
| Info disclosure | Source/config/route/secret | Follow-on boundary proof |
| Race primitive | Quota/payment/OTP/state transition | Controlled state-delta proof |

## Evidence and Write-Back

Before escalation, require a raw baseline, a controllable input, a reproducible
differential, and the smallest demonstrated impact. A `server-side fetch`,
`field-level auth matrix`, `introspection alone is informational`,
`storage/access/execution`, `baseline/type classification`, or `state machine/bounded
parallel replay` phrase is a prompt for evidence, not a finding by itself. Use the
current user/test resource for race checks. Record the selected route, action, evidence references, coverage,
dead ends, remaining unknowns, next action, and owner write-back using the shared
`SKILL RESULT` contract.

## Global Stop Conditions

Stop or downgrade to Lead when there is no raw baseline, no controllable input, no
owned/test identity where required, no repeatable response/state delta, or only a
framework/status/parser signal without a target-bound connector.
