---
id: web2-evidence-contracts
type: workflow-card
related_cards:
  - knowledge/cards/api-idor.md
  - knowledge/cards/auth-sso-token-edge-cases.md
related_skills:
  - triage-validation
trigger_tags:
  - evidence-gates
  - web-api-boundary
risk: low
maturity: tested
load_priority: low
source_refs: []
---

# Web/API 边界证据合同

## Quick Recall

- 此文承接既有 Web2 Skill 的完整证据门，不是新增方法效果声明。
- 按当前问题直接读取相关段，允许跨域组合和无卡调查；不要求先经过域索引或全表。
- Signal、Candidate、Finding 与交付资格分离，未知/缺材料不伪装为阴性。
- `maturity: tested` 表示既有工程合同承接，不表示某目标漏洞成立或新模型能力通过。

## 流程：原有运行合同

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
entrypoint. Context Pack publishes the card catalog; the AI selects by current
information gap. A catalog path is not a file read, and this Skill keeps no card map.

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

这是一个由目标、证据和信息缺口驱动的动态决策树，而非固定流程或类别白名单。
登录态、技术栈、功能形态和 ROI 只是可用示例；版本、租户关系、数据流、错误语义、
部署边界或模型提出的其它维度同样可以采用，维度可以交叉、跳过、重开或替换。
表格只保留历史高价报告中的注意力线索，不能生成强制探测顺序、机器准入或排除其它类别。

| 目标特征 | 高危面分布（按历史高价报告） |
|---|---|
| Java 栈 + JSON API | deserialization > authz > SSRF |
| 文件处理链（上传/转换/导入） | parser 链 > deserialization > 越权 |
| 支付/订单工作流 | 状态机 > 幂等/并发 > 越权 |
| 多租户 SaaS | 租户隔离 > 对象级越权 > 注入 |
| 复杂认证（SSO/MFA/恢复流） | token 边界 > 恢复流接管 > 会话固定 |
| 移动端 API 后端 | 旧版 API 越权 > 参数污染 > 批量接口 |

### Pattern Map

When several lanes match at once, compare the observed evidence, expected
information gain, plausible impact, reversibility, ownership, and cost. The map
below offers route clues; it does not impose a category order or require every
matching lane to be tested.

| Signal | Route |
|---|---|
| Object ID, tenant/org/user/account/invoice/order IDs | IDOR / object authorization |
| Token, callback, redirect, JWK/JKU/KID, SAMLResponse | JWT/OAuth/SAML/SSO |
| Query, sort, filter, report, export, header/cookie/path input | SQLi/NoSQL hidden surface |
| URL fetch, webhook, import, preview, callback | SSRF URL fetch; internal impact only after server-side proof |
| Upload, import, convert, preview, SVG/Office/XML | Upload parser; safe verification and read-back before storage, access, and execution proof |
| Template syntax, command output, shell primitive | SSTI/command/controlled RCE |
| ASP.NET `__VIEWSTATE` / ViewState / machineKey | Insecure deserialization / ViewState integrity |
| IIS/ASP.NET server fingerprint | IIS short filename (~1) enumeration lane — `shortscan` is the tool (the scanner auto-runs it on detected IIS hosts; missing tool degrades to a manual review hint); enumerated filenames feed path/secrets discovery |
| JSON body with `@type`/type-field shape, Java/fastjson/Jackson/Shiro stack signal | Insecure deserialization (Java) |
| Signed/anti-bot header (sign/sig/hmac/nonce/X-Sensor) blocks replay | Client signer lane — recover the signer only enough to replay the request; reversed signing alone is N/A, hunt the IDOR/authz/business-logic bug on the endpoint the signature was guarding |
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
If credential testing is selected, read `skills/src-hunter/modules/credential-attack.md` or use a
controlled `/spray` run with lockout, rate limits, and stop conditions.

### GraphQL Lane

发现 GraphQL endpoint 后按当前信息缺口选择有界 introspection（schema/operation 名称、
`node(id)` 可枚举性）或双角色对象对照；精确 HTTP 操作用
`validation_runner.py request-diff` owner/peer 对。批量、alias 和 mutation 都要先看
实际副作用：对测试自有且可回滚的资源，可以在 `rules/red-lines.md` 允许的最小范围内
验证；真实订单生命周期或不可逆动作只记录为 Lead，并保留后续安全验证条件。

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

## 信号与方法索引（必要旧合同承接）

这个 advisory router 只在 recon、JS、source、browser、HTTP replay 或报错证据指向某类问题时，提示本地参考和候选工具；不自动触发执行，也不替代当前 `next_question` 的判断。只使用仓库内已蒸馏资产；没有明确输入点、回显/侧信道、状态差异或可复现请求时保持 Lead，报告前仍须通过验证门。

## Active reference 范围

默认只允许参考项目内已蒸馏资产：

```text
knowledge/cards/
knowledge/payloads/
knowledge/playbooks/
rules/
```

原始外部笔记、CTF 题解、payload 字典和本机绝对路径不参与默认路由。若需要追溯
为什么某个外部模式没有吸收，读取 `docs/ctf-web-distillation-audit.md`，不要把它
当作运行时 playbook。

弱口令测试不是红线，也不走本 Web playbook router 的通用验证输入路径。观察到登录框时，
读 `skills/src-hunter/modules/credential-attack.md` 做 baseline review；稳定测试账号、默认/常见候选和
是否进入 `/spray` 的场景策略、执行节奏、审计和停止条件均由该模块与命令契约负责。

## Signal → Reference → Tool

| Signal / 证据形态 | Delta reference | 当前项目优先工具 / 动作 | 停止条件 |
|---|---|---|---|
| 真实 JWT/JWE token；`kid`/`jku`/`jwk`/`iss`/JWKS/OIDC metadata；JWT claims 参与权限、租户或余额 | `knowledge/cards/auth-sso-token-edge-cases.md` | 先无验证 decode；有真实 token 再考虑 `jwt_tool`；用 `curl`/`urllib` 读取 JWKS/OIDC metadata；用最小 replay 证明 auth boundary | 没有真实 token、没有 issuer/JWKS metadata、没有可 replay 的权限差异时停止 |
| `/admin`、`/internal`、`/api/export`、`/debug` 等 401/403；encoded slash、双斜杠、大小写、尾随点/分号响应差异；网关与后端栈不一致 | `knowledge/cards/auth-access.md`, `knowledge/cards/path-allowlist-normalization.md`, `knowledge/cards/path-pattern-management-exposure.md` | AI 根据目标证据选择一个精确的 path/header/method 请求，用 browser/curl/raw sender 执行；同方法单变量请求对可选交给 `validation_runner.py request-diff`；否则保留 raw evidence/`finding_claim` 并交给 Checkpoint | baseline、随机 miss、路径/Header 单变量无稳定后端/内容/权限差异时停止；状态变化单独保持 Signal |
| Spring/Java 指纹、`/actuator`、Jolokia、Whitelabel、heapdump/management path | `knowledge/cards/path-pattern-management-exposure.md`, `knowledge/cards/information-disclosure-source-config.md` | 比较不存在路径、Actuator root 和单个只读 endpoint；确认 content-type、JSON link/key、heapdump magic 或目标特定数据 | 200 返回登录页、Whitelabel、SPA fallback、统一错误页或普通 health 文案时保持 Signal |
| WordPress、`wp-json`、`wp-content/plugins`、主题、`admin-ajax.php`、`xmlrpc.php`、已知插件/主题版本 | `knowledge/cards/wordpress-surface-intelligence.md` | 高价值目标且版本/覆盖缺口存在时按需执行有界 `wpscan --enumerate p,t`，保存 raw JSON；随后验证组件启用、版本范围、路由与权限/影响边界 | WPScan 命中、残留静态文件、`wp-json`/XML-RPC 可达或单个 200 只算 Signal；无启用版本、可达路由或稳定影响时不测试历史 CVE |
| `url`/`uri`/`webhook`/`callback`/`image`/`fetch`/`import` 参数；`/_next/image`；PDF/image/HTML 转换器；OAST/DNS 回调 | `knowledge/cards/ssrf-url-fetch.md`, `knowledge/cards/ssrf-internal-impact.md`, `knowledge/cards/render-pipeline-ssrf.md` | `tools/oast_listen.py`；Next image 先做正常图片 baseline 和唯一 callback；redirect/parser probe；只在 URL fetch 已成立后测试 metadata/internal-service 方向 | `/_next/image` 只有 200/400、图片体或 optimizer 错误，或只有 DNS-only 且无内部访问/数据/状态影响时保持 Lead |
| upload/import/convert/export/download；DOCX/SVG/PDF/image/archive 处理；文件名、EXIF、QR、条码、压缩包参与后端逻辑 | `knowledge/cards/upload-parser.md`, `knowledge/cards/upload-to-execution.md`, `knowledge/cards/xxe-xml-parser.md`, `knowledge/cards/sqli-hidden-surfaces.md` | 浏览器/HTTP 精确复现；最小样本文件；OAST 仅用于 parser side effect；导出/下载授权用 owner/peer 双账号对照 | 无可控文件内容/文件名/metadata，或上传后不可触达任何处理路径时停止 |
| Node/Express/lodash/qs/flat/pug/vm2/happy-dom；JSON merge/clone/deep set；JS/source 暴露服务端渲染或模板链 | `knowledge/cards/node-prototype-pollution.md` | `/source-hunt` 与 Claude 原生 Read/Grep；JSON body 单变量 pollution probe；寻找权限字段/模板 sink | 没有 Node 相关栈证据或没有 JSON/对象合并输入点时停止 |
| SQL/NoSQL 但普通参数无效；Header、EXIF、QR、XML、stored profile、Host、X-Forwarded-For、Mongo regex/$where 参与查询 | `knowledge/cards/sqli-hidden-surfaces.md`, `knowledge/cards/nosql-query-injection.md` | AI 根据真实请求形状选择直接测试；需要同方法单变量重放时可用 `validation_runner.py request-diff`；时间信号用 AI 交错采样验证趋势；不使用固定矩阵 | 无错误差异、时间差异、状态差异或查询上下文证据时停止 |
| OData header/service document、`$metadata`、`$filter`、`$select`、`$orderby`、`$expand`、`$batch` | `knowledge/cards/odata-query-boundaries.md` | 保存 owner baseline；比较字段、predicate/order、navigation 和 direct-vs-batch；必要时用 `validation_runner.py request-diff`（owner/peer 对，`active_dimension=header:authorization`）做对象/租户对照 | metadata/operator/HTTP 200 单独保持 Signal；无受限字段、关联对象或 batch 策略差异时停止 |
| LDAP/AD/目录搜索错误、LDAP filter/DN 拼接、XPath parser/expression、员工搜索/组织图 | `knowledge/cards/ldap-xpath-query-boundaries.md` | 先确认 filter/DN/XPath context；建立合法/false/语法错误 control；只在测试对象上比较 auth/result/attribute 差异 | 只有 backend 指纹、wildcard 正常搜索、单次 500/长度差或 XPath quote error 时停止 |
| Java/Python/PHP/.NET/Werkzeug/SoapClient serialized blob、cookie、backup/import、session object、ViewState、`rO0AB`、`aced0005`、pickle/base64 形态 | `knowledge/cards/insecure-deserialization.md`, `knowledge/cards/controlled-rce-impact.md` | 先按格式/绑定识别 → MAC/签名/加密完整性 → 真实 deserialize/consume 验证；OAST URLDNS/JRMP 只在 lab/安全边界明确时用 | 不能证明对象被后端反序列化/消费，或 ViewState 只有可见、可解码、MAC error 时停止 |
| GraphQL endpoint、introspection、`node(id)`、批量 query、mutation、tenant/user/object id | `knowledge/cards/graphql.md`；同时参考本文件的 Web/API 证据合同 | manual introspection；双角色对象对照用 `validation_runner.py` 原语；批量/alias 只测最小次数；mutation 按真实副作用分支，测试自有且可回滚资源可在红线控制内验证，不可逆真实订单动作只记录 | 没 schema/operation 名称、无对象 ID、无身份差异时停止 |
| Next.js `/_next/data/<build-id>/...json`、动态 route data、`__NEXT_DATA__` | `knowledge/cards/api-idor.md`, `knowledge/cards/information-disclosure-source-config.md` | 比较 anonymous/owner/peer/cross-tenant；保持 route/build-id 不变，只替换一个对象 ID，并和 HTML/API baseline 对照 | 只有公开 prerender JSON、build metadata、当前 owner 数据或单账号 200 时停止 |
| `application/grpc*`、grpc-status/trailers、protobuf、reflection、gRPC-Web、grpc-gateway、JSON transcoding | `knowledge/cards/grpc-api-boundaries.md` | 保存 h2 headers/body/trailers；区分 status 12/16/7/3/0；比较 edge/backend metadata 和自有身份/对象差异 | reflection、status 12/3 或 HTTP 200 单独只算 transport/method Signal；无私有数据或状态差异时停止 |
| Cognito `IdentityPoolId`、`GetId`、`GetCredentialsForIdentity`、unauth role、临时 STS | `knowledge/cards/cloud-cognito-identity-pool.md`, `knowledge/cards/cloud-control-plane-pivots.md` | 从目标配置确认 region/pool；依次记录匿名凭证是否签发、caller ARN、单个 IAM action/resource allow/deny | `IdentityPoolId` 或 `GetId` 成功不升级；没有匿名凭证、caller 和非预期 action 影响时停止 |
| Kubernetes API、kubelet 10255/10250、service-account token、RBAC、`nodes/proxy`、pods subresource | `knowledge/cards/k8s-control-plane-boundaries.md`, `knowledge/cards/cloud-control-plane-pivots.md` | 区分组件/endpoint；检查 token audience/expiry；用 SelfSubjectRulesReview/AccessReview 或 `kubectl auth can-i` 确认 verb/resource/subresource | API/namespace 200、10255 信息或 token 格式不等于 cluster-admin；无具体 allow 和资源影响时停止 |
| CI workflow/package config、内部包名、registry 404、public fallback、lockfile/build log/SBOM/image layer | `knowledge/cards/cicd-trust-boundaries.md` | 先证明目标构建实际依赖该包，再证明 resolver 会回落公共 registry；用 lockfile/build log、SPDX/CycloneDX、Docker/GHCR layer 交叉确认版本与消费链 | public registry 404 单独只算 Lead；缺“实际依赖”或“公共回落”任一证据时不得进入 dependency-confusion Candidate |
| `ws://`/`wss://`、`new WebSocket`、socket.io/SockJS/SignalR、GraphQL subscription、WS frame 里有 user/account/tenant/channel id | `knowledge/cards/websocket-realtime-api.md` 与本文件的 WebSocket/CSWSH lane | 浏览器/JS/MCP 抓 handshake 和 frame；由 AI 基于目标证据选择最小对照与 replay，保留 raw evidence | 没有认证 WS、没有 frame schema、没有可控 ID/channel，或 Origin 一致拒绝时停止 |
| OAuth/OIDC/SAML/SSO callback、`redirect_uri`、`state`、`client_id`、SAMLResponse、NameID、ACS endpoint；email 作为 SSO/account-linking 身份键 | `knowledge/cards/auth-sso-token-edge-cases.md`, `knowledge/cards/auth-credential-recovery-flows.md` | 手工 decode SAML/OIDC；由 AI 选择 redirect/state/session/email-normalization 绑定和签名/处理差异的最小对照并保留证据 | 没有完整 auth flow 或无法控制回调参数时停止 |
| branded SSO/UI 与 mobile、旧 REST、SOAP/XMLRPC、native/legacy login 并存 | `knowledge/cards/auth-hidden-switches.md`, `knowledge/cards/auth-credential-recovery-flows.md` | 用同一测试账号比较 MFA/step-up、限速、session/token、角色/租户和 logout/password-change 生命周期 | 端点可达、200/401、方法列表或错误格式差异不能升级；无最终认证策略/session/identity 差异时停止 |
| chatbot/RAG/agent/tool-use、URL/PDF/doc summarizer、AI 输出进入 Web UI、AI 工具有 fetch/code/browser/file 权限 | `knowledge/cards/web-llm-tool-chains.md` | Playwright/browser capture；良性 prompt-injection proof；验证是否导致 IDOR/SSRF/RCE/secret exposure，而不是只证明“听话” | 只能改变回复风格、无数据/权限/工具影响时不升级 |

## 不重复吸收的基础内容

这些已经由当前项目主文档覆盖，不要在 router 里重复扩写：

```text
普通 SQLi payload
普通 SSRF payload
普通 JWT none / RS256-HS256
普通 OAuth/SAML checklist
普通 GraphQL introspection
普通 file upload extension/MIME bypass
普通 XSS payload
```

## 输出纪律

当根据本表产生 Lead/Signal 时，记录必须包含：

```text
Evidence: 当前命中的 URL / 参数 / token / header / source path / response diff
Reference: 本表对应的项目知识卡、playbook 或规则路径
Next action: 一个最小可 replay 的请求、角色差异测试、OAST probe 或 source grep
Stop condition: 何时放弃该方向
```
