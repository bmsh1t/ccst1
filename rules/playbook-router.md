# Web 渗透 Playbook Router（advisory）

这个文件只做 Claude CLI 的注意力增强：看到某类 Web 渗透证据时，提示应该读取哪个本地参考、优先使用当前项目哪个工具。它不是状态机，不自动触发利用，不替代当前 `next_question` 驱动的判断。

## 使用原则

1. **先有证据，再查参考**：只有当前 recon、JS、source、browser、HTTP replay 或报错信息已经指向某类问题时才读取对应条目。
2. **只用已蒸馏项目知识**：默认路由只指向本仓库知识卡、payload pack、playbook 和规则；外部原文只留审计追溯。
3. **工具选择仍由 Claude 判断**：本表只给候选工具；如果当前证据不匹配，忽略本表。
4. **不做 payload spray**：没有明确输入点、回显/侧信道、状态差异或可复现请求时，保持为 Lead，不升级。
5. **报告前仍走验证门**：本表产出的都是 hypothesis fuel，只有当前目标复现证据才能进入 Candidate/Validated Finding。

## Active reference 范围

默认只允许参考项目内已蒸馏资产：

```text
knowledge/cards/
knowledge/payloads/
knowledge/playbooks/
rules/
skills/security-arsenal/references/
```

原始外部笔记、CTF 题解、payload 字典和本机绝对路径不参与默认路由。若需要追溯
为什么某个外部模式没有吸收，读取 `docs/ctf-web-distillation-audit.md`，不要把它
当作运行时 playbook。

弱口令爆破不是绝对红线，但不走本 Web playbook router 的 payload 利用路径；
当登录面是合理突破口或其他高价值 lane 缺乏进展时，转
`skills/credential-attack/` / `/spray` 受控口令流程，并按
`rules/red-lines.md` 的自主选择条件、限速、审计和停止条件执行。

## Signal → Reference → Tool

| Signal / 证据形态 | Delta reference | 当前项目优先工具 / 动作 | 停止条件 |
|---|---|---|---|
| 真实 JWT/JWE token；`kid`/`jku`/`jwk`/`iss`/JWKS/OIDC metadata；JWT claims 参与权限、租户或余额 | `knowledge/cards/auth-sso-token-edge-cases.md` | 先无验证 decode；有真实 token 再考虑 `jwt_tool`；用 `curl`/`urllib` 读取 JWKS/OIDC metadata；用最小 replay 证明 auth boundary | 没有真实 token、没有 issuer/JWKS metadata、没有可 replay 的权限差异时停止 |
| `/admin`、`/internal`、`/api/export`、`/debug` 等 401/403；encoded slash、双斜杠、大小写、尾随点/分号响应差异；网关与后端栈不一致 | `knowledge/cards/auth-access.md`, `knowledge/cards/path-allowlist-normalization.md`, `knowledge/cards/path-pattern-management-exposure.md` | `tools/bypass_403.sh`；`curl --path-as-is`；方法切换；header/path 单变量 replay；记录响应差异 | 三类 payload 响应完全一致，且无栈特征/路径规范化差异时停止 |
| `url`/`uri`/`webhook`/`callback`/`image`/`fetch`/`import` 参数；PDF/image/HTML 转换器；OAST/DNS 回调 | `knowledge/cards/ssrf-url-fetch.md`, `knowledge/cards/ssrf-internal-impact.md`, `knowledge/cards/render-pipeline-ssrf.md` | `tools/oast_listen.py`；redirect/parser probe；只在 URL fetch 已成立后测试 metadata/internal-service 方向 | 只有 DNS-only 且无法证明内部访问/数据返回/状态影响时保持 Lead |
| upload/import/convert/export/download；DOCX/SVG/PDF/image/archive 处理；文件名、EXIF、QR、条码、压缩包参与后端逻辑 | `knowledge/cards/upload-parser.md`, `knowledge/cards/upload-to-execution.md`, `knowledge/cards/xxe-xml-parser.md`, `knowledge/cards/sqli-hidden-surfaces.md` | 浏览器/HTTP 精确复现；最小样本文件；OAST 仅用于 parser side effect；`tools/role_diff.py` 测导出/下载授权 | 无可控文件内容/文件名/metadata，或上传后不可触达任何处理路径时停止 |
| Node/Express/lodash/qs/flat/pug/vm2/happy-dom；JSON merge/clone/deep set；JS/source 暴露服务端渲染或模板链 | `knowledge/cards/node-prototype-pollution.md` | `/source-hunt`、`run_source_intel`、`run_js_read`；JSON body 单变量 pollution probe；寻找权限字段/模板 sink | 没有 Node 相关栈证据或没有 JSON/对象合并输入点时停止 |
| SQL/NoSQL 但普通参数无效；Header、EXIF、QR、XML、stored profile、Host、X-Forwarded-For、LDAP filter、Mongo regex/$where 参与查询 | `knowledge/cards/sqli-hidden-surfaces.md`, `knowledge/cards/nosql-query-injection.md` | `tools/json_inject_probe.py`；单参数错误/时间/布尔差异；必要时自写小 probe；避免直接 broad sqlmap | 无错误差异、时间差异、状态差异或查询上下文证据时停止 |
| Java/Python/PHP/.NET/Werkzeug/SoapClient serialized blob、cookie、backup/import、session object、`rO0AB`、`aced0005`、pickle/base64 形态 | `knowledge/cards/insecure-deserialization.md`, `knowledge/cards/controlled-rce-impact.md` | 先 decode/识别格式；OAST URLDNS/JRMP 只在 lab/安全边界明确时用；优先证明反序列化触发而非 RCE | 不能证明对象被后端反序列化，或只是静态字符串存储时停止 |
| GraphQL endpoint、introspection、`node(id)`、批量 query、mutation、tenant/user/object id | `knowledge/cards/graphql.md`；同时参考项目 `web2-vuln-classes` | manual introspection；`tools/role_diff.py`；批量/alias 只测最小次数；订单生命周期 mutation 只记录不执行 | 没 schema/operation 名称、无对象 ID、无身份差异时停止 |
| `ws://`/`wss://`、`new WebSocket`、socket.io/SockJS/SignalR、GraphQL subscription、WS frame 里有 user/account/tenant/channel id | 项目 `web2-vuln-classes` 的 WebSocket/CSWSH lane | 浏览器/JS 抓 handshake 和 frame；手工比较 Origin/session/subscription 权限；`tools/hai_payload_builder.py --type websocket` 只作 payload 参考，不自动发送 | 没有认证 WS、没有 frame schema、没有可控 ID/channel，或 Origin 一致拒绝时停止 |
| OAuth/OIDC/SAML/SSO callback、`redirect_uri`、`state`、`client_id`、SAMLResponse、NameID、ACS endpoint；email 作为 SSO/account-linking 身份键 | `knowledge/cards/auth-sso-token-edge-cases.md`, `knowledge/cards/auth-credential-recovery-flows.md` | 手工 decode SAML/OIDC；只测试 redirect/state/session/email-normalization 绑定和签名/处理差异；`tools/h1_oauth_tester.py` 仅用于 HackerOne/H1-compatible 目标或模式参考 | 没有完整 auth flow 或无法控制回调参数时停止 |
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
Reference: 本表对应的项目知识卡、payload pack、playbook 或规则路径
Next action: 一个最小可 replay 的请求、角色差异测试、OAST probe 或 source grep
Stop condition: 何时放弃该方向
```
