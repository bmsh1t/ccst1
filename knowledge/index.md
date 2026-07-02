# 知识库索引

默认只加载本索引。根据当前目标、skill、证据形态和假设，再选择具体知识卡或现有参考资料。

知识库是 Skills 的经验压缩库：负责提供可复用模式、思路分支、技巧家族、
payload 家族、bypass 思维、补充 checklist、反例、误判/死路和思路变形。
它不负责指挥流程。具体执行顺序、工具选择、验证深度和写回位置仍由当前
Skill 与检查层决定。

## 核心路由

| 文件 | 作用 | 何时读取 |
|---|---|---|
| `rules/playbook-router.md` | 证据形态到本地深度参考和项目工具的路由 | 已有 JWT、SSRF、OAuth、GraphQL、AI/RAG、上传解析等明确 Web 证据时 |
| `skills/security-arsenal/REFERENCES.md` | 外部参考库索引 | 当前项目内置方法论不够，需要外部 playbook、writeup、工具目录时 |
| `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` | 压缩方法论速查 | 需要快速补充某类漏洞的测试步骤时 |

## 核心决策知识卡

核心卡是默认决策层：用于当前 Skill 的主要 route、证据门、停止条件和覆盖提醒。
每次 context-pack 仍只选择 1-2 张，避免把知识库平铺进上下文。

| 知识卡 | 作用 | 推荐关联 Skill |
|---|---|---|
| `knowledge/cards/auth-access.md` | 认证、会话、角色、组织边界的发散问题 | `bb-methodology`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/auth-hidden-switches.md` | 登录隐藏分支选择器、认证状态机切换和低风险 ATO 验证思路 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/auth-credential-recovery-flows.md` | 密码重置、账号恢复、用户名枚举、MFA/OTP、remember-me 和受控凭证测试 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/auth-sso-token-edge-cases.md` | JWT/JWE/JWKS、OAuth/OIDC、SAML/SSO、token/account binding 边界异常 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/api-testing-workflow.md` | API docs/schema、浏览器 XHR、JS/source、mobile/旧版本和 parser/auth matrix 的补漏流程 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/business-logic-state-machines.md` | 业务逻辑、状态机、客户端信任、流程重排和异常输入验证思路 | `bb-methodology`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/api-idor.md` | API 对象级越权和多租户访问控制 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/missing-parameter-discovery.md` | `parameter is null` / 缺参响应驱动的隐藏参数发现与低风险验证 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/path-pattern-management-exposure.md` | 目标目录命名规律、管理/监控面暴露和只读访问记录驱动的二次发现 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/ssrf-url-fetch.md` | URL fetch、webhook、导入转换类 SSRF 思路 | `web2-vuln-classes`, `security-arsenal`, `triage-validation` |
| `knowledge/cards/ssrf-internal-impact.md` | SSRF 内部服务、metadata、控制面影响证明 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/graphql.md` | GraphQL、subscription、global ID 的权限边界 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/sqli-hidden-surfaces.md` | 请求元数据、路由片段、跨接口参数和二阶链路等 SQLi 非显式输入面 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/nosql-query-injection.md` | NoSQL 查询 operator、JSON/parser 和类型混淆注入 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/xxe-xml-parser.md` | XML parser、XXE、XInclude、SOAP/SAML/SVG/Office 二阶解析面 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/path-traversal-file-read.md` | 路径遍历、LFI、文件选择器和 file-read 链路 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/upload-parser.md` | 上传、导入、转换、解析器链路 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/upload-to-execution.md` | 上传后执行、webshell primitive 和受控影响证明 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/server-side-template-injection.md` | SSTI 输入面、模板引擎指纹和受控升级路径 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/insecure-deserialization.md` | 反序列化、signed object、ViewState/remember-me 和 sink 验证 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/xss-client-injection.md` | Reflected/Stored/DOM XSS 的输入面、输出上下文、payload 家族和最小浏览器执行证据 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/browser-client-boundaries.md` | CORS、CSRF、Clickjacking、DOM/postMessage 的浏览器边界验证 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/proxy-cache-boundaries.md` | Host header、代理信任、Request smuggling、Cache poisoning/deception | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/websocket-realtime-api.md` | WebSocket、CSWSH、订阅/发布和消息级权限 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/information-disclosure-source-config.md` | Debug、source map、备份、配置和源码泄露的影响链 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/web-llm-tool-chains.md` | Web LLM、prompt injection、RAG 和工具调用边界 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/controlled-rce-impact.md` | RCE / 命令执行 / shell primitive 的受控影响证明 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/node-prototype-pollution.md` | Node/Express 对象污染、template/VM sink 和 RCE 链建模 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/race-conditions.md` | 并发状态差异和 race 风险的低风险建模 | `bb-methodology`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/coverage-prompts.md` | 覆盖基线漏测提醒 | `bb-methodology`, `web2-recon`, `web2-vuln-classes` |
| `knowledge/cards/dead-ends.md` | 常见低价值方向和停止条件 | `bb-methodology`, `triage-validation` |

## 蒸馏 Router 知识卡（从 8528 份披露报告蒸馏，`/distill`）

蒸馏卡不是默认方法论正文，而是低优先级 router / recall 层：
`trigger signal -> distilled card -> source_report_ids -> on-demand case lookup`。
只有当前 focus 或证据强命中触发信号时才读取；确认需要真实攻击链形状、报告写作先例或
相似案例时，再按卡片 footer 的 `source_report_ids` 查询本地 gitignored 案例库。
不要默认拉取报告全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。

| 知识卡 | 作用 | 推荐关联 Skill |
|---|---|---|
| `knowledge/cards/signature-scope-mismatch.md` | 验签字节与消费字节不一致、密钥未绑定身份（XSW/JWT/JWKS） | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/oauth-sso-trust.md` | OAuth/SSO 邮箱信任、audience/redirect 混淆致接管 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/view-differential.md` | 校验视图 vs 执行视图的规范化/编码/截断差 | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/request-smuggling.md` | HTTP 请求走私/降级/伪首部注入（含非 URL 字段 CRLF） | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/path-allowlist-normalization.md` | 路径/白名单归一化绕过、弱字符串匹配安全判定 | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/sanitizer-parser-xss.md` | 净化器与浏览器解析差、二次解码/二级渲染 XSS | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/csp-bypass-exfil.md` | CSP 绕过与无脚本数据外带 | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/connection-string-injection.md` | 连接串/驱动/协议处理器参数注入致文件读与 RCE | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/runtime-primitive-override.md` | 同 realm 覆盖原语/内建方法击穿安全控制 | `web2-vuln-classes`, `mobile-pentest` |
| `knowledge/cards/import-migration-trust.md` | 导入/恢复/迁移类功能坍塌信任边界 | `web2-vuln-classes`, `bb-methodology` |
| `knowledge/cards/stale-derived-authz.md` | 授权/凭证派生态未随源变更失效 | `bb-methodology`, `web2-vuln-classes` |
| `knowledge/cards/connection-reuse-key.md` | 连接/缓存复用键遗漏安全维度致降级 | `web2-vuln-classes`, `web2-recon` |
| `knowledge/cards/redirect-header-leak.md` | 跨源重定向敏感头剥离不完整致凭据外泄 | `web2-vuln-classes`, `web2-recon` |
| `knowledge/cards/xs-leak-oracle.md` | XS-Leak / 可观测差异侧信道 oracle | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/cli-argument-injection.md` | CLI 包装器参数/flag 注入与终端转义注入 | `web2-vuln-classes`, `cicd-security` |
| `knowledge/cards/sqli-non-parameterizable.md` | SQLi 非参数化位置（标识符/占位符名/事务） | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/type-confusion-controlflow.md` | 参数类型/形状混淆翻转框架控制流、保留键击穿 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/llm-invisible-unicode.md` | AI/LLM 不可见 Unicode-tag 隐形提示注入 | `web2-vuln-classes`, `bb-methodology` |
| `knowledge/cards/second-order-sink.md` | 二阶/延迟 sink 注入（异步模板/SSTI/反序列化） | `web2-vuln-classes`, `bb-methodology` |
| `knowledge/cards/payment-logic-bypass.md` | 支付/计费业务逻辑绕过（取整/收款方/网关态） | `web2-vuln-classes`, `bb-methodology` |
| `knowledge/cards/postmessage-trust.md` | postMessage origin 校验与内容信任缺陷 | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/render-pipeline-ssrf.md` | 渲染/转换/导出管线作为 SSRF/RCE 攻击面 | `web2-vuln-classes`, `security-arsenal` |

## 深度附录 / Payload Packs

默认不要读取深度附录。只有具体知识卡的 `deep_refs` 命中，且当前 Skill 已经有
明确输入面、baseline 或验证问题时，才按需读取。

| 附录 | 作用 | 何时读取 |
|---|---|---|
| `knowledge/payloads/sqli-low-risk-probes.md` | SQLi 低风险 probe 家族和证据要求 | `sqli-hidden-surfaces` 命中且已有具体输入面与 baseline 时 |
| `knowledge/payloads/command-execution-probes.md` | 命令执行/RCE 低风险 probe 家族和证据要求 | 已有明确 RCE sink 或 primitive，需要最小影响证明时 |
| `knowledge/payloads/controlled-shell-primitives.md` | webshell / reverse shell 受控使用前提、禁止默认化和记录要求 | 低风险 probe 不足，且当前轮明确授权 shell primitive 时 |

## 本地 CTF Web Deep References

`ctf-web` 不默认加载全文。它作为知识卡 `deep_refs` 和
`rules/playbook-router.md` 的深水区参考：只有当前证据已经命中具体输入面、
primitive、parser 差异或验证问题时才读取。读取时提取可迁移的技巧、思路、
payload 家族和链式验证模型，不照搬拿 flag、DoS/ReDoS、持久 webshell、批量
读取或纯 CTF 终局流程。

| CTF Web 参考 | 主要挂载知识卡 |
|---|---|
| `/root/tool/ccst/ctf-skills/ctf-web/sql-injection.md` | `sqli-hidden-surfaces` |
| `/root/tool/ccst/ctf-skills/ctf-web/auth-jwt.md` | `auth-sso-token-edge-cases` |
| `/root/tool/ccst/ctf-skills/ctf-web/auth-infra.md` | `auth-sso-token-edge-cases` |
| `/root/tool/ccst/ctf-skills/ctf-web/server-side*.md` | `xxe-xml-parser`, `path-traversal-file-read`, `ssrf-internal-impact`, `upload-to-execution`, `controlled-rce-impact` |
| `/root/tool/ccst/ctf-skills/ctf-web/server-side-deser.md` | `insecure-deserialization`, `controlled-rce-impact` |
| `/root/tool/ccst/ctf-skills/ctf-web/server-side-exec*.md` | `server-side-template-injection`, `upload-to-execution`, `controlled-rce-impact` |
| `/root/tool/ccst/ctf-skills/ctf-web/client-side.md` | `xss-client-injection`, `browser-client-boundaries` |
| `/root/tool/ccst/ctf-skills/ctf-web/server-side-advanced.md` | `proxy-cache-boundaries` |
| `/root/tool/ccst/ctf-skills/ctf-web/node-and-prototype.md` | `node-prototype-pollution`, `controlled-rce-impact` |

## 深度 Playbooks

默认不要读取 playbook。只有当前 Skill 已经确认高风险 primitive，且需要组织验证、
影响证明、清理和 `/validate` 证据时，才按需读取。

| Playbook | 作用 | 何时读取 |
|---|---|---|
| `knowledge/playbooks/controlled-rce-validation.md` | 受控 RCE / shell / post-exploit impact proof 验证流程 | RCE、上传执行、SSRF-to-RCE、反序列化、SSTI 等需要影响证明时 |

## 加载策略

1. 先读取 `memory/goals/active.json`，确认当前目标、阶段和假设。
2. 根据阶段选择 Skill。
3. 根据证据从本索引选 1-2 张知识卡：核心卡优先，蒸馏卡只在明确 trigger signal 命中时作为 router / recall 补充。
4. 如果蒸馏卡 footer 有 `source_report_ids`，只有在需要真实案例链路或报告写作先例时才查询本地案例库。
5. 如果证据命中 `rules/playbook-router.md`，优先按 router 读取更深参考。
6. 知识卡产出的新思路、技巧或补漏项必须交还给当前 Skill 决策，并回到
   目标层或 action queue 记录为 lead / next action / dead end / queued action。

## 输出要求

使用知识库生成新思路时，必须同时给出：

```text
Evidence: 当前依据
Hypothesis: 安全假设
Technique family: 相关技巧/payload/bypass 家族
Checklist gap: 需要补漏的点
Next action: 最小可验证动作
Stop condition: 放弃条件
Related card: 使用的知识卡或参考文件
```
