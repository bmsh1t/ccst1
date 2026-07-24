# 知识库索引

默认只加载本索引。根据当前目标、skill、证据形态和假设，再选择具体知识卡或现有参考资料。

知识库是 Skills 的经验压缩库：负责提供可复用模式、思路分支、技巧家族、
payload 家族、bypass 思维、补充 checklist、反例、误判/死路和思路变形。
它不负责指挥流程。具体执行顺序、工具选择、验证深度和写回位置仍由当前
Skill 与检查层决定。

## Capability Registry（新增经验先登记）

`knowledge/capabilities.yaml` 是知识库治理总控，不是正文知识。
以后新增经验、技巧、bypass、判断门、路由触发或稳定执行能力时，先登记 capability，
再决定落到哪个具体层：

### 质量门

提交新增或修改的知识文档前运行：

```bash
python3 tools/knowledge_audit.py
```

来源解析门分为 `off`、`if-present`、`required`：日常审计默认 `if-present`，缺少可选
本地 corpus 只显示 `skipped`；`required` 仅用于 staging/集成验收，会阻断缺失、失效或
悬空 report 引用。

审计会检查 registry 身份、`kind/layer/load` 契约、active 文档登记、v2 frontmatter、
类型对应的信号/证据/停止/流程 section，以及 `deep_refs`、`related_cards` 和 Markdown
内部链接。`error` 表示加载或引用已经不可信，默认会以非零退出；旧 card 缺少 v2
frontmatter 属于 `warning`，允许渐进迁移。需要把迁移债务也纳入门禁时使用
`python3 tools/knowledge_audit.py --strict`。完整 JSON 报告可用 `--json` 输出。

质量门是显式治理命令和 pytest 回归，不进入每次 `/autopilot` 启动 preflight；运行时仍由
`context_pack` 根据目标证据和 registry 元数据选择有限卡片。

| 能力类型 | 落位 |
|---|---|
| 技巧 / bypass / 经验 | `knowledge/cards/` 或 references |
| 判断标准 | `tools/evidence_rubric.py` |
| 路由触发 | `tools/context_pack.py` |
| 下一步动作 | `tools/checkpoint.py` |
| 稳定执行 | `tools/validation_runner.py` |
| 结果证据 | `tools/evidence_ledger.py` |
| 目标状态 | `tools/target_case_state.py` |
| 跨步骤流程 | Skill / command 文案 |

加载预算默认按 registry 分层执行：

```text
最多 1 张 core card
+ 最多 1 张 reference card
+ 最多 1 个 case-router；若卡片存在可选 `source_refs`，可再按需查询案例
+ 最多 1 个 payload pack 或 playbook（仅验证阶段 gated）
```

降级不是删除：`case-router`、`out-of-target-intel`、`public-metadata` 等低优先级线索
保留 raw artifact 和回捞路径，只是不污染主 finding 队列。

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
| `knowledge/cards/odata-query-boundaries.md` | OData entity/field/navigation/batch 的查询授权与 parser 边界 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/business-logic-state-machines.md` | 业务逻辑、状态机、客户端信任、流程重排和异常输入验证思路 | `bb-methodology`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/api-idor.md` | API 对象级越权和多租户访问控制 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/missing-parameter-discovery.md` | `parameter is null` / 缺参响应驱动的隐藏参数发现与低风险验证 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/path-pattern-management-exposure.md` | 目标目录命名规律、管理/监控面暴露和只读访问记录驱动的二次发现 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/ssrf-url-fetch.md` | URL fetch、webhook、导入转换类 SSRF 思路 | `web2-vuln-classes`, `security-arsenal`, `triage-validation` |
| `knowledge/cards/ssrf-internal-impact.md` | SSRF 内部服务、metadata、控制面影响证明 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/graphql.md` | GraphQL、subscription、global ID 的权限边界 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/sqli-hidden-surfaces.md` | 请求元数据、路由片段、跨接口参数和二阶链路等 SQLi 非显式输入面 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/nosql-query-injection.md` | NoSQL 查询 operator、JSON/parser 和类型混淆注入 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/ldap-xpath-query-boundaries.md` | LDAP filter/DN、XPath context、AD/普通 LDAP 和受控 oracle 边界 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
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
| `knowledge/cards/public-package-artifact-intelligence.md` | 公开包仓库、容器和历史发布物的归属、provenance 与只读静态审查 | `web2-recon`, `cicd-security` |
| `knowledge/cards/js-runtime-signature-reconstruction.md` | 从请求 initiator 和运行时样本重建动态 JS 签名链，并以 first divergence 驱动最小环境补丁 | `web2-recon` |
| `knowledge/cards/custom-protocol-state-recovery.md` | 从 PCAP/log/source 恢复自定义协议 framing、消息字典和可验证状态转换 | `web2-recon` |
| `knowledge/cards/web-llm-tool-chains.md` | Web LLM、prompt injection、RAG 和工具调用边界 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/controlled-rce-impact.md` | RCE / 命令执行 / shell primitive 的受控影响证明 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/node-prototype-pollution.md` | Node/Express 对象污染、template/VM sink 和 RCE 链建模 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/grpc-api-boundaries.md` | gRPC/gRPC-Web transport、method、metadata 与对象授权边界 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/k8s-control-plane-boundaries.md` | Kubernetes API、kubelet、RBAC、service-account 与 subresource 边界 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/race-conditions.md` | 并发状态差异和 race 风险的低风险建模 | `bb-methodology`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/coverage-prompts.md` | 覆盖基线漏测提醒 | `bb-methodology`, `web2-recon`, `web2-vuln-classes` |
| `knowledge/cards/dead-ends.md` | 常见低价值方向和停止条件 | `bb-methodology`, `triage-validation` |

## 按需 Router 知识卡

case-router 不是默认方法论正文，而是低优先级、按信号加载的 router / recall 层：
`trigger signal -> case-router card -> 当前 Skill/证据门`。case-router 与 HackerOne 或任何单一案例库无绑定。
已有一批卡来自 8528 份披露报告蒸馏，继续保留可选 `source_refs`；只有确实需要真实攻击链形状、
报告写作先例或相似案例时才查询本地 gitignored 案例库。其他经人工审核、标准文档、工具行为或
跨目标实战模式形成的卡可以保持 `source_refs: []`。不要默认拉取原文，不把目标域名、payload、
凭证或 PII 写入知识卡。
对已有 corpus-backed 卡也不要默认拉取报告全文，只在当前证据确实需要案例形状时按需读取。

| 知识卡 | 作用 | 推荐关联 Skill |
|---|---|---|
| `knowledge/cards/cloud-cognito-identity-pool.md` | Cognito Identity Pool 公开标识、匿名 STS 身份与实际 IAM action 的逐跳证据门 | `web2-vuln-classes`, `triage-validation`, `security-arsenal` |
| `knowledge/cards/signature-scope-mismatch.md` | 验签字节与消费字节不一致、密钥未绑定身份（XSW/JWT/JWKS） | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/view-differential.md` | 校验视图 vs 执行视图的规范化/编码/截断差 | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/path-allowlist-normalization.md` | 路径/白名单归一化绕过、弱字符串匹配安全判定 | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/connection-string-injection.md` | 连接串/驱动/协议处理器参数注入致文件读与 RCE | `web2-vuln-classes`, `security-arsenal` |
| `knowledge/cards/import-migration-trust.md` | 导入/恢复/迁移类功能坍塌信任边界 | `web2-vuln-classes`, `bb-methodology` |
| `knowledge/cards/stale-derived-authz.md` | 授权/凭证派生态未随源变更失效 | `bb-methodology`, `web2-vuln-classes` |
| `knowledge/cards/connection-reuse-key.md` | 连接/缓存复用键遗漏安全维度致降级 | `web2-vuln-classes`, `web2-recon` |
| `knowledge/cards/redirect-header-leak.md` | 跨源重定向敏感头剥离不完整致凭据外泄 | `web2-vuln-classes`, `web2-recon` |
| `knowledge/cards/xs-leak-oracle.md` | XS-Leak / 可观测差异侧信道 oracle | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/cli-argument-injection.md` | CLI 包装器参数/flag 注入与终端转义注入 | `web2-vuln-classes`, `cicd-security` |
| `knowledge/cards/type-confusion-controlflow.md` | 参数类型/形状混淆翻转框架控制流、保留键击穿 | `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/second-order-sink.md` | 二阶/延迟 sink 注入（异步模板/SSTI/反序列化） | `web2-vuln-classes`, `bb-methodology` |
| `knowledge/cards/render-pipeline-ssrf.md` | 渲染/转换/导出管线作为 SSRF/RCE 攻击面 | `web2-vuln-classes`, `security-arsenal` |

## 已折叠吸收 / 归档的蒸馏笔记

以下蒸馏笔记已不再作为 active router card 加载：

- 已折叠吸收到主卡：
  - `oauth-sso-trust` -> `knowledge/cards/auth-sso-token-edge-cases.md`
  - `payment-logic-bypass` -> `knowledge/cards/business-logic-state-machines.md`
  - `postmessage-trust` -> `knowledge/cards/browser-client-boundaries.md`
  - `request-smuggling` -> `knowledge/cards/proxy-cache-boundaries.md`
  - `csp-bypass-exfil` -> `knowledge/cards/xss-client-injection.md`
  - `sanitizer-parser-xss` -> `knowledge/cards/xss-client-injection.md`
  - `sqli-non-parameterizable` -> `knowledge/cards/sqli-hidden-surfaces.md`
- 已降级为 archive note：
  - `llm-invisible-unicode` -> `knowledge/cards/web-llm-tool-chains.md`
  - `runtime-primitive-override` -> `knowledge/cards/node-prototype-pollution.md`

原始蒸馏笔记保留在 `knowledge/archive/distilled/`，用于复核和追溯，不参与默认路由。

## 深度附录 / Payload Packs

默认不要读取深度附录。只有具体知识卡的 `deep_refs` 命中，且当前 Skill 已经有
明确输入面、baseline 或验证问题时，才按需读取。

| 附录 | 作用 | 何时读取 |
|---|---|---|
| `knowledge/payloads/sqli-low-risk-probes.md` | SQLi 低风险 probe 家族和证据要求 | `sqli-hidden-surfaces` 命中且已有具体输入面与 baseline 时 |
| `knowledge/payloads/command-execution-probes.md` | 命令执行/RCE 低风险 probe 家族和证据要求 | 已有明确 RCE sink 或 primitive，需要最小影响证明时 |
| `knowledge/payloads/controlled-shell-primitives.md` | webshell / reverse shell 受控使用前提、禁止默认化和记录要求 | 低风险 probe 不足，且当前轮明确授权 shell primitive 时 |

## 外部材料蒸馏记录

默认知识加载只依赖项目内已蒸馏卡片、payload pack 和 playbook，不再挂载本机
绝对路径形式的原始外部笔记。外部材料的审计、取舍和未吸收原因保存在
`docs/ctf-web-distillation-audit.md`；该文档只用于人工追溯，不参与默认路由。

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
4. 如果蒸馏卡 frontmatter 有 `source_refs`，只有在需要真实案例链路或报告写作先例时才查询本地案例库。
   查询入口是显式的 `/kb cases`（`tools/case_corpus.py`）；默认只取一个摘要，缺少本地
   `distill/corpus/` 时返回 `unavailable`，不阻断普通路由。
5. 如果证据命中 `rules/playbook-router.md`，优先按 router 读取更深参考。
6. 知识卡产出的新思路、技巧或补漏项必须交还给当前 Skill 决策，并回到
   目标层或 action queue 记录为 lead / next action / dead end / queued action。

正式卡的 active/retired/superseded 状态与 `draft/tested/proven` maturity 分离，由
`knowledge/governance/events.jsonl` 和 `tools/knowledge_lifecycle.py` 追加式 replay；
候选的 pending/reviewed/promoted 状态仍只归 `knowledge_candidates.py` 管理。

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
