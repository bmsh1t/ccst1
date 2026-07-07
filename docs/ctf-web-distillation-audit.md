# ctf-web 蒸馏审计

日期：2026-07-07

## 结论

审计前，当前项目曾直接引用 `/root/tool/ccst/ctf-skills/ctf-web/*.md` 作为
`deep_refs`。这种方式适合作为临时过渡，但不适合作为长期发布形态。最终方向是
**去默认引用 + AI-gap first 选择性蒸馏**：

```text
ctf-web 原文 -> 现代 AI 可能漏掉的可迁移 delta -> knowledge/cards / payloads / playbooks / rules
```

`ctf-skills` 不再挂载到默认知识卡、Skill 或 router；默认流程只读取项目内已蒸馏知识。本文件只保留审计和人工追溯记录。

## 审计范围

只审计 Web 相关内容：

- `/root/tool/ccst/ctf-skills/ctf-web/*.md`
- `/root/tool/ccst/ctf-skills/ctf-ai-ml/llm-attacks.md`

不纳入默认 Web 实战吸收范围：

- `ctf-pwn/`
- `ctf-reverse/`
- `ctf-crypto/`
- `ctf-forensics/`
- `ctf-malware/`
- `ctf-misc/`
- `ctf-writeup/`
- `solve-challenge/`
- `ctf-web/web3.md`（应归 Web3 专线，而非 Web2 默认知识）

## 审计标准

### 吸收

满足以下条件才吸收进当前项目：

- 不是现代 AI 已普遍掌握的通用原理；必须是模型容易漏顺序、漏边界、漏连接器或漏证据门槛的内容。
- 能迁移到真实授权 Web 测试、PortSwigger/Juice Shop/企业自查，而不是只服务 CTF flag。
- 能表达为触发条件、边界、证据门槛、最小验证和停止条件。
- 能补强现有知识卡或 payload/playbook，而不是创建大而全 skill。
- 不要求默认高风险动作，如破坏性写入、批量枚举、持久 webshell、DoS/ReDoS 或高频 brute force。

### 保留 optional raw ref

满足以下情况只保留为 `deep_refs`：

- 内容很长、案例多、含大量一次性 payload。
- 只有在已确认具体 primitive 后才需要查细节。
- 和当前项目已有知识卡重合度高，但仍可作为边界案例库。

### 排除默认路由

以下内容不进入默认知识或默认路由：

- flag 位置、拿 flag 流程、admin-bot 默认假设。
- DoS/ReDoS、crash/flood、资源消耗型技巧。
- 持久 webshell、reverse shell、真实环境 shell 落地流程。
- 大 payload 字典、爆破、弱口令 brute force 默认化。
- 只为绕某个 CTF 过滤器而存在的一次性字符串。

## AI-gap 过滤器

蒸馏时先问：**这个模式是不是现代模型在没有本地参考时也大概率会想到？** 如果是，就不吸收。

### 不吸收：AI 已强项

- 普通 SQLi/XSS/SSRF/XXE/SSTI/IDOR/JWT 基础分类和常见 payload。
- 常规 `jwt none`、基础 UNION、基础 path traversal、基础 SSRF metadata、常规 DOM XSS。
- 大而全 checklist、payload 字典、工具安装步骤、CTF flag 路径。
- 只改变攻击语法、不改变判断模型或证据门槛的一次性绕过。

### 吸收：AI 可能漏的东西

- **跨边界连接器**：SQLi 读到 auth/MFA/reset/token 字段后如何串到 session/role proof。
- **parser differential**：两个解析器对 URL/path/content-type/archive/template/serializer 的理解不一致。
- **非显式输入面**：EXIF/QR/XML/Header/Host/path segment/sort key/identifier 进入后端查询或执行流。
- **二阶触发顺序**：store step 与 trigger step 分离，普通测试只看第一步会漏。
- **证据门槛**：什么响应差异才算 Signal/Candidate，什么只是 CTF-only 或 dead-end。
- **低影响验证形态**：如何在不 shell、不批量枚举、不破坏状态的情况下证明 primitive。
- **链式升级条件**：一个低危 primitive 何时值得转 SSRF→internal、SQLi→auth、upload→parser、prototype→sink。

### 蒸馏单位

每次只吸收 1 个“判断单元”，而不是整段笔记：

```text
触发条件 -> 为什么 AI 可能漏 -> 最小证据 -> 安全停止条件 -> 应沉淀位置
```

## 文件级分类

| 文件 | 价值 | 建议动作 | 吸收目标 |
|---|---:|---|---|
| `SKILL.md` | 中 | 保留 optional；只吸收 boundary-first 决策形状 | `skills/web2-vuln-classes/SKILL.md` 已基本覆盖 |
| `sql-injection.md` | 高 | 优先蒸馏 | `sqli-hidden-surfaces.md`, `sqli-low-risk-probes.md` |
| `auth-jwt.md` | 高 | 优先蒸馏 | `auth-sso-token-edge-cases.md` |
| `auth-infra.md` | 高 | 优先蒸馏 | `auth-sso-token-edge-cases.md`, `auth-credential-recovery-flows.md`, `browser-client-boundaries.md` |
| `auth-and-access.md` | 高 | 选择性蒸馏；剔除 CTF-only/AI jailbreak 泛化内容 | `auth-access.md`, `api-idor.md`, `path-pattern-management-exposure.md`, `web-llm-tool-chains.md` |
| `auth-and-access-2.md` | 低-中 | 只吸收极少数稀缺边界，如 Unicode/SRP/协议数学 | `auth-sso-token-edge-cases.md`, `type-confusion-controlflow.md` |
| `server-side.md` | 高 | 选择性蒸馏 | `ssrf-internal-impact.md`, `path-traversal-file-read.md`, `server-side-template-injection.md`, `xxe-xml-parser.md` |
| `server-side-2.md` | 高 | 选择性蒸馏 | `xxe-xml-parser.md`, `controlled-rce-impact.md`, `graphql.md`, `upload-to-execution.md` |
| `server-side-advanced.md` | 高 | 优先蒸馏 parser/path/archive 差异 | `path-traversal-file-read.md`, `upload-parser.md`, `ssrf-url-fetch.md` |
| `server-side-advanced-2.md` | 高 | 优先蒸馏 SSRF/internal/parser 差异 | `ssrf-internal-impact.md`, `path-allowlist-normalization.md`, `render-pipeline-ssrf.md` |
| `server-side-advanced-3.md` | 中 | 选择性蒸馏 gopher/SoapClient/parser 差异 | `ssrf-url-fetch.md`, `proxy-cache-boundaries.md`, `upload-parser.md` |
| `server-side-advanced-4.md` | 高 | 优先蒸馏现代 server-side 链 | `render-pipeline-ssrf.md`, `nosql-query-injection.md`, `server-side-template-injection.md`, `xxe-xml-parser.md`, `controlled-rce-impact.md` |
| `server-side-deser.md` | 高 | 蒸馏证据门槛和格式识别；RCE gadget 只 optional | `insecure-deserialization.md`, `controlled-rce-impact.md` |
| `server-side-exec.md` | 高 | 蒸馏低影响 primitive 和 sink 模型；排除直接 shell 流程 | `controlled-rce-impact.md`, `command-execution-probes.md`, `server-side-template-injection.md` |
| `server-side-exec-2.md` | 高但噪声大 | 只吸收 upload/parser/RCE sink 类；排除 shell/DoS/flag | `upload-to-execution.md`, `upload-parser.md`, `controlled-rce-impact.md`, `second-order-sink.md` |
| `node-and-prototype.md` | 高 | 选择性蒸馏 gadget 类和验证模型 | `node-prototype-pollution.md`, `controlled-rce-impact.md` |
| `client-side.md` | 中 | 只吸收 browser boundary；排除 XSS 大 payload/admin-bot 默认 | `browser-client-boundaries.md`, `xss-client-injection.md`, `xs-leak-oracle.md`, `proxy-cache-boundaries.md` |
| `client-side-advanced.md` | 中 | 只吸收 CSP/XSSI/XS-Leak/postMessage/normalization 边界 | `browser-client-boundaries.md`, `xs-leak-oracle.md`, `xss-client-injection.md` |
| `cves.md` | 中 | 不复制 CVE；吸收“版本→可达路径→低风险验证”模型 | `known software intelligence lane`, `information-disclosure-source-config.md` |
| `field-notes.md` | 中 | 保留 optional；只用于补遗漏 checklist，不默认加载 | 多张卡的对照索引 |
| `web3.md` | 低（Web2 视角） | 排除 Web2 默认吸收；交给 Web3 专线 | `web3/`, `agents/web3-auditor.md` |
| `llm-attacks.md` | 中-高 | 选择性蒸馏工具调用/RAG/agent 权限边界 | `web-llm-tool-chains.md`, `ssrf-url-fetch.md`, `information-disclosure-source-config.md` |

## 精选蒸馏主题

### 1. SQLi hidden surfaces

只吸收 AI 可能漏的 delta：

- 二阶 SQLi：注册、profile、偏好、日志、审计、报表、搜索索引等 store → trigger 流。
- 非显式输入：Header、EXIF、QR、XML、DNS/Host、path segment、sort/order/field/identifier。
- Parser/encoding 差异：XML entity、Shift-JIS/Unicode、double keyword、URL 编码、content-type 转换。
- 结果差异证据：字段集合、排序、错误类型、布尔扩展、DBMS 指纹。
- 认证连接器：SQLi 读到 MFA/reset/session/OAuth/token 字段时，转认证链验证。

不吸收：

- 高频逐字符 brute force 默认化。
- CTF-only flag 表、一次性绕过字符串。
- 破坏性 password overwrite 作为默认验证。

### 2. Auth / JWT / OAuth / SAML / MFA

只吸收 AI 可能漏的 delta：

- JWT：不吸收普通 `none`；只吸收 JWK/JKU/KID/key confusion、JWE/key material、kid path traversal 这类容易漏绑定边界的模式。
- OAuth/OIDC：redirect/state/nonce/PKCE/session/client/audience 绑定差异。
- SAML：签名覆盖范围、XPath/digest smuggling、NameID/email/external_id 绑定差异。
- MFA/step-up：tmpToken、challenge token、recovery/setup/remember-device token 与 secret/session 绑定。
- CORS/browser auth：credentialed read、null/trusted origin、preflight 与真实请求差异。

不吸收：

- JWT weak secret brute force 默认化。
- 真实用户登录钓鱼、credential harvesting。
- 只证明 prompt jailbreak、无数据/权限边界影响的 AI 内容。

### 3. SSRF / parser / server-side advanced

只吸收 AI 可能漏的 delta：

- URL parser mismatch：`parse_url` vs curl/fetch、`@`、scheme、unescaped dot、double slash、IPv6/decimal/encoded host。
- Redirect/fetch TOCTOU：校验与实际请求分离、0-TTL、DNS rebinding。
- Internal service chain：Docker/ElasticSearch/MySQL/SMTP/metadata 只作为链式 hypothesis，不默认打高风险动作。
- Render pipeline SSRF：WeasyPrint/CairoSVG/PDF/HTML conversion/image fetch。
- Gopher/CRLF/SoapClient 等协议桥接只在明确授权和低影响证据下使用。

不吸收：

- 默认 gopher payload spray。
- 内网批量扫描。
- 真实云凭据使用或数据修改。

### 4. Upload / parser / archive

只吸收 AI 可能漏的 delta：

- ZIP symlink、zip/png polyglot、wrapper、double extension、MIME/content sniffing。
- 文件名/路径/parser 差异：basename、8.3 short name、unicode homoglyph、double encoding。
- ExifTool/DjVu、image/PDF/parser 只吸收版本/处理链识别和最小证据模型。

不吸收：

- 默认上传 webshell。
- 持久后门或 reverse shell。
- 破坏性文件写入。

### 5. Browser boundary

只吸收 AI 可能漏的 delta：

- DOMPurify/Trusted backend routes、DOM clobbering、MIME mismatch。
- CSPT、XSSI/JSONP、XS-Leak timing、postMessage origin/null origin。
- CSP bypass 作为边界判断，不变成 payload 字典。

不吸收：

- admin bot 默认前提。
- 大 XSS payload 库。
- CSS 大规模 exfil。

### 6. Node / prototype / deserialization / RCE

只吸收 AI 可能漏的 delta：

- Prototype pollution：source → polluted property → gadget → sink 的证据链。
- Deserialization：格式识别、触发证据、side-effect-free probe、OAST gating。
- RCE/SSTI：先证明模板/命令 primitive，再进入低影响 proof；直接 shell 是 gated playbook。

不吸收：

- ysoserial/gadget 大字典默认化。
- shell 稳定化、持久化、横向移动。
- DoS/ReDoS 作为漏洞默认目标。

## 建议落地顺序

### Phase A：移除默认引用，只保留审计追溯

- 项目内 knowledge cards / payloads / playbooks 优先，默认流程不再读取 `ctf-skills`。
- 缺失 `/root/tool/ccst/ctf-skills` 不阻塞 hunting。
- 知识卡、Skill、router 不保留本机绝对路径；本文件只记录审计来源和取舍理由。

### Phase B：先蒸馏 3 个最高 ROI 且 AI-gap 明确的包

1. SQLi hidden surfaces。
2. Auth/JWT/OAuth/MFA/token chain。
3. SSRF/parser/server-side advanced。

每包只改现有卡或 payload，不新增 skill；每次最多吸收 3-5 个判断单元。

### Phase C：再蒸馏 4 个次高 ROI 包

1. Upload/parser/archive。
2. Browser boundary / XS-Leak。
3. Node/prototype/deserialization。
4. RCE/SSTI/command primitive。

### Phase D：更新测试和引用契约

- 测试不再要求固定 `/root/tool/ccst/...` 是唯一正确路径。
- 测试改为验证：
  - 已蒸馏知识存在；
  - optional deep_refs 仍保留；
  - ctf-only 内容未默认路由；
  - 不默认加载全文。

## 审计执行规划

### 优先级评分

每个候选判断单元按 0-2 分打分，满分 10 分；低于 7 分不吸收，继续作为 optional raw ref。

| 维度 | 0 分 | 1 分 | 2 分 |
|---|---|---|---|
| AI-gap | 现代 AI 大概率知道 | AI 知道但容易漏顺序 | AI 容易漏边界/连接器/证据门槛 |
| 迁移性 | CTF-only | 部分真实目标可用 | 多类真实 Web/授权目标可用 |
| 证据门槛 | 只有 payload | 有观察差异 | 有最小证据和停止条件 |
| 低影响性 | 默认高风险 | 可改造成低影响 | 天然低影响或可只读证明 |
| 现有卡缺口 | 已完整覆盖 | 现有卡有但不突出 | 当前知识卡明显缺失 |

硬性否决：

- 需要默认 shell、批量枚举、破坏性写入、DoS/ReDoS。
- 只能服务拿 flag 或一次性 CTF 过滤器。
- 只是常见基础 payload，没有新的判断模型。
- 无法写成“触发条件 -> 最小证据 -> 停止条件”。

### 首批候选判断单元

第一轮只挑 9 个候选，最终最多吸收 3-5 个；其余继续留 raw ref。

| 候选 | 来源 | 可能沉淀位置 | 为什么可能是 AI-gap | 初判 |
|---|---|---|---|---|
| SQLi 非显式输入面：EXIF/QR/XML/Header/Host/path segment 进入查询 | `sql-injection.md` | `sqli-hidden-surfaces.md` | AI 常测 query/body，但容易漏“数据载体先被解析再入库/入查询” | 高 |
| SQLi 二阶 store→trigger：profile/preference/log/report/search index | `sql-injection.md`, `field-notes.md` | `sqli-hidden-surfaces.md`, `second-order-sink.md` | 容易只看第一请求响应，漏后台触发点 | 高 |
| SQLi→认证连接器：MFA/reset/session/OAuth/token 字段驱动后续流程 | `sql-injection.md`, `auth-infra.md` | `sqli-hidden-surfaces.md`, `auth-sso-token-edge-cases.md` | 复杂链路连接器，AI 可能知道点但漏组合 | 已部分吸收，需查缺 |
| JWT/JWK/JKU/KID 不是 token 语法，而是 key-source 绑定边界 | `auth-jwt.md` | `auth-sso-token-edge-cases.md` | AI 常会列 JWT 攻击，但容易漏“key source 是否绑定 issuer/client/session” | 高 |
| OAuth/SAML identity binding：email/NameID/external_id/client/audience/session | `auth-infra.md` | `auth-sso-token-edge-cases.md` | 多字段绑定关系复杂，容易只测 redirect_uri | 高 |
| URL parser differential：validator 与 fetcher 对 `@`、scheme、host、slash、encoding 解析不同 | `server-side-advanced*.md` | `ssrf-url-fetch.md`, `path-allowlist-normalization.md` | AI 知道 SSRF，但容易漏双解析器对照证据 | 高 |
| Render pipeline SSRF/file read：PDF/image/SVG/HTML converter 拉取资源 | `server-side-advanced-4.md` | `render-pipeline-ssrf.md`, `xxe-xml-parser.md` | 现代框架链路隐蔽，需按处理链建模 | 高 |
| Upload/archive parser differential：ZIP symlink/polyglot/wrapper/MIME sniffing | `server-side-advanced.md`, `server-side-exec-2.md` | `upload-parser.md`, `upload-to-execution.md` | AI 可能知道上传绕过，但漏“解压/解析器/访问路径”分层证据 | 中-高 |
| Browser boundary：CSPT/XSSI/XS-Leak/postMessage/null origin | `client-side*.md` | `browser-client-boundaries.md`, `xs-leak-oracle.md` | AI 容易只想 XSS payload，漏浏览器边界和数据通道 | 中 |

### 首轮不做

- 不新建 Skill。
- 不改工具，不新增 resolver，不自动读取 `ctf-skills`。
- 不吸收 `ctf-web/SKILL.md` 的 Quick Start 命令和工具安装。
- 不吸收 XSS payload 大集合、admin-bot 默认前提、flag 位置。
- 不吸收 Web3 内容到 Web2 默认知识。

### 每个判断单元的审计模板

审计时必须按以下模板落地，缺一项不吸收：

```text
候选名称:
来源文件/标题:
AI-gap 说明:
真实目标触发条件:
最小安全证据:
停止/降级条件:
应沉淀位置:
是否需要 context_pack 路由:
是否需要测试:
是否保留 deep_ref:
```

### 吸收后的验收标准

每轮吸收必须同时满足：

- 只改现有知识卡、payload 或 playbook；除非连续多目标证明需要，否则不新增 Skill。
- 每张卡新增内容不超过一个小节或 5-8 条 bullet，避免知识卡膨胀。
- 新内容必须包含停止条件，不能只给攻击技巧。
- 如果新增路由触发，必须有 `tests/test_context_pack.py` 回归。
- 如果只补知识卡，至少跑：

```bash
python3 -m pytest tests/test_knowledge_governance.py tests/test_context_pack.py -q
```

### 当前建议的下一步

先不吸收 9 个候选。下一步只做第一轮细审，并且必须先做现有覆盖对照：

```text
审计 sql-injection.md 中 3 个候选：
1. 非显式输入面
2. 二阶 store→trigger
3. SQLi→认证连接器
```

输出仍然先写审计结果，不直接改知识卡。只有确认现有 `sqli-hidden-surfaces.md`、
`second-order-sink.md`、`auth-sso-token-edge-cases.md`、`sqli-low-risk-probes.md`
或 `context_pack.py` 没有覆盖，且满足 AI-gap 评分后，再做最小吸收。

## SQLi 三候选现有覆盖初审

本轮已对当前项目做只读对照，结论是：这 3 个 SQLi 候选大多已经被当前知识库吸收，短期不应重复写入。

| 候选 | 当前覆盖 | 初审结论 | 下一步 |
|---|---|---|---|
| 非显式输入面 | `sqli-hidden-surfaces.md` 已覆盖请求元数据、path/routing segment、cookie/session、JS/source/browser 参数、导入/上传字段、日志/审计/风控/报表链路；`sqli-low-risk-probes.md` 已覆盖 header/path/cookie/hidden param/二阶 store step；`context_pack.py` 已能按 `sqli/hidden-param/X-Forwarded-For/path-segment` 路由到本卡 | 已覆盖强；不要重复吸收 | 仅观察 EXIF/QR 是否需要更显式地从 deep_ref 提升到候选形态；没有实战失败前不改 |
| 二阶 store→trigger | `sqli-hidden-surfaces.md` 已多处要求记录 store step 和 trigger step，并覆盖日志、审计、风控、统计、报表、搜索索引、导入预览；`sqli-low-risk-probes.md` 已有“二阶最小触发”；`second-order-sink.md` 也覆盖通用延迟 sink | SQLi 侧已覆盖；通用二阶卡偏 SSTI/deser，但不构成当前缺口 | 不吸收。只有真实压测发现 AI 仍漏 store→trigger 顺序时，再补一句跨卡连接 |
| SQLi→认证连接器 | `sqli-hidden-surfaces.md` 已覆盖 MFA/TOTP secret、reset/recovery token、API key、session seed、OAuth/link secret、step-up/challenge token；`auth-sso-token-edge-cases.md` 已覆盖外部可读 secret + 中间 token 完成 MFA/step-up/session；`context_pack.py` 已有 auth/token/MFA 路由和 SQLi 卡提示 | 已覆盖强；这是最近 Juice Shop 链路后已经沉淀的内容 | 不吸收。后续只验证是否需要补测试覆盖，而不是补知识 |

### SQLi 第一轮结论

```text
不新增知识卡
不新增 Skill
不改工具
不重复吸收 SQLi 三候选
```

仅保留一个观察项：

```text
EXIF/QR/XML 这类“文件/结构化载体进入 SQL 查询”的例子目前在 deep_ref 描述中出现，
主卡已有“导入/上传字段、上传 metadata、XML entity、parser/content-type 差异”。
除非后续实战证明 AI 漏掉 EXIF/QR 这种载体，否则不提升为主卡显式 bullet。
```

## 全仓库 ctf-skills 二次审核

本轮按“低价值直接丢弃，只保留高价值”的口径复审整个 `/root/tool/ccst/ctf-skills`，不再逐项整理 CTF 笔记库。结论是：默认引用范围应继续收敛在 Web 相关内容，非 Web 目录只有极少数条件型连接器值得保留为观察项。

### 高价值但已由当前项目覆盖

这些内容确实有价值，但已经进入当前知识卡 / payload / playbook 体系，不需要重复吸收：

| 来源 | 有价值的部分 | 当前覆盖 | 动作 |
|---|---|---|---|
| `ctf-web/sql-injection.md` | 非显式输入面、二阶触发、SQLi→认证连接器 | `sqli-hidden-surfaces.md`, `sqli-low-risk-probes.md`, `auth-sso-token-edge-cases.md` | 保留 deep_ref，不重复写 |
| `ctf-web/auth-jwt.md`, `auth-infra.md` | JWK/JKU/KID key-source、OAuth/OIDC/SAML 身份绑定、MFA/step-up 中间 token | `auth-sso-token-edge-cases.md`, `auth-credential-recovery-flows.md` | 保留 deep_ref，不重复写 |
| `ctf-web/server-side-advanced*.md` | URL parser differential、filter-then-fetch、render/PDF/SVG 管线 SSRF | `ssrf-url-fetch.md`, `ssrf-internal-impact.md`, `path-allowlist-normalization.md`, `render-pipeline-ssrf.md` | 保留 deep_ref，不重复写 |
| `ctf-web/server-side-exec*.md`, `server-side-deser.md` | 先证明 primitive，再做受控 RCE/反序列化影响证明 | `controlled-rce-impact.md`, `command-execution-probes.md`, `controlled-rce-validation.md`, `insecure-deserialization.md` | 保留 deep_ref，不重复写 |
| `ctf-web/server-side-advanced.md`, `server-side-exec-2.md` | 上传/压缩包/文件名/metadata/parser 差异 | `upload-parser.md`, `upload-to-execution.md` | 保留 deep_ref，不重复写 |
| `ctf-web/client-side*.md` | postMessage、XS-Leak、XSSI、CSP/浏览器边界 | `browser-client-boundaries.md`, `xs-leak-oracle.md`, `xss-client-injection.md` | 保留 deep_ref，不重复写 |
| `ctf-web/node-and-prototype.md` | prototype pollution 的 source→property→gadget→sink 证据链 | `node-prototype-pollution.md`, `controlled-rce-impact.md` | 保留 deep_ref，不重复写 |
| `ctf-ai-ml/llm-attacks.md` | RAG/agent/tool-use 权限边界、间接注入、不可见 Unicode | `web-llm-tool-chains.md` | 只作为 Web LLM deep_ref，不吸收 jailbreak/prompt 字典 |

### 唯一值得保留的新观察项

| 来源 | 候选判断单元 | 为什么值得保留 | 当前状态 | 后续触发条件 |
|---|---|---|---|---|
| `ctf-crypto/prng.md`, `ctf-crypto/prng-attacks.md` | Web token / reset / OTP / UUID / session 的弱 PRNG 连接器 | AI 常知道“随机数弱”，但容易漏“一个端点泄露 PRNG 输出会污染 reset token、签名 nonce、邀请码或会话 ID”的跨流程连接 | 当前 auth 卡覆盖 token 绑定，但没有显式 PRNG/entropy 判断；暂不吸收，避免把 crypto CTF 搬进 Web 默认流 | 真实目标出现可观察连续 token/OTP/UUID、时间种子、共享 `random` 输出、可预测 reset/invite/magic-link 或签名 nonce 时，再最小补 `auth-sso-token-edge-cases.md` / `auth-credential-recovery-flows.md` |

这个观察项也不该现在新建 Skill。它如果被后续实战证明需要，最多补一个小节：

```text
触发条件 -> 可观察输出样本 -> 低频预测/重复性证据 -> 是否能影响 reset/session/OTP/signature -> 停止条件
```

### 默认丢弃策略

本轮不再维护低价值清单。以下内容直接不进默认 Web hunting，不进 context_pack，不进 Skill：

- CTF flag、writeup、solve-challenge、比赛平台导航。
- pwn/reverse/malware/forensics/crypto 算法题、stego、地理 OSINT、社媒 OSINT。
- shell 稳定化、持久化、提权、横向移动、真实环境 post-exploitation。
- jailbreak/prompt payload 字典、XSS payload 字典、一次性过滤器绕过。
- DNS maze、NSEC/IXFR 找 flag、跨题容器 IP 复用、CAPTCHA 字形题等 CTF-only 技巧。

### 二次审核结论

```text
立即吸收：0
新增 Skill：0
新增工具：0
默认 deep_ref：无本机 ctf-skills 路径
新增观察项：弱 PRNG → Web token/session/reset 连接器
```

当前项目的方向应固定为：不把 `ctf-skills` 作为默认 raw reference，项目默认流程依赖已蒸馏知识卡。后续只在真实压测证明 AI 漏掉“连接器 / 顺序 / 证据门槛”时，再做最小吸收。

## 最终建议

不要继续维持“知识卡直接指向巨大 CTF 原文”的长期形态。应该逐步把高价值模式吸收到当前项目的四层记忆系统：

```text
经验技巧 -> knowledge/cards
低风险 probe -> knowledge/payloads
完整验证组织 -> knowledge/playbooks
证据门槛 -> rules / evidence rubric
路由触发 -> context_pack
```

`ctf-skills` 不进入默认运行时；默认 hunting 只依赖已蒸馏知识。需要追溯来源时只查本审计文档，不把原文重新挂回知识卡。
