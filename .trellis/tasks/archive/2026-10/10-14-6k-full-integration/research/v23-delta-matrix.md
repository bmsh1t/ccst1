# 2.3 逐项差分与处置矩阵

比较根：A=`/root/out/clown-src-6k-skill`；B=`/root/out/clown-src-skill-二开优化版2.3`。这是一份静态内容/结构差分，不是效果审核、实时宿主测试或来源许可认证。

## 知识库文件总体

A 为 49 个 Markdown（含 README、短表），B 为 48 个 Markdown。32 个同名文件字节一致；15 个同名差分文件逐项列出；A 独有 `path-traversal-lfi-test.md` 与短表，B 将短表改名为 `shortlist.md`。改名不是能力增量。

| 文件 | 差异锚点 | 已核验差分 | C 处置 |
|---|---|---|---|
| `README.md` | A/B行1,3,7,13,15,21,32–70 | 机械替换：路径与名称标签；索引名称改写未作语义校验 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `authbypass-test.md` | A/B行1,193,195 | 机械替换但损坏词汇，出现“音media”“群records” | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `cache-poisoning-test.md` | A/B行3,5 | 规则路径和知识库名称机械替换 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `cors-test.md` | A/B行1 | 标题机械替换；SRC禁用声明仍在 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `file-upload-test.md` | A/B行1 | 规则路径替换，无步骤差异 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `graphql-test.md` | A/B行3,5,474,476 | 规则链接、章节名称与文件名标签替换 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `http-smuggling-test.md` | A/B行5 | 知识库名称替换，无步骤差异 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `idor-test.md` | A/B行158,266,337–345,427,431,526,530,536,552 | 词汇替换把资料、内部知识库等识别用语改坏；反例仍在 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `info-leak-test.md` | A/B行1 | 规则路径替换，无步骤差异 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `logic-test.md` | A/B行1,6 | 规则路径和知识库名称替换 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `oauth-jwt-test.md` | A/B行462,464,753,755 | 两个不同补充来源标签合并成同一个文件标签 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `race-condition-test.md` | A/B行5,1069 | 末尾关联标签和知识库名替换 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `ssrf-test.md` | A/B行3 | 知识库名称替换，无步骤差异 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `websocket-test.md` | A/B行5,639 | 路由链接 api-sec 改 api-security，未验证目标存在 | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |
| `xss-test.md` | A/B行4,25 | 词汇机械替换造成“个人records” | keep A as complete preserved baseline; do not import B rewrite; repair only consumer links required by C |

32 个同名逐字相同文件（保留 A，不产生 B 新能力）：

`401-403-bypass.md`, `agent-tool-exec-test.md`, `api-gateway-test.md`, `clickjacking-test.md`, `cloud-ide-codex-rce-chain.md`, `crlf-injection-test.md`, `csp-bypass-test.md`, `csrf-test.md`, `csv-formula-injection-test.md`, `dangling-markup-test.md`, `dependency-confusion-test.md`, `deserialization-test.md`, `dns-rebinding-test.md`, `el-injection-test.md`, `email-header-injection-test.md`, `ghost-bits-cast-test.md`, `hpp-test.md`, `http-host-header-test.md`, `http2-attacks-test.md`, `injection-test.md`, `insecure-scm-test.md`, `jndi-injection-test.md`, `js-reverse-guide.md`, `llm-security-test.md`, `open-redirect-test.md`, `prototype-pollution-test.md`, `recon-methodology.md`, `subdomain-takeover-test.md`, `type-juggling-test.md`, `waf-bypass.md`, `xslt-injection-test.md`, `xxe-test.md`

同名文件 hash 和精确 B 文件路径见本目录 `v23-delta-inventory.json`。

## 短表和 B lane 的新增方法候选

A `打穿短表.md` 与 B 知识目录 `shortlist.md` 均为 94 文本行、87 场景行，三类替换后内容相同。
B lane 版本为 98 文本行、91 场景行：第 3–4 行还将维护依据改为 `../SKILL.md §5` +
`../anti-idle-gates.md`、入口改为 `../site-entry-playbook.md`。这些是治理/路由重定向，
不是已验证的新调查能力，不导入 C。第 95–98 行另增 4 个场景：

| B 来源 | 场景 | 对应正文 | 已知状态 | C 处置 |
|---|---|---|---|---|
| `/root/out/clown-src-skill-二开优化版2.3/skills/specialized/src-hunt-lane/references/kill-chains/shortlist.md:L95` | 老高校 IIS/WCF 教务身份票据与业务接口场景 | 无单独对应手册 | substantive added shortlist scenario; no linked manual located; efficacy/source claim not checked | defer; do not include in A-complete cutover |
| `/root/out/clown-src-skill-二开优化版2.3/skills/specialized/src-hunt-lane/references/kill-chains/shortlist.md:L96` | RuoYi 配置读取场景 | ruoyi-getconfig-unauth.md (54行) | substantive added scenario; see ruoyi manual; efficacy/source claim not checked | defer; later A-gate review |
| `/root/out/clown-src-skill-二开优化版2.3/skills/specialized/src-hunt-lane/references/kill-chains/shortlist.md:L97` | WAF/MSSQL blind-injection scenario | waf-bypass-mssql-blind.md (45行) | substantive added scenario; see waf manual; efficacy/source claim not checked | defer; later A-gate review |
| `/root/out/clown-src-skill-二开优化版2.3/skills/specialized/src-hunt-lane/references/kill-chains/shortlist.md:L98` | ASP.NET ashx/DTcms combo | ashx-unauth-combo.md (39行) | substantive added scenario; see ashx manual; efficacy/source claim not checked | defer; later A-gate review |

三份新增手册和短表行只完成存在性、来源声明及章节位置登记，效果、可复现性和报告准入尚未核验；当前不得写入活动 A 短表。此延后不改变 6k 的 62 项承诺范围。

## 19 个专家入口声明

B `references/experts/` 有 19 个 `SKILL.md` 专家声明。只看了入口元数据，未逐篇对照正文、consumer、宿主分发和实际效果；因此是研究候选，不可计成 19 项已证实能力，也不作为第二技能路由系统。完整路径/hash 见 JSON。

| 专家目录 | C 可对照入口/材料（非能力等价证明） | 处置 |
|---|---|---|
| `agent-security` | `skills/src-hunting/SKILL.md`；独立 agent 专项覆盖未核对 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `ai-identity-security` | `skills/credential-attack/SKILL.md`；AI identity 等价覆盖未核对 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `api-auth-and-jwt-abuse` | 现有 auth-sso-token 方法与执行 owner | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `api-authorization-and-bola` | target Store evidence + IDOR 方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `api-recon-and-docs` | web2-recon 与完整方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `deserialization-insecure` | 反序列化完整方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `file-upload-methodology` | 上传方法与原生执行 owner | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `graphql-methodology` | GraphQL 完整方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `idor-broken-object-authorization` | IDOR 方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `mcp-security` | 未核对独立 C 专项 owner，不宣称已覆盖 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `oauth-sso-attack` | OAuth/JWT 方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `prompt-injection` | 未核对独立 C 专项 owner，不宣称已覆盖 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `race-condition` | 竞态方法与真实执行 owner | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `recon-and-methodology` | web2-recon / src-hunting | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `request-smuggling` | smuggling 方法与执行 owner | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `security-testing-methodology` | 唯一 src-hunting 全局 owner，不建第二核心 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `ssrf-methodology` | SSRF 完整方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `websocket-security` | WebSocket 完整方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |
| `xss-methodology` | XSS 完整方法 | do not create parallel specialist Skill; use as deferred research input, compare against C existing owner and A before any admission |

## 适配与架构资产

| B 资产 | 已知证据 | C 处置 |
|---|---|---|
| `/root/out/clown-src-skill-二开优化版2.3/scripts/validate_adapters.py` | checks field shapes/constants/examples, not working producer-consumer host handoff | borrow envelope vocabulary only; C owner must prove real consumer |
| `/root/out/clown-src-skill-二开优化版2.3/references/v23/handoff-schema.json` | additionalProperties=false schema omits source_refs/confidence used in adapter sample | do not import as runtime contract; reconcile against real C fields if later needed |
| `/root/out/clown-src-skill-二开优化版2.3/tests/adapter-cases.json` | sample claims required source_refs/confidence absent from schema | diagnostic evidence only |
| `/root/out/clown-src-skill-二开优化版2.3/skills/specialized/src-hunt-lane/references/kill-chains/README.md` | two kill-chain links contain control characters; shortlist says ../SKILL.md though correct path is ../../SKILL.md | do not copy malformed index |
| `/root/out/clown-src-skill-二开优化版2.3/skills/specialized/src-hunt-lane/references/kill-chains/shortlist.md` | A 为 94 文本行/87 场景；B lane 为 98 文本行/91 场景；第 3–4 行另改写维护依据及入口 | 保留 A；不导入 B 治理/路由重定向；延后 4 个新增场景 |

## 跨源能力处置

最终能力与 owner 处置只维护于 [跨源能力矩阵](capability-disposition-matrix.md)，不在本文件重复另一份结论。
