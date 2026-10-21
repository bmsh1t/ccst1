# 知识统一：能力对照表（验收基准）

日期：2026-10-21
状态：Step 1 产出，供 Step 3 逐主题归并执行与 Step 4 验收
来源：`git ls-files` 快照 + `knowledge/cards` frontmatter 全量提取 + 6k 知识库 49 文件尺寸/首标题扫描

本表是**验收基准**，不是实施计划。Step 4 的“能力无损”按此表逐行判定：
R 行必须存在等价正文；A 行必须保留；D 行可以消失；X 行必须带明确指路。

---

## 0. 基准事实

| 项 | 数量 | 说明 |
|---|---|---|
| 6k 方法文件 | 49（47 方法 + README + 打穿短表） | 全量正文 578,284 B / 34 份 ≥600B |
| 6k 短桩（<600B） | 14 | 本身就是一行判据，不得当完整方法 |
| CCST 知识卡 | 63 | 63 张 `maturity: draft`，仅 2 张 `tested` |
| capabilities 条目 | 70 | card 63 / payload-pack 3 / workflow 2 / playbook 2 |
| 6k 引用的本仓工具 | 2 | `aspnet_viewstate_knownkey.py`、`telerik_knownkey.py`（本次已接线） |
| 重叠主题对（正文级） | 13 对 | 见 §3 |

**关键结构发现（已修正一次误判）**：6k 方法正文**有大量裸文件名交叉引用**
（`idor-test.md` 39 次、`authbypass-test.md` 27 次、`file-upload-test.md` 15 次、
`xss-test.md`/`ssrf-test.md` 各 8 次、`path-traversal-lfi-test.md`/`info-leak-test.md` 各 7 次）。
初版判断“零交叉引用”是把 `知识库/xxx.md` 带目录前缀的写法当成唯一形式，实际正文用的是
**同目录裸文件名**。影响：

- 迁移后若所有方法仍同处一个目录，裸名引用自动继续解析，**零改写成本**
- 但若有方法被拆到不同目录（如 SSTI 合并、短桩并入 README），裸名引用会断
- `打穿短表.md` 只引用 17 个不同文件名，正文才是引用密集区

因此归并的首要约束是：**`knowledge/methods/` 必须保持扁平单目录**，不得按类别分子目录，
否则 100+ 处裸名引用全部失效。

---

## 1. R 行：6k 方法正文（必须存活，迁移到 `knowledge/methods/`）

判定：这些文件承载完整测法（适用条件/操作/分支/验证/假点）。迁移后正文必须逐节存活。

| 6k 文件 | 字节 | 主题 | 对应 CCST 卡 |
|---|---:|---|---|
| deserialization-test.md | 42,444 | Java/PHP/Python/.NET 反序列化 | insecure-deserialization |
| http-smuggling-test.md | 40,406 | 请求走私 | — |
| idor-test.md | 38,647 | 越权 / BOLA | api-idor, rest-numeric-id-cross-actor |
| cache-poisoning-test.md | 35,654 | 缓存投毒/欺骗 | proxy-cache-boundaries |
| race-condition-test.md | 34,631 | 竞态 | race-conditions |
| prototype-pollution-test.md | 28,574 | 原型链污染 | node-prototype-pollution |
| ghost-bits-cast-test.md | 27,614 | Ghost Bits CAST | — |
| websocket-test.md | 27,367 | WebSocket | websocket-realtime-api |
| path-traversal-lfi-test.md | 26,734 | 路径穿越 / LFI | path-traversal-file-read |
| authbypass-test.md | 27,084 | 认证绕过（含 IM 发签/身份供应商） | auth-access, auth-hidden-switches, auth-sso-token-edge-cases |
| oauth-jwt-test.md | 22,284 | OAuth / JWT / SAML | auth-sso-token-edge-cases |
| csrf-test.md | 20,133 | CSRF（§18 二维码登录） | — |
| waf-bypass.md | 18,741 | WAF 绕过 | — |
| xxe-test.md | 17,691 | XXE | xxe-xml-parser |
| recon-methodology.md | 13,776 | 侦察方法论 + FOFA 语法 | — |
| file-upload-test.md | 12,798 | 文件上传（含 STS/对象 key 通配） | upload-parser, upload-to-execution |
| http-host-header-test.md | 12,155 | Host 头 | proxy-cache-boundaries |
| open-redirect-test.md | 12,036 | 开放重定向 | redirect-header-leak |
| type-juggling-test.md | 11,190 | 类型杂耍 | type-confusion-controlflow |
| xss-test.md | 10,832 | XSS（§8 XSS→RCE、自定义协议） | xss-client-injection |
| info-leak-test.md | 10,049 | 信息泄露（含公网中间件） | information-disclosure-source-config |
| api-gateway-test.md | 9,774 | API 网关 | grpc-api-boundaries |
| graphql-test.md | 9,600 | GraphQL | graphql |
| subdomain-takeover-test.md | 9,827 | 子域接管 | — |
| jndi-injection-test.md | 8,462 | JNDI 注入 | — |
| cloud-ide-codex-rce-chain.md | 7,745 | 云 IDE/Codex RCE 链 | — (CCST 新增, 6k 路径无) |
| el-injection-test.md | 7,415 | EL 注入 | server-side-template-injection |
| ssrf-test.md | 6,942 | SSRF | ssrf-url-fetch, ssrf-internal-impact, render-pipeline-ssrf |
| logic-test.md | 6,341 | 业务逻辑（商家促销绑定） | business-logic-state-machines, payment-callback-idempotency |
| js-reverse-guide.md | 5,204 | JS 逆向 | js-runtime-signature-reconstruction |
| insecure-scm-test.md | 5,197 | SCM 不安全 | import-migration-trust |
| injection-test.md | 4,074 | 注入总览 | sqli-hidden-surfaces, nosql-query-injection |
| ccst-flight-rsc.md | 3,815 | Flight/RSC 对象图恢复 | — (CCST 新增) |
| agent-tool-exec-test.md | 3,048 | 对话口工具真执行 | web-llm-tool-chains |

**6 份大正文无对应 CCST 卡（纯 6k 增量，必须完整承接）**：
http-smuggling、ghost-bits-cast、csrf、waf-bypass、recon-methodology、subdomain-takeover、jndi-injection。

---

## 2. A 行：CCST 独有增量（必须保留，6k 未覆盖）

判定：6k 49 文件无对应正文，且承载真实判断能力。归并时这些保持 `knowledge/cards/` 原样，
作为方法正文的**下游证据门/停止条件**层（方法引用它们，不复制它们）。

| CCST 卡 | load | 增量点（6k 没有的） |
|---|---|---|
| evidence-driven-hunting | low | 证据驱动轮转（比较 fingerprint 与上次结果） |
| hypothesis-reframe | medium | 停滞时的假设重构 |
| coverage-prompts | medium | 覆盖提问（有界注意力窗口） |
| dead-ends | medium | 死路登记与再开条件 |
| surface-unknown-probes | medium | 面未知时的最小探针 |
| view-differential | low | 视图差分 |
| second-order-sink | low | 二阶 sink |
| stale-derived-authz | low | 陈旧派生授权 |
| signature-scope-mismatch | low | 签名作用域错配 |
| connection-reuse-key | low | 连接复用键 |
| connection-string-injection | low | 连接串注入 |
| cli-argument-injection | low | CLI 参数注入 |
| import-migration-trust | low | 导入/迁移信任边界 |
| cloud-cognito-identity-pool | low | Cognito 身份池 |
| cloud-control-plane-pivots | low | 控制面横向 |
| k8s-control-plane-boundaries | low | K8s 控制面 |
| cicd-trust-boundaries | medium | CI/CD 信任边界 |
| public-package-artifact-intelligence | low | 包仓库情报 |
| custom-protocol-state-recovery | low | 自定义协议状态恢复 |
| odata-query-boundaries | low | OData 查询边界 |
| ldap-xpath-query-boundaries | low | LDAP/XPath |
| grpc-api-boundaries | low | gRPC 边界 |
| dns-email-trust-boundaries | medium | DNS/邮件信任边界 |
| cdn-response-differential | medium | CDN 响应差分 |
| browser-client-boundaries | medium | 浏览器客户端边界 |
| xs-leak-oracle | low | XS-Leak |
| web-llm-tool-chains | medium | Web LLM 工具链 |
| wordpress-surface-intelligence | low | WordPress 情报 |
| api-testing-workflow | high | API 测试工作流 |
| rest-basket | low | REST basket |
| controlled-rce-impact | medium | 受控 RCE 影响分级 |
| upload-to-execution | medium | 上传到执行 |
| information-disclosure-source-config | medium | 源码/配置泄露 |
| missing-parameter-discovery | medium | 缺失参数发现 |
| path-pattern-management-exposure | medium | 管理路径模式 |
| path-allowlist-normalization | low | 路径白名单归一化 |
| sqli-hidden-surfaces | high | 隐藏 SQLi 面 |
| render-pipeline-ssrf | low | 渲染管线 SSRF |
| auth-credential-recovery-flows | high | 凭证恢复流程 |
| payment-callback-idempotency | medium | 支付回调幂等 |

判定：上表 40 张为**A 行**（6k 无对应）。剩下 23 张归入 §3 重叠或 R 行已列。

---

## 3. 重叠主题对：归并规则（13 对）

归并规则统一为：**6k 正文为主体并入 `knowledge/methods/`，CCST 卡的增量段补入对应章节，
CCST 卡保留为证据门/停止条件层并由方法正文引用**。重复正文确定唯一维护位置。

| # | 6k 方法 | CCST 卡 | 合并后正文位置 | CCST 增量补入 |
|---|---|---|---|---|
| 1 | graphql-test.md | graphql | methods/graphql-test.md | Quick Recall 触发词 + 双主体只读 node diff 证据门 |
| 2 | deserialization-test.md | insecure-deserialization | methods/deserialization-test.md | ViewState 三阶段判断（格式→完整性→真实消费）；knownkey 工具指针 |
| 3 | idor-test.md | api-idor, rest-numeric-id-cross-actor | methods/idor-test.md | 对象/角色状态机 + actor-pair 对比门 |
| 4 | ssrf-test.md | ssrf-url-fetch, ssrf-internal-impact, render-pipeline-ssrf | methods/ssrf-test.md | **DNS/OAST 证据标准修正**（见 §5）；内部影响分级；渲染管线分支 |
| 5 | path-traversal-lfi-test.md | path-traversal-file-read | methods/path-traversal-lfi-test.md | 白名单归一化反例 |
| 6 | prototype-pollution-test.md | node-prototype-pollution | methods/prototype-pollution-test.md | gadget → RCE 影响链门 |
| 7 | race-condition-test.md | race-conditions | methods/race-condition-test.md | 单包/多包边界与稳定复现条件 |
| 8 | injection-test.md | sqli-hidden-surfaces, nosql-query-injection | methods/injection-test.md | 隐藏面信号 + NoSQL 操作符注入分支 |
| 9 | xss-test.md | xss-client-injection | methods/xss-test.md | 客户端注入边界（DOM/存储/协议） |
| 10 | file-upload-test.md | upload-parser, upload-to-execution | methods/file-upload-test.md | 解析器差异 → 执行路径分级 |
| 11 | authbypass-test.md + oauth-jwt-test.md | auth-access, auth-hidden-switches, auth-sso-token-edge-cases | methods/（两文件保留）| 隐藏 auth 开关 + SSO token 边界；两卡分别引用对应文件 |
| 12 | el-injection-test.md + xslt-injection-test.md | server-side-template-injection | methods/ | SSTI 影响分级 |
| 13 | info-leak-test.md | information-disclosure-source-config | methods/info-leak-test.md | 源码/配置来源验证门 |

**判定依据**：13 对合计覆盖 23 张 CCST 卡。加上 §2 的 40 张，63 张卡全部归类，无遗漏。

---

## 4. D 行：可消失（判定为导航/短桩，无需正文存活）

| 文件 | 字节 | 处置 |
|---|---:|---|
| 401-403-bypass.md | 320 | 短桩，并入 methods 导航或保留为短桩 |
| clickjacking-test.md | 158 | 同上 |
| cors-test.md | 285 | 同上（SRC 禁用声明） |
| crlf-injection-test.md | 208 | 同上 |
| csp-bypass-test.md | 128 | 同上 |
| csv-formula-injection-test.md | 146 | 同上 |
| dangling-markup-test.md | 136 | 同上 |
| dependency-confusion-test.md | 141 | 同上 |
| dns-rebinding-test.md | 110 | 同上 |
| email-header-injection-test.md | 166 | 同上 |
| hpp-test.md | 151 | 同上 |
| http2-attacks-test.md | 120 | 同上 |
| llm-security-test.md | 290 | 同上（禁开声明） |
| xslt-injection-test.md | 157 | 同上（无正文，归 SSTI 分支） |

**14 个短桩合计 2,482 B**。它们的一句话判据有价值（“缺头不写”“不挖勿开”），
但不构成方法正文。处置建议：汇入 `knowledge/methods/README.md` 的“短判据索引”，
正文文件可删——但这要求 Step 4 验证“短表仍能找到该判据”。

---

## 5. X 行：已确认缺陷（Step 2 修正，与迁移解耦）

| 缺陷 | 位置 | 修正要求 |
|---|---|---|
| SSRF 证据标准过强 | `ssrf-test.md:28` “有 DNS 记录 → SSRF 存在” | 改为：DNS 查询可能来自代理/预览机器人/邮件网关/WAF 沙箱；需与同控 OAST marker 关联且区分“应用取回”与“链路上某解析者查了”；**单凭 DNS 记录不构成 SSRF** |
| Telerik/ViewState 导航缺失 | `insecure-deserialization.md` | 补 knownkey 工具指针（`aspnet_viewstate_knownkey.py` / `telerik_knownkey.py`，离线、默认只出指纹、`--reveal-key` 受控） |
| distill/suggest 状态标签 | `tools/distill_*`、`commands/kb.md` | 输出必须区分健康/审核状态，不得把 draft 卡当已审推荐 |

---

## 6. 迁移后必须重新指向的路径（Step 3 清单）

| 位置 | 当前指向 | 迁移后 |
|---|---|---|
| `skills/src-hunter/SKILL.md` 路由表（约 50 行） | `知识库/xxx-test.md` | `knowledge/methods/xxx-test.md` |
| `skills/src-hunter/SKILL.md` 知识库目录表 | 同上 | 同上 |
| `打穿短表.md` 全表（17 个不同文件名引用） | `见 xxx-test.md` | 新路径（或保持裸名，随短表同迁） |
| 方法正文 100+ 处裸文件名交叉引用 | 同目录裸名 | **无需改写**，前提是 methods/ 保持扁平单目录 |
| `commands/autopilot.md` manifest | `skills/src-hunter/知识库/README.md`、`打穿短表.md` | 新路径 |
| `rules/hunt-iter.md` L17 | `skills/src-hunter/知识库/` | `knowledge/methods/` |
| `docs/ccst-runtime-adapter.md` | 来源与历史节 | 更新归档位置 |
| `install.sh` | 递归 skill 包 | 增加 `knowledge/methods/` |
| `knowledge/capabilities.yaml` | 无 method 条目 | 新增 47 条 method 登记（layer=reference, load=on-demand） |
| `tools/knowledge_paths.py` | 已就绪（Codex 未提交改动） | 确认纳入 |

---

## 7. Step 4 验收判据

**工程接通（文件/链接级）**：
1. §1 全部 R 行正文在 `knowledge/methods/` 存在，字节数差异 ≤ 归并增量
2. §2 全部 A 行卡保留，`deep_refs` 可解析
3. §3 全部 13 对合并后，CCST 增量段确实在正文中出现（逐段核对）
4. §6 全部路径引用零悬空（`knowledge_audit` + rg 验证）
5. 短表中每一行的“见 xxx.md”都能解析到新位置
6. **方法正文裸文件名交叉引用全部仍可解析**（随机抽 20 处 `xxx-test.md` 引用，验证目标文件存在于 methods/ 扁平目录）

**能力无损（模型级，不得用文件检查替代）**：
7. 同线索能找到原有方法：取短表 5 行代表性线索（对象存储 STS / 云元数据 SSRF / IM 发签 /
   密文 ID / 分片上传），迁移前后各跑一轮，模型能找到同一方法正文
8. 特殊分支可达：deserialization 的 ViewState 分支、xss 的 §8 自定义协议分支、
   file-upload 的签名覆盖分支
9. 工具入口可达：knownkey 工具从方法正文可被发现
10. 保存/恢复/召回/来源展开/纠错失效链路正常

**当前状态**：步骤 1 完成；步骤 2 未开始；步骤 3 未开始；步骤 4 未开始。
