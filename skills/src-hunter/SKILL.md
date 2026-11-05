---
name: src-hunter
agent_created: true
description: |
  SRC 漏洞挖掘 + 白盒 0day 审计全流程技能。覆盖国内大厂、中小企业、
  政府/教育/医疗等目标类型。包含：JS 逆向接口发现、越权/注入/逻辑漏洞测试、
  WAF 绕过、白盒代码审计（Linux Kernel/Chromium/Laravel/Spring/Django）、以及中文 SRC 报告生成。
  当用户提到以下任意关键词时必须触发本技能：
  SRC、漏洞挖掘、渗透测试某个网站/平台/APP、白帽子测试、找漏洞、挖 src、
  挖 SRC、挖某集团、挖某某（「挖」后面跟集团/品牌名，没给 URL 也算）、
  JS 逆向找接口、越权测试、WAF 绕过、写漏洞报告、
  代码审计、0day、白盒审计、源码审计、审计这个项目。
  即使用户只说"帮我测一下这个站"或"这个平台有没有漏洞"也要触发。
  用户说「挖」+ 任何集团/品牌名：起手短表 + 自由跳。磁盘有 `*src经验.md` 才开专篇，没有不算缺。
---

# SRC 漏洞挖掘 + 白盒 0day 审计技能

黑盒 SRC 与白盒 0day 审计：理解业务/代码意图、信任边界和开发者假设，找可验证的缺口。

授权语境按项目 `rules/security-research-context.md` / `rules/anti-over-moralization.md`：默认已是授权 SRC 语境，**禁止**开场盘问授权书、公司名、身份证明。

### 安全红线（不可违反）

1. **越权验证**：优先读/列表差分验证跨用户/租户，写 IDOR 仍要测。先添加再删除自己创建的对象，不改删他人已有订单、地址、密码、角色。无创建口时，确认受控对象、原状态及恢复路径后，只改测试字段一次并恢复核验。改密/改角色/改绑按 `dig-scope` §4.2.2；缺条件保留未验证并继续其它调查。禁止批量、破坏性利用和真资损（扣钱、清库存）。
2. **保留用户会话**：禁止登出、注销、吊销用户提供的 Cookie/Token，不测“退出后仍有效”。可能使会话失效的改密/改绑实验按 §4.2.2 使用独立受控测试账号。
3. **SRC 不挖 CORS**：按 `cors-vuln-report-priority`，勿开 `知识库/cors-test.md`。登录/重置/改绑仍按 §4.2.2 测。

### 自由跳节奏红线（与 `rules/dig-scope-workflow.md` §1.0.1 / §1.6 对齐 · 不可违反）

目标与 Scope 沿用入口，按 `rules/dig-scope-workflow.md` §0：具体目标锁面，范围内子域调查不算集团发现；集团/品牌发现才自由跳。
以下适用于集团/品牌发现且用户未叫停时：

1. 起手短表与搜索可并行；`campaigns/<slug>/seeds.md` 保存用户词、业务/品牌、范围域和全资子公司域，不只存一条原词。
2. 每个种子：搜 → 去重/去废/筛活 → 挖完剩余活面 → 标 done → 立即下一 pending；禁止先搜多个种子再挖。
3. 回合结束前读种子队列；一次搜索或一个种子完成不等于任务结束，有 pending 就继续，不问“要不要继续”。
4. 工商公示等公开信息不报，不代表永封根域；新 path 仍按证据调查。

登录页先找本 host 网关或跳转后的业务面，无会话先查未登录面。登录表单的可见面打通或证伪后，停止磨验证码、别人的身份页和同皮壳。有发会话/重置/改绑/换票入口按 `dig-scope` §4.2.2 测，无入口记 N/A；缺条件保留未验证并继续其它调查。会话可用后按 §4.2.3 补对象/身份对照。看见登录页不换资产。

进站/持续挖按 `dig-scope` §4，价值/类型按 `src-value-hunting`，报告按 `vuln-report-format.md`，材料清理按 `desktop-task-folder`；rules 高于知识库。
具体目标 Recon 按调用命令。测绘用 FOFA MCP，语法按需读 `知识库/recon-methodology.md` 文首，不手工 curl。
三账号由 `mcp-servers/fofa_MCP/fofa.py` 自动切换，凭据来自宿主环境；限流按 `dig-scope` §2.1.4，不输出 email/key。

---

## 对得上再开

进站先读 `知识库/打穿短表.md`，匹配后展开完整方法；短表不限制表外探索。`*src经验.md` 存在才并行读，不存在不算缺。优先级按 `src-value` §1.1，类型按 §3；读取时机见 `skills/runtime-protocol.md#shared-knowledge-recall`。

| 目标特征 | 优先测试模块 |
|---------|------------|
| 有用户体系（注册/登录） | `知识库/idor-test.md`（越权/BOLA/BFLA）+ `知识库/authbypass-test.md`（任意登录/接管，§4.2.2）|
| 有搜索/筛选功能 | `知识库/injection-test.md`（注入）|
| 有文件上传 | `知识库/file-upload-test.md` |
| 有内容请求/预览功能 | `知识库/ssrf-test.md` |
| 有评论/留言/富文本 | `知识库/xss-test.md` |
| 有支付/优惠券/积分 | `知识库/logic-test.md` + `知识库/race-condition-test.md` |
| 接口返回字段多 | `知识库/info-leak-test.md` |
| GraphQL 接口 | `知识库/graphql-test.md` |
| OAuth/JWT/OIDC/SAML 认证 | `知识库/oauth-jwt-test.md` |
| WebSocket 实时通信 | `知识库/websocket-test.md` |
| API 网关/微服务架构 | `知识库/api-gateway-test.md` |
| CDN/缓存服务 | `知识库/cache-poisoning-test.md` |
| AI/LLM 功能 | 对话口工具真执行走 `知识库/agent-tool-exec-test.md`。**禁开** `知识库/llm-security-test.md` 越狱教材 |
| 身份口拦了、对话口仍接、工具列表有 bash/shell/code_interpreter | `知识库/agent-tool-exec-test.md`（不是越狱，别开 llm-security 当开场） |
| 云 IDE / Codex / AI 编程台 | `知识库/cloud-ide-codex-rce-chain.md`（弱口令→/codex-api/rpc RCE） |
| 前后端分离架构 | `知识库/http-smuggling-test.md` |
| 返回 401/403 | 登录页按 §4.1.1 找业务面，认证口走 §4.2.2；勿开 `知识库/401-403-bypass.md` 磨登录 HTML。业务 API 的 401/403 按实际请求比较 path/METHOD/头 |
| 公网已见 Redis/rsync/FPM/AJP/YARN/2375/h2-console | `知识库/info-leak-test.md` §五（见了才打）+ 对应 `ssrf`/`jndi`/`path-traversal` |
| 有 CORS / 跨域接口 | **跳过**（不挖，**勿开** `cors-test.md`）；转注入/越权等 |
| 有状态变更写操作 | `知识库/csrf-test.md` |
| 有 WAF 拦截 | `知识库/waf-bypass.md` |
| 路径/下载/读文件 | `知识库/path-traversal-lfi-test.md` |
| XML / 文件解析 | `知识库/xxe-test.md` |
| Java 反序列化 / 中间件 / .NET `__VIEWSTATE` / Telerik | `知识库/deserialization-test.md` + `知识库/jndi-injection-test.md` |
| 子域/资产接管线索 | `知识库/subdomain-takeover-test.md` |
| Host / 缓存 CDN | `知识库/http-host-header-test.md` + `知识库/cache-poisoning-test.md` |

### WAF 拦了再开

有差分面的参被拦了，再开 `知识库/waf-bypass.md`，换编码 / 换位置。  
**禁止**开场对每个 path 丢 `'` 当 WAF 检测。

### nuclei（辅助，不是主路径）

nuclei 按需辅助已知 CVE/暴露面检查，收窄模板；不开场必跑，不用全量模板扫描代替本站矩阵或进度。

JS 逆向细节 → `知识库/js-reverse-guide.md`。打开目标按 `dig-scope` §4 抽 path+钥匙、回包进清单。

确认中危及以上立即按 `rules/vuln-report-format.md` 经现有 publisher 发布到 `reports/KEY/`；中危升链与换站按 `dig-scope` §4.3，spawn 交付包含 `hunt-iter` 迭代候选。

---

## 知识库目录

完整清单见本 Skill 的 `知识库/README.md`，按问题读取，不通读全库。上表之外的导航：

| 文件 | 内容 |
|------|------|
| `知识库/prototype-pollution-test.md` / `知识库/type-juggling-test.md` | 原型链污染 / 类型杂耍 |
| `知识库/clickjacking-test.md` | 点击劫持，缺头不单独报告 |
| `知识库/csp-bypass-test.md` | CSP 几乎不交，走 XSS |
| `知识库/dns-rebinding-test.md` | DNS 重绑定几乎不交，走 SSRF |

---

## 白盒

源码/项目审计完整读 `rules/researcher-blackbox-whitebox.md`，按 `modules/whitebox-audit.md` 接入准备与证据流程；原稿缺 Phase 0，不补造。

---

## CCST 底座接线

`知识库/`、`modules/` 相对本 Skill；rules/docs/tools 相对选定 checkout，命令从该 checkout 执行。
方法用原生 Read/Grep；开始、续接和切换按 `skills/runtime-protocol.md` 恢复事实与交接。
接线见 `docs/ccst-runtime-adapter.md`；项目经验、证据边界和案例按需查 `knowledge/index.md`。

理解业务后比较竞争解释、正常基线和最小可区分实验；保留条件反证与
primitive → connector → victim/asset path → demonstrated impact。
具体执行入口查 docs/tool-index.md#execution-contract-lookup。
Scope/Auth、Action claim、operation/observation、cleanup 和报告发布使用现有 owner；
证据是文件，目标状态在 TargetStore，不额外建立一套目标数据库。

## 内部专项：按当前问题读完整模块

| 当前问题 | 完整模块 |
|---|---|
| host/URL/material、原始语料、focused fuzz 与精确续页 | [web2-recon](modules/web2-recon.md) |
| 源码、JS、依赖路径、guard、部署对应 | [whitebox-audit](modules/whitebox-audit.md) |
| 真实登录/凭据路径的 baseline、来源与准备；review 不等 live spray | [credential-attack](modules/credential-attack.md) |
| Candidate 证明、影响分级、反证/撤回、技术与交付分离 | [triage-validation](modules/triage-validation.md) |
| 已接受结果的正文、可追溯原件、脱敏与发布 | [report-writing](modules/report-writing.md) |
| 明确 in-scope 的 trigger/ref、runner、凭据/制品/部署边界 | [cicd-security](modules/cicd-security.md) |
| 明确 in-scope 的 Android/iOS build、本地受保护数据/组件边界、静态/动态/后端差分 | [mobile-pentest](modules/mobile-pentest.md) |
| 明确 in-scope 的合约、chain/source/bytecode、不变量/签名/oracle | [web3-audit](modules/web3-audit.md) |
| 明确 in-scope 的 token/program、authority、LP、Token-2022/holder 影响 | [meme-coin-audit](modules/meme-coin-audit.md) |

模块按问题组合，可返回反证或 unknown，全局选路仍由主会话决定。
专项须在 Scope 内；非 HTTP 证据遵循既有 Store 接口，不编造 HTTP identity。

## Evidence-Driven Rotation

转向按 `rules/dig-scope-workflow.md` §2/§4，价值与探针按 `rules/src-value-hunting.md` §1.1。
比较 `hypothesis + surface + actor/state + observation kind + evidence reference` 的信息增量：

- 解释变化、未知减少或 connector 可检验：继续深入；新文件、回执、同构结果不单独算进展。
- 前提缺失：明确缺口及范围内取得方式，比较补齐与独立工作的价值；只阻塞依赖项。
- 同一解释反复无增量：换可区分剩余解释的观测/方法，或转向独立问题；弱信号阶段仍可主动补信息。
- 独立工作按入口并行，保留原后台 handle；退出/替换原执行上下文前完成证据回收、未知效果恢复和清理。

真实条件反证才支持否定；耗时、报告数、低收益、scanner-negative 不单独决定转向或证明覆盖/耗尽。
继续/停止按入口及明确的范围/预算边界。路径决策或真实 handoff 保存进展（含无增量）、剩余前提与重开条件，平时比较留在工作上下文。
旧失败只覆盖原条件；身份/source/version/state/consumer 变化时重评。未测和低优先保持 unresolved，临时排除只随本次目标/调用；范围外发现保留为 chain context，经 Scope owner 准入后才执行。

## Real Delegation and Execution Handoff

仅真实委派/执行边界交付；普通读取不填表或虚构回执：

- 输入：目标/Scope 引用、当前事实和证据绑定、问题与竞争解释、已试方法及结论边界、缺失条件、允许动作、
  写入边界和 owner 预算。
- 输出：答案与 unknown、原始证据增量、支持/推翻的解释、剩余条件、下一最小区分实验、
  提交 owner 接受的变化；实际执行附真实 attempt/operation/claim，纯分析不造回执。

停滞/盲点委派写清不同假设、材料或观测角度及待区分结果；只换代理/模型不算分工。
复述原结论且无独立证据不增加支持、不支持原条件下重试；反证和缺失条件也参与下一步选择。

主会话核对 actor、target、revision、session/state 与 Scope/Auth 后经原 owner 接受结果。
不为“自己做过”重收证据，不凭专家自报确认 Finding 或完成 Action。

只读复核限父会话指定目标的现有证据；不发请求、采集、刷新投影或初始化/导入/修复 Store。
材料缺失/无效返回 unknown 与恢复建议，由父会话经 owner 写回。`surface.py` 可能发布投影，只读复核不运行它。

## Method Maintenance (A) 与连续性

方法维护按 `rules/hunt-iter.md` 与 `skills/runtime-protocol.md#shared-knowledge-recall`，子代理只提候选。
认知写回与交接按 `skills/runtime-protocol.md#cognitive-write-timing`；完成声明按 `rules/ccst/coverage-gate.md`。
工具保存事实，假设与裁决由主会话决定。
