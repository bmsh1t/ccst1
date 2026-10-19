---
name: src-hunter
description: SRC hunting and whitebox source audit, from business/code intent and attack-surface questions to evidence-backed validation and reports. Use for requested website/API/app investigation, group or brand discovery, source/0day audit, or scoped CI/CD, contract and token analysis; ordinary implementation work is not a security assessment.
---

# SRC Hunting + Whitebox Audit

理解业务和代码意图，找到信任边界与开发者的认知盲区，而不是把扫描器或漏洞列表当调查。
本入口以 6k 原版 src-hunter（S01）为主体改写，结合 CCST 的竞争解释、条件反证、
专项方法与工程 owner；来源、原件和适配说明见 `knowledge/methods/clown/README.md`。

当前主会话是唯一调查控制器。手工调查与 `/autopilot` 共用此主干；后者只增加继续、
等待、预算和收尾义务，不产生第二套方法或授权。内部模块按问题读取，不注册成独立 Skill，
不需要九次角色切换。方法和知识增强自身判断，没有对应条目也可以探索。

## 理解业务 / 代码意图

先通过 `skills/runtime-protocol.md#shared-memory-continuity` 恢复当前目标、明确意图、
Scope/Auth、未完成 owner、条件经验与真实 handoff。当前事实优先于会话摘要；已持有且
仍有效的工作集可复用。真实锁、claim 和未知执行效果仍须处理，Queue 候选不是路线指令。

从已观察的入口解释：谁以什么身份，对哪个对象，在怎样的租户/状态/业务流中做什么，
系统原本应保护哪条边界。源码沿真实入口、变换、guard 和 sink 追问同一件事。
区分观察与推断；只有证据改变模型时才增量维护 `evidence/<target>/business_model.md`，
保留来源。它是业务背景笔记，不是另一个 Action/Finding/记忆真源，不逐观察重写。

围绕当前缺口提出竞争解释：正常公开行为、会话/缓存差异、配置或版本条件，也可能是真实
边界突破。比较可能影响、预期学习、现有证据、可逆性和成本，选能区分解释的最小实验。
保留正常 baseline；按实际问题比较 actor/object、tenant/state、parser、client/version
或 downstream consumer，不把这些维度当封闭分类或必须逐项完成的表。

## 范围与取材：锁面 / 集团发现

固定 URL、站点、文档或资产清单按 `rules/hunting.md#current-target-context` 锁面；
不能暗扩为全集团测绘。用户的重要资产组、同 host 多 path、业务流子域与同皮差异由该
规则统一解释；同皮不是共同覆盖证明，未测面保留。集团/品牌发现或跨目标续接读
`rules/campaign.md`，即使已经选定了一个 target 也要恢复 seeds 与它自己的当前 owner。
只读/预览不 init、不 set、不写认知；种子、归属线索和实际获准执行目标分开。

取材服务问题，不要求 Recon → Hunt → Validate 顺序：

- 已有请求、源码、schema、浏览器流量或高信号线索可直接调查，不等全量 Recon。
  没有库存、零存活或残余页都不等于整个目标结束，也不授权自动重跑整条管线。
- 有前端时提取真实 path、对象/密文 ID、隐藏路由、会话来源和业务调用关系；无 JS、
  JS 受限或登录页并非终点，可转现有 API、源码、历史证据或已获准的其它业务面。
  不为等 JS 空转，不把第三方 SSO 或同皮登录 HTML 当唯一突破口。
- 获得有效测试会话后，转向对象图、角色/租户/状态差分；回包中的 id/url/token 是
  目标私有线索，列表、附件、导出等关系由证据连接，不自动扩 Scope 或批量复制数据。
- 线索薄弱时可主动做一次有界发现实验；FOFA/被动枚举、Katana、浏览器、source、
  Nuclei/FFUF 是可选取材手段，不是开场义务。显式 `/recon` 才选择现有完整 profile。
  原始语料与 partial/cursor 不丢失；坏 cursor 不从零重跑，先回原 owner 处理。

最小伤害与可解释、可回滚的验证是基础。具体副作用归 `rules/red-lines.md`，
测试行为归 `rules/hunting.md`；不按 HTTP 动词一刀切，不导入原包的默认授权、
永久类别禁测、个人代理或无界续跑。用户登录态保护与真实 cleanup 义务不变。

## 对得上再开：完整方法，而非固定矩阵

先看当前特征暴露哪条边界，再读完整相关方法；短表可用于发现，但不是必读网关、
测试上限或执行顺序。以下名称相对方法根的 `skills/src-hunter/知识库/`，不是本包同级目录。

| 实际特征 / 问题 | 可展开的方法 |
|---|---|
| 用户、对象、角色、租户、认证或恢复入口 | `idor-test.md`、`authbypass-test.md`、`oauth-jwt-test.md` |
| 搜索/筛选、解析差分、语言类型转换 | `injection-test.md`、`type-juggling-test.md` |
| 上传、导入、下载、文件/路径/XML 解析 | `file-upload-test.md`、`path-traversal-lfi-test.md`、`xxe-test.md` |
| URL fetch、预览、网络/服务端回调 | `ssrf-test.md`、`dns-rebinding-test.md` |
| 富文本、前端对象、浏览器信任边界 | `xss-test.md`、`prototype-pollution-test.md`、`csp-bypass-test.md` |
| 支付、优惠、状态转换、并发 | `logic-test.md`、`race-condition-test.md`、`csrf-test.md` |
| 字段/配置泄露、已见服务/组件 | `info-leak-test.md`，按实际 sink 补 `jndi-injection-test.md` / `deserialization-test.md` |
| GraphQL、WebSocket、API 网关 | `graphql-test.md`、`websocket-test.md`、`api-gateway-test.md` |
| 代理解析、Host、CDN/缓存、跨域 | `http-smuggling-test.md`、`http-host-header-test.md`、`cache-poisoning-test.md`、`cors-test.md` |
| 子域/资产归属与接管线索 | `subdomain-takeover-test.md`；先核对 Scope/归属，不因指纹授权执行 |
| AI 对话工具或云 IDE / 编程台的真实执行边界 | `agent-tool-exec-test.md` / `cloud-ide-codex-rce-chain.md`，区分实际工具执行与文本响应 |

WAF 出现于有差分面的实验时再读 `waf-bypass.md`，按当前边界调整编码/位置；不要对
每个 path 喷引号当检测。401/403 先区分业务 API、会话和登录壳，未知保持未知。
Nuclei 适合回答已知组件/暴露面问题；全模板结果不是本站覆盖或技术阴性。
JS 细节见 `js-reverse-guide.md`，资产取材见 `recon-methodology.md`。表外方法同样可读。

### 完整知识库与版本读取

唯一活动方法根为 `knowledge/methods/clown/`：原组织的 49 份知识文件与五份完整
包外依赖保留，不复制第二可写正文。全部条目、guide/index、来源健康与版本通过
`python3 tools/hot_method.py --catalog --json` 或 Context Pack 的 `hot_methods` 发现；
focus 不过滤或排名方法。原 `知识库/README.md` 与 `打穿短表.md` 都是可选导航。

按目录发出的 `read_command`（`--read RELATIVE --expected-manifest HASH --json`）
取得锁内捕获的完整正文及 context，包含前提、顺序、成功证据、反例和停止/重开条件。
目录健康不代表正文已读；版本变化重新取目录，不验 hash 后另开可变路径。
运行于指定 CCST checkout，或显式 `--repo-root`；安装目录不是方法根，也不自动定位仓库。

五份 references 分别承载 `dig-scope-workflow`、`src-value-hunting`、
`researcher-blackbox-whitebox`、`hunt-iter`、`vuln-report-format` 的完整可用资料。
来源参考 SKILL 不安装、不作为第二工作流加载；S52 的 Phase 0 缺损仍明示，不伪造补齐。
`pending_update`、missing、changed、invalid_manifest、origin_only 与 source_incomplete
不混同；显式 `--origin` 只溯源，不能当活动方法。读取不自动 recover/修复，方法不可用
也不抹掉独立 Store 事实或已审冷卡。共享卡及经验读取归
`skills/runtime-protocol.md#shared-knowledge-recall`，Web/API 完整证据方法还可读
`knowledge/playbooks/web2-evidence-contracts.md`，不从孤立 route 行执行。

## 证明与输出

执行前读 `docs/tool-index.md#execution-contract-lookup` 中匹配的现有合同；实际
claim/resolve 还须遵守 State And Queue。保留目标原始输入/输出、时间、身份与真实
operation/attempt/claim 回执。状态码、框架、parser error、scanner hit 单独只是 Lead/Signal。

解释支持与反对证据：`primitive → connector → victim/asset path → demonstrated impact`。
看不到 consumer 不能替它判 kill；做一次有界的 consumer 检查或保留其影响 unknown。
把可证明的 Candidate 交给 [triage-validation](modules/triage-validation.md)，七问与
撤回方法保留；技术裁决、目的地资格和 Action resolution 分属不同 owner。

确认 A 立即保存，证据与目的地条件满足即可写报告，不等可选 B/C、同族或提级实验。
只有缺少必要连接时才用 CHAIN_REQUIRED；缺证据不能靠串接不兼容会话放大影响。
[report-writing](modules/report-writing.md) 从当前 confirmed assessment、完整证据和
独立 eligible destination 写正文，经现有 publisher 保存；不自动提交，不另造生命周期。

## 白盒：源码路径与运行证据分别成立

用户明确要求源码/0day 审计时，可直接从 [whitebox-audit](modules/whitebox-audit.md)
进入，不必先做网络 Recon。Native Read/Grep 沿 entry → transformations → guards → sink，
保留实际 source bytes/SHA、revision、file:line、攻击者控制、前提、调用/数据流和最强反例。
`/source-hunt --source-file PATH` 可保存选定原件，不把 HEAD 当正文版本，不默认执行依赖脚本。
部署版本/配置对应单独核对；源码可达不自动等于运行可利用。动态边、未读区域或部署未知
保持 partial/blocked，纯阅读不造执行回执，也不借缺失 Phase 0 声称完成白盒全流程。

## 内部专项：按当前问题读完整模块

| 当前问题 | 完整模块 |
|---|---|
| host/URL/material、原始语料、focused fuzz 与精确续页 | [web2-recon](modules/web2-recon.md) |
| 源码、JS、依赖路径、guard、部署对应 | [whitebox-audit](modules/whitebox-audit.md) |
| 真实登录/凭据路径的 baseline、来源与准备；review 不等 live spray | [credential-attack](modules/credential-attack.md) |
| Candidate 证明、影响分级、反证/撤回、技术与交付分离 | [triage-validation](modules/triage-validation.md) |
| 已接受结果的正文、可追溯原件、脱敏与发布 | [report-writing](modules/report-writing.md) |
| 明确 in-scope 的 trigger/ref、runner、凭据/制品/部署边界 | [cicd-security](modules/cicd-security.md) |
| 明确 in-scope 的 Android/iOS build、静态/动态/后端差分 | [mobile-pentest](modules/mobile-pentest.md) |
| 明确 in-scope 的合约、chain/source/bytecode、不变量/签名/oracle | [web3-audit](modules/web3-audit.md) |
| 明确 in-scope 的 token/program、authority、LP、Token-2022/holder 影响 | [meme-coin-audit](modules/meme-coin-audit.md) |

这些是阅读导航，不是 Skill catalog、自动选路或九模块流水线。局部方法可组合、可返回
反证或 unknown；全局转向仍由主会话决定。非 HTTP 合约/token 的既有 Store 接入限制不变，
不能编造 HTTP identity。未授权的专项不因代码名、品牌或研究身份自动执行。

## Evidence-Driven Rotation

比较 `hypothesis + surface + actor/state + observation kind + evidence reference`
与上次结果：解释变化、未知减少或 connector 可检验时继续；同质无增量、重复 fingerprint、
owner 预算边界或前提缺失时重新取舍；高信息结构信号可以立即转向。真实 kill condition
才支持条件化否定。时间、低收益、预算结束或 scanner-negative 不能证明覆盖/耗尽。

路径决策或真实 handoff 时保存证据增量（含无增量）、剩余前提与重开条件；同一现场内
的比较留在工作上下文，不逐步另填表。失败只适用于记录条件，新身份/source/version/state/
consumer 可重开。未测和低优先保持 unresolved；临时排除只随本次目标/调用，范围外发现
只是被动 chain context，须先经 Scope owner 才能执行。

## Real Delegation and Execution Handoff

同会话阅读不用委派表、角色切换或虚构回执。真实跨代理/执行边界才交付：

- 输入：目标/Scope 引用、当前事实和证据绑定、问题与竞争解释、缺失条件、允许动作、
  写入边界和 owner 预算。
- 输出：答案与 unknown、原始证据增量、支持/推翻的解释、剩余条件、下一最小区分实验、
  提交 owner 接受的变化；实际执行附真实 attempt/operation/claim，纯分析不造回执。

主会话复核 actor、target、revision、session/state 的兼容性与 Scope/Auth，再通过原领域
owner 接受结果。不为“自己做过”重收证据，不把专家自报当 Finding/Action 已完成。

## Method Maintenance (A) 与连续性

方法维护先用原 reader 完整读取 `references/hunt-iter.md` 及准入引用，由主会话独立核对
实际来源、门槛和三问；专家只提议。通过 `hot_method.py --apply` 的真实 CAS 与
main_session review 发布唯一方法/必要索引，不直接改正文/hash，不借 A 改治理、入口或规则。
共享卡仍走受审晋升，私有原件不进入通用知识；原件可读不等于来源完整或审核已认证。

认知写回沿 `skills/runtime-protocol.md#cognitive-write-timing`：稳定结论、反证、条件
变化和真实交接主动保存；普通只读/无增量不写。暂停、切换、compaction 或结束保留明确
结构化 next_intent、条件与 observation 引用，不用摘要替代恢复绑定。
预算停止新工作，不停止已发执行的证据回收、unknown recovery、cleanup 或终态心跳。
完成声明仍受 `rules/coverage-gate.md` 约束；Scope/Auth、父子 Scope、claim/CAS 和证据
完整性不因方法建议降低。工具保存事实，不替 AI 选择假设或裁决语义。
