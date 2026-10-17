# 6k 完整接入：最终方案审核（2026-10-15）

状态说明：本记录形成于 D1 确认前；用户随后明确回复 `A`。最新维护权限以同任务 `prd.md` 为准，下文保留审核当时的状态和证据。

## 结论与审核边界

**方向可保留，当前工件尚不具备实施条件。** 推荐继续采用“现有架构上的完整接入与最小必要融合”，不回退到只读热方法指针，也不另建控制器、数据库或知识正文库。

本轮交付是静态方案审核，不是产品实现、能力实测或用户批准。D1 方法维护权限仍未选择；推荐 A 不等于已获授权。`task.json:6` 仍为 `planning`。

引用根目录：

- **C**：`/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`，实际实施目标，不是 `ccst2`。
- **A**：`/root/out/clown-src-6k-skill`，用户提供的 6k 源快照。
- **B**：`/root/out/clown-src-skill-二开优化版2.3`，2.3 对照来源。

主代理亲读本任务 PRD、C 架构及核心运行协议、旧规划、A 根规则与迭代规则、B 入口和相关架构合同；三个只读研究代理分别核对源覆盖、现有证据/记忆接口和 2.3 的具体消费者。重要结论回到原文件定点复核，不以代理自报或上游宣传作验收。

## 审核发现

### F01：旧计划不能充当本次实施设计

审核开始时，本任务只有 PRD、task.json 和两个空 JSONL；本轮新增本审核记录，但 `design.md`、`implement.md`、逐项最终处置矩阵仍未完成。复杂任务的实施评审门尚未满足。

旧 `C/.trellis/tasks/10-10-clown-absorption-skill-restructure/research/capability-first-hot-path-plan-2026-10-13.md:9–12,134–145` 以只读热方法和后置晋升为目标，并把若干 2.3 能力概括为已覆盖。本次 PRD 的 R1、R4 要求实际加载完整方法及有效迭代；旧记录只能作历史依据，不能直接继承其“规划完成”或能力等价结论。

**处置建议**：保留原历史文件，当前任务单独形成设计、实施顺序和实际处置矩阵。批准 D1 后仍须完成完整规划评审，不直接进入实现。

### F02：62 项有台账，不等于 62 项语义已接入

只读清单与 SHA256 比较确认：

- A 为 1 个 AGENTS、11 个 rules、50 个 src-hunter 文件，共 62 项。
- C 的 53 个 entries 加 1 个 context，覆盖全部 50 个 src-hunter 文件及 4 篇长规则；54 份拷贝与源字节、登记 hash 一致。
- AGENTS 和其余 7 篇规则仅在 `governance_sources` 登记适配去向；`hot_method.load_manifest()` 不消费该字段。相关位置：`C/knowledge/clown-hot-method-manifest.json:6–19`、`C/tools/hot_method.py:67–90`。

有两类不能靠改链接名称解决的依赖：

1. `A/rules/hunt-iter.md:18,39–41` 把 `vuln-report-format` 的实际正文判定作为方法进入短表的前置条件；它不只是报告排版。将其全部映射成 report-writing，未证明准入逻辑仍存在。
2. `A/rules/src-value-hunting.md:41,47`、`A/skills/src-hunter/SKILL.md:25,35,50,148` 还引用报告、类别策略、目录和宿主规则。须逐项说明保留、适配或不作为运行默认的依据，不能把八条治理注记称为完整融合证明。

**处置建议**：逐源记录完整正文去向、活动入口、引用依赖、适配差异、消费者及验收。源内容保留、运行规则优先级和历史来源不是同一状态；保留来源不要求覆盖用户 AGENTS、Trellis 或宿主配置。

### F03：白盒缺损与附件定位必须分别处理

`A/rules/researcher-blackbox-whitebox.md:1–43` 与浏览器规则全文相同；第 44 行起是残表，第 48 行直接进入 Phase 1。C 拷贝相同，缺损在用户提供的源中已存在，不是本次迁移造成。字节一致不能证明 Phase 0 完整。

本轮未定位到可证明为原始 Phase 0 的完整材料。旧摘要所称“提炼稿”不能当作恢复原文的证据。现有 `C/skills/whitebox-audit/SKILL.md:22–27` 及其问题驱动方法可以作为保留能力的依据，不能冒充 A 的遗失原文。

另一方面，`C/knowledge/methods/clown/README.md:37–39` 的两个附件没有独立文件，但对应内容实际内嵌在 `A/skills/src-hunter/知识库/prototype-pollution-test.md:522` 与 `A/skills/src-hunter/知识库/waf-bypass.md:274`。应修正到章节的定位，而不是宣称这些附件内容全部缺失。

**处置建议**：保留损坏来源与诊断；补充内容标明作者和依据，不称逐字恢复。把缺独立文件、可定位内嵌内容和真正缺损分开，不能伪造已读或已补全状态。

### F04：活动正文更新、路径与原生加载必须同时设计

现有代码有三个约束：

- `C/tools/hot_method.py:29–37,94–101` 禁止 `.`、`..` 及越出根目录。不能把 `bundled_root` 简单设为 `.`，也不能用跨根指针掩盖布局问题。
- `:144–158` 只接受同一个登记 hash；合法修改方法而不更新其活动版本绑定，也会成为 `changed`。外部原始源路径与改写后的活动正文不能天然共用一份 hash。
- 原生同步器读取根级 commands/agents/skills，见 `C/tools/runtime_doctor.py:13–18,103–124`。`knowledge/methods/clown/skills/src-hunter` 不是它的原生 Skill 来源；只移动正文或改 README 不能证明入口可发现。

还存在当前说明与消费者漂移：`hot_method.py:181–184,198` 只有显式 catalog 才展开列表，focus 不筛目录；`C/tools/context_pack.py:876` 未请求 catalog，文本格式化 `:1158–1177` 仍只打印方法列表，不展示 discovery。`C/skills/src-hunting/SKILL.md:91–96` 却仍描述 ready 且 focus 匹配的选中入口。JSON 中有 discovery 不等于所有常用出口已展示它。

**处置建议**：保持唯一调查核心，区分原始来源身份与活动正文版本；更新正文、完整性绑定和消费者必须相容。方法发现、健康诊断和语义选读分别负责，不能恢复固定 top-k，也不能让合法修改永久不可用。具体布局和兼容路径必须写入 design，不能只承诺“可发现”。

### F05：记忆与证据是接线缺口，不是缺第二套 owner

| 问题 | 已有事实 | 必须补足的连接 |
|---|---|---|
| 跨目标种子 | `C/rules/campaign.md:21–29` 已使用 `campaigns/<品牌slug>/seeds.md`，各目标再进入自己的 Store。`TargetStore.create_action` 在 `C/tools/target_store.py:1471–1500` 拒绝异目标 subject。 | 明确恢复时读取哪个 campaign 工作材料、怎样保留其未完成活面并切换目标。未找到工具自动消费 seeds 的链路；不能声称 Action 已完成跨目标恢复，也不需要 campaign 数据库。 |
| 无 Finding 的原生观察 | `TargetStore.start_attempt`、`record_execution` 可无 Action/Finding；`C/tools/probe.py:205–207,303–329` 已有真实调用者。 | `record_native_evidence` 仍强制已有 Finding，见 `C/tools/validation_runner.py:1235–1244,1477–1479`。补已有原件的无 Finding 登记入口，而非占位 Finding、另存证据账本或扩 schema。 |
| 条件经验与交接 | `C/tools/target_store.py:2411–2455`、`C/tools/target_memory.py:488–502` 已接受真实 operation/observation 引用。 | 让新增原生登记返回可直接被这些 owner 消费的引用；保持 note、条件化 negative 和 handoff 的证据含义不同。 |
| 浏览器多步实验 | importer 保存 capture/recon，不等于逐步实验。`C/tools/browser_mcp_import.py:482–507` 的 ok 不校验每步响应完整；已有 summary 会在 `:388–397` 直接返回。 | 明确每步 request/response、时序、subject 和缺失响应；缺失保持 partial。相同导入 identity 返回旧 partial 不等于自动补全。 |
| 登记恢复 | `C/tools/validation_runner.py:1417–1425` 已支持相同材料的稳定登记与 sync 重试。Store 的改变材料重登记还要求 expected_operation，见 `C/tools/target_store.py:1982–1987`。 | 区分相同字节重试与同次执行补充新证据；保留同一 attempt、前序 operation 和原件，不能为了补登记重新执行网络动作。 |

### F06：目标写回时机仍有真实冲突，不能只处理共享晋升

`C/skills/runtime-protocol.md:34–36,42–55` 要求在重要节点主动写回，明确只读/预览除外；`C/rules/retrospective.md:119,231` 却把目标层写回描述为默认只建议、待操作者明确要求。入口不同可能导致本应持久化的交接仅停在答复里，直接影响 R3/A4。

**处置建议**：运行协议继续拥有目标内认知写回时机，复盘引用它，不再重复定义相反默认值。共享卡片发布、治理规则和 Skill 调度修改保持其独立审核边界；D1 只裁决活动方法正文维护，不能顺便放开这些权限。

### F07：专项保留还须消除失联引用，非 HTTP 限制明确后置

- 主代理复核确认 `C/skills/mobile-pentest/SKILL.md:78–79` **仍引用** `api-testing-workflow`，而 `C/knowledge/capabilities.yaml:48–59` 标记其 retired。研究中的“旧引用未证实仍存在”不采纳；这里必须纳入入口兼容修正，不复活已退役知识卡来绕过问题。
- Web3 非 HTTP 原件不能直接进入当前 HTTP(S) observation/Finding 生命周期：`C/tools/target_store.py:1366–1372`；`C/commands/web3-audit.md:49–53` 已承认此限制。保留方法、原件和可用分析入口，不虚构 HTTP endpoint，也不借本任务扩大为 Store schema 改造。
- cleanup、degraded、advisory、reframe、指标与各专项消费者须作为既有增量保护，不以“保留文件名”替代调用链验收。原项目未证明的能力不能算本次退化，也不能被宣传成已接通。

### F08：2.3 适合借鉴合同，不适合按清单整体搬运

B 的结构化表达有参考价值，但运行保证须分级：

- `B/templates/test-matrix.yaml:14–22` 和 `B/references/v22/evidence-schema.json:14–18` 给出基线、受控变量、差异、状态、影响和 cleanup 表达，可与 C 原 owner 对照，不必迁入新账本。
- `B/scripts/validate_adapters.py:18–37` 只检查字段、常量和样例外形；未证明宿主适配的生产—接收链。`B/tests/adapter-cases.json:20` 要求 source_refs/confidence，但 `B/references/v23/handoff-schema.json:5–17` 的封闭 properties 未定义它们。其“已有样例”不能作为可复用运行时已验证的结论。
- `B/scripts/orchestration/report_gate.py:203–262`、`orchestrate_cycle.py:180–213`、`hypothesis_ledger.py:58–83` 依赖 B 的 branch、状态文件和 ledger；不能随证据字段一起复制，否则与 C 的调查控制器和事实 owner 重叠。
- 对 A/B 指定知识目录的只读比较为：A 49、B 48 个 Markdown，32 个同名逐字相同、15 个同名改动，另有改名或不同路径文件。B 的 19 个专家入口是组织增量，不等于 19 项已证明的新能力；旧记录重点保留四条新增短表行及三份手册，不构成完整差分清单。

**处置建议**：分别登记来源/hash、声明版本、段落差分、正文健康、真实消费者、上游审核状态和 C 的处置状态。借鉴专家分层、按需加载、宿主差异和 handoff 表达；不迁入第二 controller、graph/ledger 或重复门禁。新方法是否有实际增量逐项判断，不由上游 active 标签决定。

## 建议确认的方案骨架

1. **调查责任**：保留 `src-hunting` 和主会话作为唯一调查核心；6k 的完整方法、规则关系与节奏接入这个入口，不另装一套竞争的调查控制器。
2. **正文与来源**：唯一活动方法正文，保留来源及历史版本；62 项逐一处置，必要适配明示。既不以摘要替代相关完整方法，也不把“保留原文”误解为覆盖宿主治理或每轮全量加载。
3. **记忆与事实**：现有 Store、Experience、handoff、证据与发布 owner 不换；campaign 工作材料继续独立于单目标 Store。只补真实缺失的调用和恢复连接。
4. **方法维护**：按下节待选 D1 设计；不把方法维护、目标内经验和已审共享知识混成一次写入。
5. **2.3 融合**：保留能改善现有边界的表达、组织和参考方法；每个迁入点绑定现有 owner，不照搬运行时与状态机。
6. **切换**：入口、活动版本绑定、引用、记忆/证据消费者准备完成后成组切换；冲突明确失败。回退只针对本批自有代码/方法版本，不恢复旧目标数据，不覆盖用户改动。
7. **范围**：不安装或同步个人 runtime、不提交、不下载模型、不碰真实目标；本轮仍只规划。后续实现也不顺带改 schema、建 benchmark 或全面重构。

上述是审核建议，不替代尚未完成的 design/implement，也不声明所有来源内容已完成适配。

## A1–A9 的最小验收映射

这些是后续实施计划必须落地的行为场景，**本轮未执行**。临时材料须隔离，不新增项目测试文件或 benchmark 设施。

| PRD 标准 | 最小可观察证据 |
|---|---|
| A1 | 62 项逐一有去向、来源和适配记录；在无 `/root/out` 的隔离布局中仍能展开实际所需正文；已知损坏不冒称完整。 |
| A2 | 从现有手动与自动入口到同一调查核心，能读取相关完整方法及真实附件；无第二控制器，也不把目录输出视作已经读过。 |
| A3 | 原专项入口与必要消费者仍可达，Mobile 退役引用有正确替代；Store/schema/实体 ID 与用户资产未改变。 |
| A4 | 换目标、重启和压缩后，当前 handoff/next_intent 来自正确 owner，campaign 未完成活面仍可读；只读模式无写入。 |
| A5 | 使用临时保存原件登记无 Finding/Action 的观察，再引用到经验/交接；多步顺序与 subject 精确，缺响应为 partial；重试零网络重放。 |
| A6 | 依已选 D1 接受合格增量后，下一次读取获取唯一新正文和有效版本绑定；旧版本、来源、审核身份可追溯；不合格输入不晋升。 |
| A7 | 不重放未知执行；cleanup 需真实回读，报告/交付职责分离；预算停止保留未完成事项，不伪造完成回执。 |
| A8 | 隔离宿主布局可正确发现；混合版本、源缺失、合法修订及并发冲突有不同诊断；回退不改变目标数据。 |
| A9 | 以最小临时材料证明上述接线，不用文件数、静态 schema 校验或起服务替代行为；不声称实战能力或性能提升。 |

## D1：本轮仍待用户选择的维护权限

**推荐 A**：主控先核对真实来源正文，按 6k 门槛与三问决定是否增补唯一活动方法。子代理只能提交拟进/拟补；主控独立复核后再写，不能接受“子代理说通过”作为证据。保持修改前后版本、来源及真实审核身份，合法修订后仍可被下一轮读取。不合格内容不晋升；目标私有事实不进入方法库。

A 不扩大到共享卡片发布、Skill 调度逻辑或治理 Rules 改动；这些继续走既有人工审核。不能伪造人工回执，或把活动方法更新伪装成已审共享知识发布。部署/切换/提交权限也不随 D1 一并授予。

**B**：全部方法改动先做候选，人工确认后生效。它保留更强的人工作业控制，但无法完整保留 6k 的当轮主控迭代节奏。

此处细化 A 的主控/子代理边界，修正原草案容易被读成“所有子代理结果永久等人工”的歧义；未替用户选择 A 或 B。

## 后续门槛与本轮核验

1. 用户明确选择 D1。
2. 在同一任务补齐 design、implement、逐项来源/兼容处置矩阵及两个实际上下文清单。
3. 呈现完整规划摘要，由用户审阅该版本；不能用早先的建任务许可或 D1 选择代替实施许可。
4. 只有其后的明确实施批准才能启动任务；本轮不执行 `task.py start`。

本轮实际检查包括：限定目录清单和 SHA256 比较、任务 JSON/文件存在性检查、fast-context 定位及源码定点阅读、主代理对关键引文和冲突的复核。未运行产品 CLI、测试、构建、浏览器或目标操作；未把静态审核称为行为验证。产品修正仅列入规划，未在本轮执行。

规划工件的 Python 窄检查通过：36 处带根标记的文件/行号引用可解析，R1–R6 与 A1–A9 全部保留，PRD 链接有效，task.json 字节及既有 tracked diff 与审核前一致。最后按差异人工复核新增说明和本记录；该检查不证明上述产品接线已实现。
