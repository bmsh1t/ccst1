# CCST Autopilot 架构评审与推荐方案

状态：历史评审底稿，已获授权并按当前任务实施。范围仅 Claude CLI。
下文保留评审时的证据与设想；当前实现、用户关于 Recon 可并行的修正及验收结论
以 `../design.md`、`host-findings.md` 和生产架构合同为准。

源码：`/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`。
上游：`/root/tool/Agentic-Bug-Hunter`。
本文件及取证页面只保存在临时评审目录，未创建 Trellis 任务。

## 结论

推荐保留 **一个主会话调查循环、一个方法源、既有事实 owner**，补齐 **一个薄的 Claude 原生宿主适配边界**。

Autopilot 负责自动继续，6k 负责调查方法，执行器负责原件与回执，Store/Checkpoint 各自负责原有事实。宿主适配只做入口内容送达、恢复上下文和结束检查；不调用模型、不选择攻击路线、不写另一套目标事实。

这个方向优于继续增加“必须调用 Skill”的文字，也比把整场调查搬入子代理改动更小。入口动态展开正文可以作为送达手段，但独立使用它不能解决压缩恢复、证据漏登记或过早结束。

## 证据与根因

1. `commands/autopilot.md:36` 已有 Claude 动态展开的 Bootstrap。`tools/autopilot_bootstrap.py:876` 初始化单目标 Store，再返回当前状态；它没有执行调查循环。
2. `commands/autopilot.md:68` 和 `skills/runtime-protocol.md:39` 要求主会话调用原生 Skill。`allowed-tools: Skill` 提供调用能力，并不实际调用。当前 `src-hunter/SKILL.md` 没有 fork 或 hook；description 仍是原生发现信息。
3. 合成靶场验收 `/tmp/ccst-autopilot-narrow-live-t0_4pwvz/acceptance.md` 显示：42 个请求都没有完整 src-hunter 正文，41 次工具调用没有 Skill；安装检查通过，Skill 工具可用。存在 3 个 Candidate 和 3 份草稿，但 operation/observation/assessment/正式 report 均为零。模型约 436 秒自行停止，实际 720 秒验收额度未到。
4. `tools/autopilot_gate.py:831` 是只读指引投影。无 owner 工作且不是空目标初始 Recon 时，默认 `next_action=handoff`；`:1149` 再用文字解释 handoff 应继续。这不是机器执行的续跑机制。
5. 现有证据合同已经要求捕获与登记放在同次父会话工具执行中，消费回执后再调查，见 `docs/evidence-runners.md:28`。问题包括未消费合同，不能只归因为底层缺工具。
6. `tools/autopilot_state.py:2157` 的 Closure 判断能阻止无证据的“耗尽”声明，但目前没人保证每次模型准备结束时都会调用它。它也不能替代“是否值得继续”的调查判断。
7. `hooks/hooks.json` 是旧示例；当前安装资产类型只有 commands/agents/skills，见 `tools/runtime_doctor.py:23`、`install.sh:42`。这不构成已接通的 Claude 生命周期钩子。Grok 用户指南不能作为 Claude 实现依据。

根因是三种保证混在了提示词里：正文是否送达、owner 事实是否满足执行/结束条件、模型是否正确运用调查方法。它们需要不同的验证方式。

## 官方宿主能力及限制

本目录保存了官方页面的抓取结果；下述为当前文档，仍须在项目支持的 CLI 版本上复现。

| 能力 | 官方边界 | 方案影响 |
| --- | --- | --- |
| Skill description | 通常进入可用技能列表，完整正文在调用时加载 | 自然发现保留；显式自动化不以模型是否想起 description 为前提 |
| 命令动态展开 | shell 输出在模型收到 Skill 内容前替换占位符；输出不再递归展开 | 复用现有入口，在准入成功后提供原文件正文，不维护复制版 |
| 原生 Skill 生命周期 | 正文跨 turn 保留；相同渲染结果可去重；改变参数或动态输出会重新追加全文 | 稳定方法正文与变化的目标状态分开，不逐动作重新加载全部技能 |
| 压缩 | 当前文档说明每个调用技能最多重附前 5,000 tokens、合计 25,000 tokens | 调用成功一次不能证明压缩后完整；需要明确恢复边界 |
| 子代理 `skills:` | 启动时预加载完整技能；缺失/禁用时可跳过并记警告；通常不继承主会话历史 | 是有效备选，但不能单独解决长调查写回、压缩和主子交接 |
| SessionStart | 支持 resume/compact 等触发并加入上下文 | 用于重新取得当前事实；不能重用旧 Bootstrap 当现状 |
| hook additionalContext | 当前文档规定超过 10,000 字符可能变成文件路径和预览 | 注入成功必须检查完整正文送达，不能只看 hook 退出码 |
| Stop hook | 可阻止本次正常结束并反馈；用户中断不触发；API 错误另有事件；有循环保护 | 适合作为最后一道检查，不应承担无限调度或故障重试 |
| Skill 内 hook | 调用后可持续到 session 结束 | 必须限定活动 Autopilot；不能污染之后的普通对话 |

当前源文件是 17,677 字节、10,143 字符；去除 frontmatter 的正文为 9,657 字符。单纯把整个文件塞进一个 hook 字符串已经超过上述文档阈值；正文自身也接近阈值。字节、字符、token 不可互换。

来源：

- [Skill 调用与发现](https://code.claude.com/docs/en/skills#control-who-invokes-a-skill)
- [动态展开](https://code.claude.com/docs/en/skills#inject-dynamic-context)
- [Skill 生命周期与压缩](https://code.claude.com/docs/en/skills#skill-content-lifecycle)
- [子代理预加载](https://code.claude.com/docs/en/sub-agents#preload-skills-into-subagents)
- [Hook 上下文限制](https://code.claude.com/docs/en/hooks#add-context-for-claude)
- [SessionStart](https://code.claude.com/docs/en/hooks#sessionstart)
- [Stop](https://code.claude.com/docs/en/hooks#stop)

## 职责固定

| 归属 | 应负责 | 不应吸收的职责 |
| --- | --- | --- |
| `/autopilot` 主会话 | 恢复、选择当前问题、执行、继续、在有依据时结束 | 第二份漏洞方法、另一套事实状态 |
| Claude 宿主适配 | 入口展开、会话与目标绑定、恢复正文和当前视图、正常结束前检查 | 模型调用循环、攻击排序、扫描 Shell 语句猜操作、自动登记或裁决 |
| `src-hunter` / 6k 方法与 rules | 业务和技术分析、假设、完整方法、反证、影响判断 | Claude 宿主事件处理和 Store 生命周期 |
| Bootstrap / state / gate | 准入、当前 owner 事实、等待与可执行工作投影 | 实际执行 Skill、漏洞价值排名或认定调查结束 |
| 执行器与登记 owner | 已发执行身份、原件、partial/unknown、真实登记回执 | 将 HTTP 200/工具命中自动确认为漏洞 |
| Store / Checkpoint / Closure | Action、Finding、裁决、发布、经验、review/witness 及证据充分性 | 根据“加载过技能”证明测试质量 |

`runtime-protocol.md` 只保留共享的恢复、问题召回和写回时机；命令入口保留自动化时序。方法、执行合同和事实 schema 均沿用现有 owner。

## 推荐流程

```text
/autopilot 主域名
  → Bootstrap：参数、Scope/Auth、安装一致性、显式初始化/读取
  → Claude 宿主送达：完整 src-hunter 正文 + 简短自动化合同 + 当前状态
  → 恢复尚未结束的执行；存在 phase lock 就等待，不重复启动
  → 新空目标：Recon 完成并返回 → Surface
  → 主会话同时复核业务面、技术面；ranker 按需
  → 选问题 → 缺历史时召回 → 读完整相关方法
  → 实际执行并捕获 → 通过原 owner 登记 → 检查回执
  → Candidate 验证 → 满足条件时发布
  → 刷新当前状态 → 继续选问题
  → 拟结束：检查当前工作与停止依据，保存必要交接
```

已有可用请求、浏览器或源码证据的目标可以直接调查。多个在 Scope 内的子域名是同一主目标的资产视图，不自动变成新的集团种子队列，也不要求每个子域重复 Bootstrap。

报告、Checkpoint、Round settle 和 handoff 都是过程事件。没有待办 owner 只表示模型需要选择下一调查问题。强技术线索可以优先于普通换 ID；不新增固定漏洞遍历顺序。

### 正文送达与恢复

- 自然语言使用仍通过原生 description/Skill，不改 6k 触发文字。
- 显式 `/autopilot` 复用动态展开入口：从选定 checkout 的唯一原文件读取正文，作为独立内容块送达。动态上下文不复制方法、不把 JSON 字段或路径充当正文，也不声称发生了一个没有发生的 Skill 工具调用。
- 方法正文、目标当前状态分开；工作循环不为刷新事实而重复整份方法。
- 送达块同时标明原 Skill 包的绝对根路径，保证正文里的 `知识库/`、`modules/` 相对引用仍可读取；不重写正文链接，也不假装保留未运行的 native frontmatter 效果。
- resume/compact 时通过原生 SessionStart 边界恢复最小自动化合同、完整方法和当前 owner 视图；正在使用的专项方法若已丢失，需要重新展开后再执行。
- 传输必须保全正文。超过宿主限制、路径失效、钩子未触发或内容被降为预览，都算加载未验收，不能静默截断继续声称正常自动化。不得为了满足传输限制先删改 6k 内容。
- 适配只保留会话 ID、此次调用、明确目标/参数、启停范围等必要的宿主绑定；它不是目标进度、Finding、覆盖或记忆的第二真源。跨目标不能沿用全局 active-target 猜测绑定。
- 完成、取消、换会话和用户后续新请求必须有明确的解绑行为；新 `/autopilot` 才创建新的调用绑定。用户打断后不能在下一次普通对话结束时被旧 Stop hook 强行续跑。激活/解除使用宿主事件，不靠解析模型最终文本。
- 钩子作用域、恢复时的重新注册和正文限额是先决宿主实验项；未证实前不把候选钩子模板装入个人环境。

### 执行和写回

- 沿用 `docs/evidence-runners.md:28`：脚本捕获与登记同次执行，浏览器结果立即导入登记；核对 operation/observation 等真实回执后继续。
- 失败时只补登记，不因登记错误重复未知效果的网络请求。Action 与 Round 各自按原有 owner claim/heartbeat，不要求普通 Autopilot 为所有请求新建 Round。
- 验证和发布仍使用现有 owner 证据绑定；草稿不是正式报告。稳定结论、反证和条件变化才写经验，不逐工具调用加工记忆。
- hook 可以发现已登记任务、候选或回执上的未完事项，不能凭空发现所有绕过执行合同的裸 Shell 请求，也不能自动确认漏洞。要保证任意原生网络 I/O 的强制登记，须约束执行通道；本方案不通过 Shell 文本解析假装提供这种保证。

### 停止与继续

在现有 control 投影统一表达三类含义，不新建状态机：

1. 有未结束的执行：等待/恢复原执行。
2. 仍有可推进的问题：继续；owner 列表为空也可进入调查。
3. 有实际结束依据：正常收尾或明确未完成地退出。

其中自由调查分支应使用清晰的继续含义，消除 `next_action=handoff` 同时承担“继续选问题”的歧义；Closure 的历史 handoff 语义保持未完成。调用方一起调整，不另加第二套判定器。

结束依据限于：用户要求、明确 Scope/宿主/用户限制、确实阻止有用工作的障碍，或经当前证据复核后的无值得继续路线。局部账号/组件失败必须保留独立路线。没有默认全程时间、费用或轮数上限；操作超时/限速仍保留。

原生 Stop 适配只读现有 state/Closure/review，检查已知未完执行、待验证或待发布工作及当前结束依据；缺少必要处理时返回一条具体恢复指引。当前 `record_global_review` 只有 status、decision、next_action、证据及残余项，`write_handoff` 也没有机器可读停止依据。推荐在现有 Checkpoint review 内补充本次停止理由和调用绑定（例如 Scope/明确限制、整体阻塞、证据支持的无值得继续路线），沿用其快照及证据校验。宿主直接处理用户取消；不要求用户先让模型提交 review 才能打断。正常完成后解除此次会话绑定。

调查价值仍由模型判断；hook 只核对结构化依据、当前事实和未处理事项，不猜自然语言回复中的“结束”关键词，也不以 unknown 个数强制扫描全部矩阵。结构化的“无值得继续路线”仍是需要证据审查的判断，不能声称机器验证了价值。

“无值得继续路线”与“穷尽攻击面”不同。后者仍必须满足当前 Closure `can_claim_exhausted=true`，而前者须保留未测部分与可重开条件。

必须验证：钩子不拦截用户主动中断，不把普通后续对话重新拉回调查；连续相同事实、相同失败不能无限拦停。无进展时明确以自动化故障/未完成退出，保留原证据，不借故伪造完成或引入全程预算。

## 方案比较

| 选择 | 得到什么 | 仍缺什么 / 代价 | 取舍 |
| --- | --- | --- | --- |
| 继续改 description、重复“必须调用 Skill” | 改动最少 | 已证实会漏调用；不解决后续合同消费 | 不作为修复架构 |
| 仅动态注入完整正文 | 首次内容送达不再依赖一次模型工具选择 | 压缩、登记、结束仍可能失效 | 作为推荐方案中的入口机制 |
| 把整个 Autopilot 改成 fork + agent `skills:` | 原生预加载、独立上下文 | 改变父子事实/写回/工具/等待/恢复边界；仍不保证方法正确使用 | 当前不迁移整场调查 |
| 每工具调用都做语义 gate 或自建控制器 | 可以扩大执行约束 | 开销、解析脆弱、第二套调度/状态；容易再次膨胀 | 不采用 |
| 主会话 + 薄原生宿主适配 + 既有 owners | 同时覆盖送达、恢复和正常结束检查，保留当前深度路线 | 原生生命周期和完整注入须先实测 | 推荐 |

ranker 和其他专项 agent 仍用于独立小问题。Round 留作已有 claim/恢复/显式调度的机制，不能重新成为第二条调查流程；本次不顺带删除公开入口。

## 落地顺序与范围

### 第一步：宿主机制小实验，不改产品

用隔离 Claude CLI 配置和无网络合成任务验证：动态展开正文；Skill/命令 hook 的激活范围；resume/compact 后正文完整性；Stop 的拦停/放行/中断；过长输出与缺失资源明确失败。先确立支持的 CLI 版本和真实行为，再冻结实现细节。

该步骤不挖靶场、不需要扩写 6k、不替换个人 runtime。不能拿“hook 正常退出”替代模型请求实际收到完整正文的证据。

### 第二步：实现一处宿主适配并收敛调用者

- `commands/autopilot.md`：入口、简短循环、明确终止；删重复加载说明。
- `commands/autopilot-round.md`：共享入口适配，保留原 Round 义务。
- `tools/autopilot_bootstrap.py`：保留原有准入和 JSON API；宿主渲染单独消费它。
- `tools/autopilot_gate.py` 与必要 state 消费者：统一继续/等待语义，不另算一次路由。
- 若原生 frontmatter 无法独立承载所需绑定，新增一个小的 Claude 宿主适配模块；不新增模型调用、扫描调度或目标 Store。
- `skills/runtime-protocol.md`、`docs/ccst-runtime-adapter.md`、`docs/architecture-contract.md`：各自只写本层责任。
- `tools/checkpoint.py`、其现有 review 校验和 `commands/checkpoint.md`：增加正常自动结束的结构化理由及本次调用绑定，沿用同一 witness，不新建 stop 数据库/第二份判定规则。旧 review 历史保持可读；它本身不授权另一会话停止。所有调用者和快照绑定必须同步。
- runtime 安装继续复用原有 ownership/drift 流程。若需管理 hook 资产，只接这一条分发路径，不另写个人设置覆盖器。

6k 的 `skills/src-hunter/**`、十一份原 rules 和原始历史材料不在默认改动范围。若传输或方法问题确实要求修改，先给出文件、原因、影响，再询问用户。

### 第三步：固定验收后清理

先通过行为验收，再移除被替代的重复协议和无消费者导航。保留现有 Store、schema、原件、记忆纠错和 Scope/Auth 校验。每批都有可比较的前态；不在同一批顺手改排名、预算、报告格式、知识召回或方法正文。

## 验收标准

机械检查证明接口与宿主送达；真实 CLI 记录证明模型是否消费。两者分开出结论。

| 场景 | 必须观察到的行为 |
| --- | --- |
| 全新主域名 | 完整方法送达；初始 Recon 先返回再开始依赖调查；Surface 后同时复核业务/技术材料 |
| 主域名多子域 | Scope 内资产共用主目标；不误入集团 seeds；不机械逐子域新建生命周期 |
| 原会话/重启续接 | 从当前 owner 恢复未完工作和条件，不重复已执行的未知效果请求 |
| 压缩恢复 | 完整方法与当前事实实际恢复；正文尾部标记可见；专项方法缺失会重读 |
| 证据与持久化 | 真实请求/响应可展开，operation 与证据绑定可核验；登记失败仅重试登记 |
| 验证/报告 | Candidate 经当前裁决与发布 owner；草稿不算报告；报告后出现新的有效调查步骤 |
| 停止 | 未完 owner、空列表、Checkpoint、报告数都不冒充结束；用户中断有效；无默认预算 |
| 故障 | 缺 Skill、注入超限、资源缺失、陈旧绑定、hook 失效均明确；不陷入重复拦停 |
| 方法消费与深度 | 完整方法实际影响实验；反证、角色/条件变化改变下一问题；阴性/未测不混淆 |
| 成本 | 初始/恢复的正文开销可量化；不逐请求注入全文，不固定 ranker，不引入额外主模型控制循环 |

固定 CLI/模型、靶场快照、权限、初始材料与验收外部限额；先做小规模重复验证（建议同一关键场景至少三次），报告每次轨迹和失败，不用一次成功或平均值宣称稳定。外部验收限额只负责控制实验成本，不恢复成产品默认停止条件。

工程通过不等于穷尽漏洞。验收至少展示方法送达、方法使用、证据写回、恢复后继续四条完整链。

## 本轮完成与未验项

已对照当前命令、Bootstrap/gate/Closure、执行登记与安装接线，读取上游入口和 Claude 官方资料，复核既有合成验收结论。未改产品、6k、个人 runtime 或预存 WIP；未运行测试或真实 Claude 复验。

子代理两路独立复核均因模型限流失败，剩余有界核对由主线程完成。正文注入、hook 作用域和压缩后恢复尚无本轮真实 CLI 证明；这三项必须在第一步小实验后才可标为已验证。
