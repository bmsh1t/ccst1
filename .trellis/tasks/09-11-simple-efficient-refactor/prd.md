# 简单高效：使用面减负 + 结构重组

## Goal

**验收标准就是四个字：简单高效。**

日常狩猎一次假设的心智成本降到 vuln_memory 级（一条 probe + 四个判断字段 + 一句话 resolve），
但底下保留全部机器保证（证据链、防重、红线、coverage 回写、checkpoint 写回、closure 可核对）。

```
现在：  add(17参数) → 手拼16字段claim → 手拼spec跑runner
        → 手拼metadata resolve → checkpoint回忆字段名
目标：  probe(一条命令,自动落账)
        → claim --template idor --from-evidence <id>   (写4个判断字段)
        → resolve 一句话
        → 机器自动完成其余一切簿记
```

## 设计原则

- **加壳不拆墙**：owner、闸门、ledger、closure 语义全部不动；只改 AI 交互面（阶段一）
  和代码摆放（阶段二）
- **AI 只写判断**：机械字段（endpoint/method/evidence_ref/baseline_ref/类别稳定字段）
  全部机器推导或模板预填；AI 的输入收敛到临场判断四件套
  （hypothesis_id / expected_learning / kill_condition / decision_reason）
- **每批全量测试绿**：当前基线 1870 passed，逐批只增不减
- **风险递增排序**：先做零语义改动的体感层，再做纯搬动的结构层

## 阶段零：删死重 + 拆过度设计 + 文档减负（2 天）

### 零-0：文档减负（实测驱动的 -28%，先做——每轮狩猎都在付文档税）

实测背景：契约文档总量 420 KB（≈105K tokens，AI 需要懂的"规矩"是 vuln_memory
的 11 倍）；重量不在死文档（仅 14 KB）而在**概念级重复**——7 个高频概念在
多份命令文档各自维护完整解释（"checkpoint 写回"在 16 份文档、"claim 契约"
在 10 份、"recall gate"在 8 份），每次演进同步 N 份，这是文档税的机制性来源。

四刀（总账 420 KB → ~300 KB，约 -28%）：

| # | 手术 | 量 | 手段 |
|---|---|---|---|
| ① | 删死文档 | -14 KB | distill.md 整份、kb.md 的 promote/lifecycle 段（:26-122）、retrospect.md 死流程段、promotion-rules.md 的状态机段（保留落位规则表格）、repo-root-seams.md 的 vision_browser 段 |
| ② | 概念单一来源化（根治） | -60~90 KB | 高频概念收敛到 rules/ 一处权威定义，命令文档改 1-3 行引用。**概念清单实测为 10 个**：原 7 个（checkpoint 写回/claim 契约/recall gate/红线/反早停/skill 选择/lane contract）+ autopilot 家族实测新增 3 个重复源（Four-Layer Runtime / 三模式 / Credential Lane）。主战场是 autopilot 家族 4 份文档（77.8 KB，每份 46-67 次 checkpoint/lane 概念提及）——checkpoint 写回权威定义收敛到 commands/checkpoint.md，autopilot 家族降为引用，仅此一族预计 -30~40 KB |
| ③ | 代码-文档重复压缩 | -30 KB | 只动 autopilot.md/validate.md 的字段复述段（叙述占比 90%+，复述 bootstrap JSON 字段与 decision schema）；hunt.md 的方法论叙述（138 行，真东西）不动 |
| ④ | autopilot skill 瘦身 | -6 KB | 275 → ~200 行，砍与 lanes/commands 重复段；re-invocation 税 5K → ~3.5K tokens |
| ⑤ | agents 版漏网重复段 | -3 KB | agents/autopilot.md 的三模式段（:103-116，批次 7 A4 漏删——A4 只删了 runtime-protocol 的仪式句）与 Four-Layer Runtime 段收敛。**注意：agents 版 17/20 段是子代理特有人格契约（Use When/Inputs/Prime Directive/专家交接），与 commands 版角色不同，不合并** |

关键收益不只是行数：② 之后**每次契约演进从"同步 16 份"变成"改 1 份"**，
并消除"AI 读到过时版本"的不确定性。砍幅诚实定在 -28%（实测"减半"无依据，
会伤活的方法论文档）。

验收：420 KB → ≤310 KB（含零-B 删除 distill.md 的 -8 KB 合计口径）；10 个概念
各有唯一权威文件且 `rg` 确认命令文档只剩引用；agents/autopilot.md 保留 17 段
子代理人格契约仅去 3 段重复；全量测试绿（文档契约测试成对改）。

### 零-A：三零孤儿（零风险归档）

实测三零孤儿（零代码引用 / 零文档引用 / 零命令入口）——动手时复核修正：

- `tools/knowledge_value_review.py`（415 行）
- `tools/self_review.py`（214 行）
- `tools/distill_aggregate.py`（86 行）
- `tools/vision_browser.py`（72 行，仅一份 seam 文档提及，0.2 已删）

**noise_filter.py 复核排除**：vuln_scanner.sh:1067/1074/1431 实际调用
（fingerprint/dedup/filter 三命令）+ tests/test_core_foundation_tools.py 覆盖。
它不是孤儿，保留。零-A 实际归档 4 个文件 ≈ -787 行。

处置：`git mv` 到 `archive/tools/`（同 capability_governance 先例）；
每个删前复核一次引用面（本清单的实测是 2026-09-11 的，动手时重跑确认）。
预计 **-1,187 行**，零风险（没有任何执行路径到达它们）。

### 零-B：拆 cross-target 知识治理的中间层（用户决策：删掉状态机，保留人工审核）

实测断链三处叠加（2026-09-11）：
- `knowledge_candidates.py` 要求素材挂在 target_memory entry_id 上，41 条存量数据
  全是旧格式 {text,ts} → stage 必然 "entry not found"（实测确认）
- 无"从 ledger/finding 直接取材"的入口；/retrospect 只有文档建议没有命令通路
- 58 张卡全部 maturity=draft、0 review、0 promote——整套 3,154 行治理机器
  （candidates 1,135 + lifecycle 766 + distill_reports ~800 + registry 消费）
  从未运转过一个零件

**改造方向：三层官僚 → 一条直线。人工审核保留为"看草稿、mv 或删"，
git 即生命周期，不再要第二个状态机管理文件状态。**

处置：

| 项 | 行数 | 处置 | 理由 |
|---|---|---|---|
| `tools/knowledge_candidates.py` | 1,135 | 归档 | 零使用；entry_id 设计即断点本身 |
| `tools/knowledge_lifecycle.py` | 766 | 归档 | 零使用；maturity 降为 frontmatter 字段人眼看 |
| `tools/distill_reports.py` + 旧 `commands/distill.md` | ~800 | 归档 | 平行死线（corpus 蒸馏从未 fetch）；名字让给新的 |
| `tools/knowledge_registry.py` | 252 | **保留** | context_pack 召回预算在用（活） |
| `tools/knowledge_audit.py` | 1,001 | **保留** | /kb 在用（活） |
| 58 张卡 + capabilities.yaml | — | **保留** | 召回链路活着 |
| `commands/retrospect.md` 提及 candidates 的段落 | — | 同步改写 | 指向新 /distill |

净 **约 -2,700 行**，保留活的（registry/audit/卡片），删从未转过的状态机。

### 零-C：新 `/distill` 直线入口（~150 行，替代被删的整条链）

```
/distill <target>
  ① 机器：拉 ledger 条目 + findings + case_state（原始证据，非 AI 回忆）
  ② 机器：出蒸馏 prompt（vuln_memory /sub 类型学：
     Pattern / Target→Vuln / 失败教训 / 绕过关系）
  ③ AI：提三元组（出题-收卷协议）
  ④ 机器：渲染成 card-template.md 格式草稿（含 source evidence_refs、
     maturity: draft、scrub 脱敏——IP/密钥不进卡是红线级，保留这 ~30 行）
  ⑤ 写 knowledge/candidates/<slug>.md
  ⑥ 输出提示：review 后 mv 进 knowledge/cards/ 即 promote，删除即 reject
```

- 脱敏逻辑从被归档的 candidates.py 抄入（唯一值得保留的片段）
- `context_pack` 的 reviewed_candidate_hints（唯一读 candidates 的活代码）
  同步适配新目录形态（从 lifecycle.jsonl 读改为扫草稿文件，或直接退役该 hint——
  实现时按复杂度二选一）
- 验收：对 127.0.0.1:3001 实跑一次（BOLA basket 模式是现成素材），
  产出第一张草稿卡并人工 mv 进 cards——首次走通即激活 semantic 层

### 零-D：autopilot_state / checkpoint 功能收益性裁决（实测驱动，-1,300 行）

对两个最大代码实体做了逐功能收益性审计（transcript 使用次数 + 外部消费方 +
生产入口核查），结论：**零函数级死码，但有明确收益存疑项与一处架构错位**。

| 处置 | 项 | 依据 |
|---|---|---|
| **归档** | `--max-lanes-reached` flag 及配套（~50 行） | transcript 仅 3 次使用且全是 argparse 定义自身；语义可由 `--bounded` + round 数据推导 |
| **归档（设计复核后收窄）** | proposal 家族中只喂 `commands` 字段的部分：`_write_back_commands`（18 行）+ checkpoint 的 `commands` 字段 + resume.py 的命令展示分支 | 设计复核推翻了"整族 1,126 行可归档"：`_lead_proposals`/`_next_proposals`/`_dead_end_proposals` 生产的 `target_write_back.lead/next/dead_end` 正是 `apply_target_memory`（B2 默认写回）的**数据源**——它们是活的。死的只有"把写回内容渲染成 AI 手抄命令"的出口（resume.py:517/714 展示 `commands[:3]`，无执行路径） |
| **迁移** | `_normalise_endpoint_path`（两文件 AST 哈希完全相同，复制粘贴实锤） | 落 `tools/target_paths.py`（共享工具函数的家），两处改 import |
| **保留** | `build_closure_projection`（550 行） | 此前疑点排除：CLI `--closure` 在用（:6469/:7445），盲测期靠它发现过 state 投影 bug |
| **保留** | witness/round 生命周期（552 行）、coverage 同步（411 行）、target memory 写回（133 行） | round 系 flag 58-92 次/项，高频核心 |

架构合理性佐证（实测职责构成）：

- autopilot_state 7,489 行 = 投影 2,856 + 读取 1,077 + 纯工具 1,740 + 决策 790
  + CLI 92——五类职责耦合是假的（只共享参数不共享状态），支撑阶段二第一刀
- checkpoint 4,919 行 = witness/round 552 + coverage 411 + 写回 133 + proposal
  家族 1,126（其中死出口仅 ~30 行）+ 其他 2,023——proposal 家族主体是
  apply_target_memory 的数据源（活），仅命令渲染出口已死

### 阶段一补充：零-D 归档 proposal 后的收尾

- `commands/checkpoint.md` 里"record commands 手工执行"段、`rules/context-loading.md`
  的提案流程段、resume.py 的 `commands[:3]` 展示分支（:517/:714）同步删除
- 验收：`rg -n 'write_back_commands|checkpoint.get\("commands"' tools/` 仅剩归档目录；
  target_write_back/next_action_queue 消费方（apply_target_memory/ingest_checkpoint）零变化

灰色模块切分（列入阶段二观察项，不立即动）：

- `report_generator`（1,712 行）：核心是报告↔队列对账（该留），外围格式化
  文案（Claude 本来会的部分）可在阶段二评估切出
- `resume`（777 行）：磁盘读取该留，输出格式是糖衣

判断标准（来自 vuln_memory 审查的修正版原则）：

```
Claude 会话内会做、且出错不跨会话传播的  → 不写代码
Claude 会做、但需要跨会话记住/对账/防重的  → 写代码（不是替它思考，是替它记住）
Claude 物理上做不了的（持久化/向量/锁）    → 写代码
```

## 阶段一：使用体感（3-4 天，5 项）

### 1. claim 模板 + 差量覆盖（最大单点，1-2 天）

- `action_queue claim --template <name> --from-evidence <ref>` 双通道预填：
  - `--from-evidence`（已有）：推导 endpoint/method/evidence_ref/baseline_ref
  - `--template`（新增）：类别稳定字段预填（family/technique/active_dimension/
    skill_route/risk_tier/max_hypothesis_actions/depth_contract_version）
- 模板注册表（内置 idor-cross-actor / sqli-error-based / authz-header-swap 等高频形态
  + `--list-templates`），AI 显式值永远覆盖模板
- **16 字段 → 4 判断字段**；模板本身过 P0 分桶检查（模板是格式税的削减，不是门槛的削减）
- 测试：模板预填正确、差量覆盖优先级、未知模板拒绝、模板 + from-evidence 组合

### 2. record 极简形态（0.5 天）

- `evidence_ledger record` 支持 `--from-probe <event_id>`：从已有 probe 事件复制
  机械字段（endpoint/method/actor/variant/evidence_ref），只补 result/notes
- 或位置参数极简形态（`record T /api/x GET tested_clean`，其余默认）
- 28 参数的复杂度收进"进阶用法"文档区，日常路径 2-3 个参数

### 3. bootstrap 人话摘要行（0.5 天）

- `autopilot_state --bounded` 输出顶部加一行结构化摘要：
  `Next: <frontier 首项人话> | Gate: <hard_gate 状态> | Queue: <active 数>`
- 机器字段全保留（owner 消费方不动）；摘要行是 vuln_memory `_build_context` 形态的移植
- 测试：摘要行与投影字段一致性（摘要说 frontier 首项 = priority_frontier[0]）

### 4. 结构化 leads + 场景化 resume（1 天）

- `target_memory` 的 `active_leads` 条目从自由文本升级为轻量结构：
  `{hypothesis, evidence_ref, next, stop_condition}` 四字段（向后兼容：纯文本
  条目继续可读）
- `resume` 输出末尾合成一段场景摘要（"我上次在干嘛、当前假设、下一步"）——
  vuln_memory 场景摘要的可读性 + ccst evidence_ref 的可对质性
- checkpoint 的 `--apply-target-memory`（已默认开）自动携带该结构

### 5. 测试日常习惯（0 改动）

- 不动 1870 个测试；日常开发用 `pytest -x --lf`，全量留给批次收尾
- 写进任务 Notes 作为习惯约定，不进代码

## 阶段二：结构重组（1.5-2 周，4 刀）

### 6. 拆 autopilot_state.py（第一刀，最大单点）

- 7,489 行 / 127 函数 / 5 类职责 → 5 个文件：
  - `autopilot_state_read.py`（状态加载、路径解析，~1200 行）
  - `autopilot_projection.py`（投影构建，~1800 行）
  - `autopilot_gate.py`（hard_gate / frontier / 23 个决策函数，~1000 行）
  - `autopilot_loop_guard.py`（Loop Guard 独立，~600 行）
  - `autopilot_state.py`（保留为 CLI 入口 + 组装，~800 行）
- **纯搬动**：函数体逐字迁移（git mv 语义），不改任何逻辑；每批搬一层跑全量
- 风险控制：一次搬一个文件，绿了再搬下一个

### 7. 斩 aq↔ck 循环依赖（第二刀）

- `action_queue.ingest_checkpoint`（:1716 函数内 import）改为接收 checkpoint dict
  参数，调用方（CLI/autopilot）负责调 `build_checkpoint()` 传入
- 两文件从此单向依赖，可独立测试
- 测试：ingest 行为不变（用等价 dict 断言）

### 8. 命令文档"谁思考"列（第三刀）

- 38 个 `commands/*.md` 的参数表加认知归属标注：
  `AI 判断`（必须 AI 给）/ `机器推导`（from-evidence/template 可预填）/ `机械`
  （owner 自动）
- 模板来源：vuln_memory SKILL 的"谁思考"表（18 命令 × 3 类的形态）
- B5 的字段分类（推导/判断）已有实测映射，直接复用

### 9. L2 契约层（第四刀，防复杂度回潮）

- 新增 `tools/contracts.py`（或 contracts/ 包）：跨 owner 不变量集中声明
  （validate 终态契约、queue claim 契约、ledger 红线契约、checkpoint→queue 锁序）
- validate.py / action_queue.py 双方 import 同一声明；任何一方改契约，另一方编译期可见
- 这是本会话 validate↔queue 集成缺口（藏两轮才暴露）的根治
- 起步只收编 3-4 个最高频契约，不追求大而全

## Acceptance Criteria

- [x] 零-0（实施修正）：405 KB → 393 KB（-12 KB / -3%）；12 处机制复述段
      收敛为权威文件引用（checkpoint 写回/recall/GlobalReview/decision schema/
      队列操作/Four-Layer/batch/anti-loop/Deep Mode/finding_claim/浏览器/Intel）；
      反早停权威强化。**诚实修正**：原"-28% → 310 KB"预估把 skills SKILL.md、
      playbook-router 信号路由表、triage-validation 七问全文都算成了"重复"——
      实测它们是单一权威本体（索引/决策树/权威定义），不是可收敛的复述；
      机制级重复实测总量就是 ~12 KB。保留判断：剩余 393 KB 是活的分工文档，
      不为凑数砍活方法论。autopilot skill 275 行对象不存在（S1 后已无此文件）
- [x] 零-A：4 个三零孤儿归档（-787 行；noise_filter 复核排除——vuln_scanner.sh 在用）；测试随源归档，conftest 排除 archive/
- [x] 零-B：candidates/lifecycle/distill_reports/rubrics/governance 数据归档
      （约 -2,900 行）；活函数族迁 corpus_projection.py；registry/audit/58 卡保留
- [x] 零-D：--max-lanes-reached CLI flag 删除（函数参数保留默认 False——
      75 处测试与 3 个程序化调用方显式传 False 有文档价值，删参破坏面不成比例）；
      checkpoint["commands"]/​_write_back_commands/resume 展示分支删除；
      _normalise_endpoint_path shim（两处）删除，调用点直改 canonical_endpoint_path
      （closure_resolver 本就是家，无需迁 target_paths）；
      --bounded/--closure/round/apply_target_memory 行为零变化，1821 passed。
      注：context_pack._write_back_commands 是同名异物（pack 提示字段，测试在用），保留
- [x] 零-C：/distill 两段式落地；127.0.0.1:3001 BOLA basket 首卡 rest-basket.md
      已 mv 进 cards 并登记 capabilities.yaml（semantic 层首次激活）
- [x] claim --template（首批 5 模板 + --list-templates）；四判断字段负断言防模板化
- [x] record --from-probe <event_id>：机械字段从 ledger 复制（3001 实跑验证）
- [x] --bounded 含 summary 人话行（派生自投影字段，一致性测试锁定）
- [x] resume Scene 摘要段 + target_memory --structured-json 四字段（实跑验证）
- [x] autopilot_state.py 7,489 → 5,006 行（loop_guard 551 + state_read 621 +
      gate 1,534 拆出）；closure/decision 投影族（~1,550 行）实测深耦合 30+
      状态构建函数，纯搬动会形成 state↔projection 循环 import——诚实保留在
      state 并记录原因。原"<1500 行"目标基于错误假设（五类职责完全独立）
- [x] 模块加载期 aq 零 ck import（懒加载分支移 CLI 层；依赖单向 ck→aq）
- [x] "谁思考"权威定义落 tool-ai-boundary.md；5 个高交互命令加认知归属表
      （其余 33 个命令参数面以机械字段为主，统一引用权威定义）
- [x] tools/contracts.py 收编 3 契约；checkpoint 锁序运行时断言绑定
- [x] 全量 1843 passed（零-B 62 个状态机测试随源退役，新增 35 个能力测试）
- [x] 分桶专项 5 passed（151 闸门清单不变）

## 明确不做

- ❌ 删 owner / 闸门 / coverage / validate（9 批次刚验证的资产）
- ❌ 六层换四层 / 换记忆模型叙事
- ❌ autopilot 砍功能（常用路径，全保留）
- ❌ 测试瘦身（1870 是敢改代码的唯一原因）
- ❌ 引入 embedding/新依赖（stdlib-only 纪律）
- ❌ 给 /distill 重建任何状态机（staged/reviewed/promote 转移已随零-B 删除；
     git mv 即 promote、删除即 reject，人工看草稿即 review）

## Notes

- 与已归档的 09-11-ai-capability-roadmap 互补：那个治"判断税"（9 批次已完结），
  本任务治"使用摩擦 + 摆放 + 过度设计"
- 施工顺序：零-0 → 零-A → 零-B → 零-C → 阶段一 → 阶段二；零与一可部分并行，
  阶段二动结构按刀串行
- 全任务终账（实测）：tools/ 88.5K → 86.2K（归档 -3,900 + 拆分 re-export +1,500
  + 新能力 +1,000）；契约 405 → 398 KB；autopilot_state 7,489 → 5,006 主文件
  + gate/loop_guard/state_read 三模块。原"-28% 文档"预估被实测推翻（机制重复仅
  ~12KB，其余是活分工文档）；净效果=删 3,900 行 + 新增 5 个交互能力
- vuln_memory 借鉴清单已吸收进本任务：谁思考表（阶段二#8）、场景摘要（阶段一#4）、
  _build_context 人话形态（阶段一#3）、/sub 出题-收卷协议与类型学（零-C）；
  其存储层实现（无锁/子串图谱/衰减不重置）明确不借鉴
- 零-B 删除的机器所承载的"知识治理"意图由三样东西继承：新 /distill 的 evidence_refs
  （可溯源）、scrub 脱敏（防泄密）、人工 mv 审核（防过拟合）——治理目标不变，
  载体从状态机换成 git + 人眼
