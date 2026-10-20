---
description: 复盘本轮 hunt / validation / target session，并把经验分流到目标层、知识库、Skills 或 Rules。用法：/retrospect [target]
---

# /retrospect

复盘并沉淀经验。

这个命令用于会话结束、切换目标、长时间 hunt 后，帮助 Claude 把经验写回四层体系。
它不是普通总结，而是**分流决策器**：必须判断哪些内容写回目标层、哪些建议晋升知识库、哪些暴露 Skill / Rules 的缺口。

## 必读文件

```text
rules/ccst/retrospective.md
memory/goals/active.json
rules/ccst/coverage-gate.md
knowledge/promotion-rules.md
```

必要时读取：

```text
skills/runtime-protocol.md
rules/ccst/red-lines.md
knowledge/index.md
```

## 用法

```text
/retrospect
/retrospect target.com
```

## 自动收集

先解析目标。优先使用 `$ARGUMENTS`；没有参数时读取仅负责目标选择的 `memory/goals/active.json`。
仍然没有目标时，停止并要求用户指定目标。

有目标后按缺口消费，不预拉全量状态：

```bash
python3 tools/target_memory.py show TARGET --json
python3 tools/checkpoint.py --target TARGET --json
```

`checkpoint.py` 是只读快照，不是写回 owner。写回时机唯一见
[`skills/runtime-protocol.md#cognitive-write-timing`](../skills/runtime-protocol.md#cognitive-write-timing)。
其输出携带 coverage、decision、surface 摘要和 retrospect 建议；
`target_write_back.lead/next/dead_end` 保持空，handoff 仅展示当前交接，不能反推落盘。
先消费这两个视图；只有 checkpoint 输出确实
缺字段时，才按需补读对应 owner：

```bash
python3 tools/autopilot_state.py --target TARGET --json    # 需要 lane/route 状态时
python3 tools/surface.py --target TARGET --json            # 需要逐 endpoint 表面时
python3 tools/coverage_matrix.py find-gaps --target TARGET # 需要未处置覆盖格预览时
```

`find-gaps` 不做语义过滤；按需提高 `--limit` 或读取完整矩阵，不把有界预览当作全部覆盖。
`coverage_matrix.py rebuild` 仅在矩阵过期且复盘要写回时执行。

复盘时优先使用 checkpoint 输出的 `target_write_back`、`coverage`、`decision`
和 `retrospect` 字段，再判断哪些经验需要晋升到知识库（走 `/distill`）、
Skills 或 Rules。

需要展开主张或条件化经验时读取同一 Store：

```bash
python3 tools/target_store.py findings --target TARGET
python3 tools/target_store.py findings --target TARGET --id FINDING_ID
python3 tools/experience_recall.py query --target TARGET --json
```

按 selected Finding 查询返回的 assessment/evidence/delivery/report 关系展开原始材料；
validation summary 使用该次 validate 返回并保留的 `summary_path`，先核对 target/Finding。
Store Finding 没有 summary 定位字段。缺库/缺 Finding ID 显式失败，合法空库列表可为空；
旧 Finding/目标记忆/会话文件仅供显式历史检查，不用于恢复当前事实。

`findings/last-validate.json` 仅表示最近一次运行，不得替代 selected finding 的 canonical
artifact 绑定。

不要默认读取大体积原始扫描日志、完整响应包、HTML dump、所有 JSONL 或无关历史会话。

## 输出格式

必须输出这个结构。没有内容也要写 `none` 和原因。

```text
RETROSPECTIVE DECISION
- Target:
- Session goal:
- Evidence reviewed:
- Coverage state:
  - covered:
  - high-value gaps:
  - red-line blocked:
  - still unknown:
- Target write-back:
  - lead:
  - next:
  - dead-end:
  - handoff:
  - source checkpoint:
- Knowledge promotions:
  - candidate:
  - target card:
  - reason:
  - proposed entry:
- Skill changes:
  - candidate:
  - target skill:
  - issue:
  - proposed change:
- Rule changes:
  - candidate:
  - target rule:
  - reason:
  - proposed change:
- Remember:
  - validated finding or success pattern:
- Decision:
  - safe auto-write:
  - needs human review:
```

## 分流规则

### 目标层

按唯一写回时机协议保存影响后续判断的必要增量，不等用户再次说“记住”；
无增量不重复写，明确只读/预览时不写目标层或 campaign 工作文件。

exact command 使用 `rules/ccst/retrospective.md#写入目标层` 的完整示例，显式绑定 TARGET。
negative 必须有适用条件、重开条件和同 Store 已登记的 `OPERATION_ID:STEP`（从零开始）；
KILL 或低价值方向不自动证明 negative。缺登记证据时仅明确建议未验证 note 或保留假设。
`next`/`handoff` 只是 advisory intent，不创建或完成 Queue Action。

可分流的内容（不是额外写回频率；是否写入仍遵循上述唯一协议）：

- 当前目标还有 Lead / Signal
- 有明确下一步
- 有重复低价值方向需要避免
- 会话需要交接

### 知识库层

可复用经验先按 `knowledge/promotion-rules.md` 判断，再建议写入对应知识卡。
跨目标共享仍走 `distill_target` 候选与 `knowledge_promote` 审核晋升。
6k 方法增补遵守完整 `rules/hunt-iter.md`：主控核对准入门槛、三问和来源后，
直接修改选定 checkout 的 `skills/src-hunter/知识库/` 正文与必要索引，以 Git 保留差异；不改安装副本。
子代理只交候选，不能借复盘绕过审核；方法维护不改走共享卡的 `knowledge_promote.review_existing`。

如果没有合适知识卡，使用：

```text
knowledge/card-template.md
```

共享知识卡默认只输出候选，不绕过审核发布；这不覆盖上面的原生方法维护合同。
共享卡的 `proposed entry` 包含：

```text
Evidence pattern:
Why it matters:
Thought branches:
Technique / payload / bypass family:
Checklist gap:
Next action:
Stop condition:
Validation requirement:
False positives / dead ends:
Promote to Skill / Queue when:
```

### Skills 层

如果问题来自流程选择、调用顺序、输出格式或写回纪律，建议修改：

```text
skills/runtime-protocol.md
skills/<skill>/SKILL.md
```

默认不要直接修改 Skill。输出具体 `target skill`、问题和建议改法。

### 检查层

如果问题来自红线、覆盖、上下文加载或验证标准，建议修改：

```text
rules/ccst/red-lines.md
rules/ccst/coverage-gate.md
rules/ccst/context-loading.md
rules/ccst/reporting.md
```

默认不要直接修改 Rules。输出具体 `target rule`、触发证据和建议改法。

## 决策要求

复盘必须给出：

```text
Write target memory: yes/no + exact command(s)
Promote to knowledge: yes/no + target card + reason + proposed entry
Change skill: yes/no + target skill + reason + proposed change
Change rule: yes/no + target rule + reason + proposed change
Remember finding: yes/no + reason
Needs human review: yes/no + reason
```

安全默认：

- 目标层重要增量按唯一时机协议保存；无增量不重复写，明确只读/预览优先且不写。
- 原生方法由主控按 hunt-iter 审核后写回 checkout；共享卡及 Skill/Rule 流程变更默认输出建议，
  不借方法维护绕过各自审核。用户已明确要求修复的工程变更按该授权执行。
- 任何包含凭证、cookie、token、PII、客户数据、目标专属秘密的内容都不能晋升知识库。

## 禁止输出

不要只输出：

```text
本轮没有发现漏洞。
```

必须输出：

```text
本轮覆盖了什么；
还有什么没覆盖；
哪些方向无效；
哪些线索保留；
哪些经验需要沉淀。
```
