# 复盘与沉淀规则

复盘用于把一次 hunt、验证或目标切换中的经验沉淀回四层体系。它不是报告，也不是漏洞验证。
它的增强目标是把“总结”变成“分流决策”：每条经验必须落到目标层、知识库、Skill、Rules、`/remember` 或 `none`。

## 目的

每次重要会话结束前，回答：

- 什么有效？
- 什么无效？
- 漏了什么？
- 哪些线索还值得继续？
- 哪些经验可复用？
- 哪些 Skill 流程需要优化？
- 哪些规则需要调整？

## 沉淀分流

| 内容类型 | 写入位置 |
|---|---|
| 只属于当前目标的线索 | 目标层 `lead`，见[完整写回示例](#写入目标层) |
| 当前目标下一步 | 目标层 `next`，见[完整写回示例](#写入目标层) |
| 当前目标无效方向 | 目标层 `dead-end`，见[完整写回示例](#写入目标层) |
| 会话交接摘要 | 目标层 `handoff`，见[完整写回示例](#写入目标层) |
| 多目标可复用思路 | `knowledge/cards/*.md` |
| 知识晋升判断 | `knowledge/promotion-rules.md` |
| Skill 执行顺序或判断方式问题 | `skills/*/SKILL.md` 或 `skills/runtime-protocol.md` |
| 红线、覆盖、上下文加载、验证标准问题 | `rules/*.md` |
| 已验证发现或成功模式 | `/remember` |

## 自动证据读取

复盘前先收集低风险证据，避免凭记忆总结：

```bash
python3 tools/target_memory.py show TARGET --json
python3 tools/checkpoint.py --target TARGET --json
```

先参考 checkpoint 的 `target_write_back`、`coverage`、`decision` 和 `retrospect`，
再决定是否晋升知识库、Skills 或 Rules。只有视图缺字段时才展开对应 owner：

```bash
python3 tools/autopilot_state.py --target TARGET --json
python3 tools/surface.py --target TARGET --json
python3 tools/coverage_matrix.py find-gaps --target TARGET
```

分别用于 lane/route、逐 endpoint 表面和未处置覆盖格；不默认预拉全量状态或执行
`coverage_matrix.py rebuild`。有界 `find-gaps` 不是全部覆盖，按需扩展。
需要主张或条件化经验时读取同一 Store：

```bash
python3 tools/target_store.py findings --target TARGET
python3 tools/target_store.py findings --target TARGET --id FINDING_ID
python3 tools/experience_recall.py --target TARGET --json
```

`memory/goals/active.json` 仅用于选择目标。缺库/缺 Finding ID 必须显式失败，合法空库
的列表可为空；旧 Finding、目标记忆和会话 JSON 只供显式历史检查，不作当前事实回退。
按 selected Finding 查询返回的 assessment/evidence/delivery/report 关系展开；validation
summary 使用该次 validate 返回并保留的 `summary_path`，核对 target/Finding 后读取。
Store Finding 没有 summary 定位字段，不能从全局 `findings/last-validate.json` 绑定别的 Finding。

不要默认读取大体积原始日志、完整响应包、HTML dump 或无关历史会话。

## 复盘问题

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

## 判断标准

### 写入目标层

满足以下任一条件：

- 只对当前目标有意义
- 还只是 Lead / Signal
- 需要下次继续验证
- 是当前目标的 dead end

目标层只在操作者明确要求持久化时执行，默认输出 exact command 建议。
TARGET 必须是已初始化目标；以下内容按实际观察替换，不把示例结论当作事实：

```bash
python3 tools/target_memory.py lead --target TARGET \
  --conditions 'peer session; same tenant; JSON representation' \
  'Hypothesis: compare the saved control and peer response'
python3 tools/target_memory.py next --target TARGET \
  'Compare the existing control with the saved peer response'
python3 tools/target_memory.py dead-end --target TARGET \
  --conditions 'peer session; same tenant; JSON representation; recorded deployment' \
  --reopen-when 'role, tenant, representation or deployment changes' \
  --operation-ref OPERATION_ID:0 \
  'No peer read was observed under these recorded conditions'
python3 tools/target_memory.py handoff --target TARGET \
  --conditions 'saved response only; impact not established' \
  --next-intent 'Compare existing control before another experiment' \
  --operation-ref OPERATION_ID:0 \
  'Candidate remains unconfirmed'
```

`OPERATION_ID:STEP` 必须引用同目标 Store 已登记的真实 observation，STEP 从零开始；
此处的 `OPERATION_ID:0` 必须替换为实际登记返回的 operation ID 和对应步骤。
artifact 路径、Finding ID、虚构执行都不是替代品。negative 必须有非空且明确的适用条件、
重开条件和 operation 引用，仅在这些条件下成立；KILL 只是不报告 candidate，不证明 negative。
没有登记证据时保留假设/缺失证据，或在明确要求保存时使用未验证 note：

```bash
python3 tools/target_memory.py note --target TARGET \
  'Unverified observation: peer-read evidence is still missing'
```

不得隐式把失败的 negative 转成 note，也不得为了写经验虚构/自动登记 observation。
`next`/`handoff` 是 advisory intent，不创建或完成 Queue Action。

写回内容必须去掉凭证、token、cookie、PII 和客户数据。

### 写入知识库

满足以下任一条件：

- 多个目标可复用
- 能帮助 Skill 更好发散
- 是常见高价值模式
- 是常见低价值方向
- 有明确触发信号、下一步和停止条件

知识库默认只输出 patch 建议，不自动改文件。候选条目必须包含：

```text
Evidence pattern:
Why it matters:
Next action:
Stop condition:
Validation requirement:
```

知识库候选必须说明目标卡片，例如：

```text
knowledge/cards/api-idor.md
knowledge/cards/auth-access.md
knowledge/cards/ssrf-url-fetch.md
knowledge/cards/graphql.md
knowledge/cards/upload-parser.md
knowledge/cards/race-conditions.md
knowledge/cards/dead-ends.md
knowledge/cards/coverage-prompts.md
```

### 修改 Skill

满足以下任一条件：

- 当前流程顺序导致漏测
- Skill 没有正确调用知识库
- Skill 输出缺少 Evidence / Hypothesis / Next action
- Skill 没有写回目标层
- Skill 经常在某类任务上选错路径

Skill 默认只输出建议，不自动改文件。建议必须说明：

- target skill
- 当前证据
- 缺陷类型：route / ordering / output / write-back / context-load
- proposed change

### 修改 Rules

满足以下任一条件：

- 发现新的高风险边界
- 覆盖基线缺少关键 surface
- 上下文加载规则导致读太多或读太少
- 验证/报告 gate 存在模糊或冲突

Rules 默认只输出建议，不自动改文件。建议必须说明：

- target rule
- 触发证据
- 为什么不是知识库或 Skill 问题
- proposed change

### `/remember`

只有已验证发现、稳定成功模式或经过 `/validate` 的结论进入 `/remember`。
Lead、Signal、未验证假设、目标专属线索不进入 `/remember`。

## 自动化边界

| 动作 | 默认行为 |
|---|---|
| 写目标层 lead / next / dead-end / handoff / note | 默认建议；操作者明确要求后才执行 |
| 修改知识卡 | 只建议 patch，需人工确认 |
| 修改 Skill | 只建议 patch，需人工确认 |
| 修改 Rules | 只建议 patch，需人工确认 |
| `/remember` | 仅验证后建议执行 |
| 删除或覆盖已有经验 | 禁止自动执行 |

## 禁止事项

- 不把未验证漏洞结论写成知识库事实。
- 不把目标专属敏感信息写入知识库。
- 不把真实凭证、cookie、token、个人数据或客户数据写入知识库。
- 不用复盘替代 `/validate`。
- 不用“这次没发现”结束复盘，必须说明覆盖和剩余项。
- 不把目标层 dead end 直接晋升为全局规则，除非多个目标重复出现且有停止条件。
