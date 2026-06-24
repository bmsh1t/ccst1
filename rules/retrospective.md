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
| 只属于当前目标的线索 | `python3 tools/target_memory.py lead "..."` |
| 当前目标下一步 | `python3 tools/target_memory.py next "..."` |
| 当前目标无效方向 | `python3 tools/target_memory.py dead-end "..."` |
| 会话交接摘要 | `python3 tools/target_memory.py handoff "..."` |
| 多目标可复用思路 | `knowledge/cards/*.md` |
| 知识晋升判断 | `knowledge/promotion-rules.md` |
| Skill 执行顺序或判断方式问题 | `skills/*/SKILL.md` 或 `skills/runtime-protocol.md` |
| 红线、覆盖、上下文加载、验证标准问题 | `rules/*.md` |
| 已验证发现或成功模式 | `/remember` |

## 自动证据读取

复盘前先收集低风险证据，避免凭记忆总结：

```bash
python3 tools/target_memory.py show <target>
python3 tools/checkpoint.py --target <target> --json
python3 tools/autopilot_state.py --target <target> --json
python3 tools/surface.py --target <target> --json
python3 tools/coverage_matrix.py rebuild --target <target>
python3 tools/coverage_matrix.py find-gaps --target <target>
```

`tools/checkpoint.py` 负责把当前目标状态压缩为目标层写回建议。复盘必须先
参考 checkpoint 的 `target_write_back` 和 `coverage`，再决定是否晋升知识库、
Skills 或 Rules；不要在复盘里重新发明另一套目标写回逻辑。

如果存在，再读取：

```text
findings/<target>/findings.json
findings/<target>/validation-summary.json
memory/goals/targets/<target>.json
```

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

目标层允许自动写回，但必须写出 exact command：

```bash
python3 tools/target_memory.py lead "..."
python3 tools/target_memory.py next "..."
python3 tools/target_memory.py dead-end "..."
python3 tools/target_memory.py handoff "..."
```

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
| 写目标层 lead / next / dead-end / handoff | 可以建议自动执行 |
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
