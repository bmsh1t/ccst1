---
description: 复盘本轮 hunt / validation / target session，并把经验分流到目标层、知识库、Skills 或 Rules。用法：/retrospect [target]
---

# /retrospect

复盘并沉淀经验。

这个命令用于会话结束、切换目标、长时间 hunt 后，帮助 Claude 把经验写回四层体系。
它不是普通总结，而是**分流决策器**：必须判断哪些内容写回目标层、哪些建议晋升知识库、哪些暴露 Skill / Rules 的缺口。

## 必读文件

```text
rules/retrospective.md
memory/goals/active.json
rules/coverage-gate.md
knowledge/promotion-rules.md
```

必要时读取：

```text
skills/runtime-protocol.md
rules/red-lines.md
knowledge/index.md
```

## 用法

```text
/retrospect
/retrospect target.com
```

## 自动收集

先解析目标。优先使用 `$ARGUMENTS`；没有参数时读取 `memory/goals/active.json`。
仍然没有目标时，停止并要求用户指定目标。

有目标后先读取这些低风险上下文：

```bash
python3 tools/target_memory.py show <target>
python3 tools/checkpoint.py --target <target> --json
python3 tools/autopilot_state.py --target <target> --json
python3 tools/surface.py --target <target> --json
python3 tools/coverage_matrix.py rebuild --target <target>
python3 tools/coverage_matrix.py find-gaps --target <target>
```

`checkpoint.py` 是目标层写回建议的主来源。复盘时优先使用它输出的
`target_write_back`、`coverage`、`decision` 和 `retrospect` 字段，再判断哪些
经验需要晋升到知识库、Skills 或 Rules。

如果存在文件，再读取：

```text
findings/<target>/findings.json
findings/<target>/validation-summary.json
memory/goals/targets/<target>.json
memory/goals/sessions/*.md
```

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

当前目标相关内容可以直接建议写回。只在用户明确要求自动写入时执行命令。

```bash
python3 tools/target_memory.py lead "..."
python3 tools/target_memory.py next "..."
python3 tools/target_memory.py dead-end "..."
python3 tools/target_memory.py handoff "..."
```

触发条件：

- 当前目标还有 Lead / Signal
- 有明确下一步
- 有重复低价值方向需要避免
- 会话需要交接

### 知识库层

可复用经验先按 `knowledge/promotion-rules.md` 判断，再建议写入对应知识卡。

如果没有合适知识卡，使用：

```text
knowledge/card-template.md
```

默认不要直接修改知识库。输出 `proposed entry`，包含：

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
rules/red-lines.md
rules/coverage-gate.md
rules/context-loading.md
rules/reporting.md
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

- 目标层写回可以自动执行，但只在用户明确要求时执行。
- 知识库、Skills、Rules 默认只输出建议，不自动改文件。
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
