---
description: 检查当前目标或本轮输出是否满足覆盖基线。用法：/check-coverage
---

# /check-coverage

检查覆盖基线。

这个命令不是漏洞验证，也不是扫描器。它用于防止 Claude 过早收工，确保本轮工作交代清楚“测了什么、没测什么、为什么”。

## 必读文件

```text
rules/coverage-gate.md
memory/goals/active.json
```

建议同时读取：

```text
knowledge/cards/coverage-prompts.md
rules/red-lines.md
```

## 自动步骤

先解析当前目标。优先从 `$ARGUMENTS` 读取；没有参数时读取
`memory/goals/active.json` 的 `target`。如果仍然没有目标，停止并要求用户给出目标。

有目标后先运行：

```bash
python3 tools/coverage_matrix.py rebuild --target <target>
python3 tools/coverage_matrix.py find-gaps --target <target>
python3 tools/evidence_ledger.py summary --target <target>
python3 tools/surface.py --target <target>
```

解释方式：

- `find-gaps` 非空：不能说“全面完成”，必须列出高价值 gap 和下一步。
- `find-gaps` 为空：仍需结合 `/surface`、target memory、Workflow Leads、unsafe-skipped、blocked/n/a/dead-end 解释覆盖状态。
- Evidence Ledger 的 Actor Matrix gaps 非空：不能说 authz/IDOR/业务逻辑完整覆盖；必须列出缺少的 actor/object/replay 差异。
- `rebuild` 没有 endpoint：说明 recon/source/browser 输入不足，不能把空矩阵当成全面覆盖。
- 如果某个 gap 的继续测试会触发 `rules/red-lines.md`，标记为 `blocked: red-line`，并给出低风险替代验证。

## 使用场景

- `/hunt`、`/surface`、`/source-hunt` 或手工测试结束前
- 准备向用户汇报“没有发现有效漏洞”前
- 准备切换目标或写 handoff 前
- 某个 Skill 输出过短、缺少未覆盖项时

## 检查问题

1. 当前目标和阶段是什么？
2. 本轮覆盖了哪些核心 surface？
3. 每个核心 surface 至少有哪些 lane 被判断过？
4. 对 authz/IDOR/业务逻辑，是否覆盖 anonymous、owner、peer、low_role、cross_tenant？
5. 哪些是 `tested`，证据是什么？
6. 哪些是 `lead` / `signal`，下一步是什么？
7. 哪些是 `candidate`，是否需要 `/validate`？
8. 哪些是 `blocked`，阻塞原因是什么？
9. 哪些是 `n/a`，为什么不适用？
10. 哪些还是 `unknown`，下一步是什么？
11. 是否有动作被 `rules/red-lines.md` 阻止？

## 输出格式

```text
COVERAGE CHECK
- Target:
- Phase:
- Matrix:
- High-value gaps:
- Evidence ledger:
- Actor matrix gaps:
- Covered:
- Leads / Signals:
- Candidates:
- Blocked:
- Not applicable:
- Dead ends:
- Still unknown:
- Red-line blocked:
- Next actions:
- Decision: continue / handoff / validate / report-not-ready
```

## 决策

### continue

仍有高价值 `unknown` 或明确 next action，应继续测试。

### handoff

本轮可以停止，但必须写清楚剩余项和下一步。

### validate

存在 `candidate`，应该进入 `/validate`。

### report-not-ready

没有 candidate，或证据不足，不能写报告。

## 禁止输出

没有覆盖摘要时，不要输出：

```text
已全面测试，没有发现问题。
```

应该输出：

```text
本轮覆盖了 X；未覆盖 Y；没有形成可验证 Candidate；下一步是 Z。
```
