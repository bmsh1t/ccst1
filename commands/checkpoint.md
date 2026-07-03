---
description: 为当前目标生成 autopilot checkpoint、覆盖摘要和目标记忆写回建议。用法：/checkpoint <target> [--apply-target-memory]
---

# /checkpoint

生成目标 checkpoint。

这个命令用于 `/autopilot`、`/hunt`、长会话结束、切换目标、或准备汇报前。
它不是扫描器，也不是报告器；它把当前目标的状态压缩成可续接的目标记忆建议。

默认只输出建议，不写文件。只有用户明确要求时，才使用
`--apply-target-memory` 写入目标记忆层。

## 用法

```bash
python3 tools/checkpoint.py --target target.com
python3 tools/checkpoint.py --target target.com --note "finished API authz pass"
python3 tools/checkpoint.py --target target.com --apply-target-memory
python3 tools/checkpoint.py --target target.com --json
```

## 自动读取

```bash
python3 tools/context_pack.py --target <target>
python3 tools/autopilot_state.py --target <target> --json
python3 tools/coverage_matrix.py rebuild --target <target>
python3 tools/evidence_ledger.py summary --target <target>
python3 tools/target_case_state.py summary --target <target>
```

工具会从这些状态生成：

- 当前 decision：`refresh-recon` / `enrich` / `hunt` / `continue` / `validate` / `report` / `checkpoint` / `handoff`
- 覆盖摘要和 high-value gaps
- Evidence Ledger 摘要和 Actor Matrix gaps
- Target Case State 摘要和 top backlog / enrichment action
- target memory 的 `lead`
- target memory 的 `next`
- target memory 的 `dead-end`
- target memory 的 `handoff`
- 可复制执行的 `tools/target_memory.py` 命令
- `/retrospect <target>` 后续沉淀入口

## 自动写入边界

允许自动写入，仅限：

```text
memory/goals/targets/<target>.json
memory/goals/sessions/<timestamp>-<target>.md
```

禁止自动修改：

```text
knowledge/cards/*
skills/*
rules/*
reports/*
findings/*
```

知识库、Skills、Rules 的沉淀必须走 `/retrospect`，默认只输出建议。

## 输出格式

```text
CHECKPOINT DECISION
- Target:
- Phase:
- Decision:
- Next action:
- Selected skill:
- Knowledge cards:
- Coverage:
  - endpoints:
  - high-value gaps:
- Case state:
  - actors:
  - sessions:
  - objects:
  - pending backlog:
  - top next action:
- Evidence ledger:
  - entries:
  - actor matrix gaps:
  - red-line unchecked:
  - actor gaps:
  - record commands:
- Target write-back:
  - lead:
  - next:
  - dead-end:
  - handoff:
- Commands:
- Retrospect:
- Apply status:
```

## 决策解释

- `validate`：存在 pending structured finding，应进入 `/validate`。
- `report`：存在 validated finding，但仍需人工审查，不自动提交。
- `refresh-recon`：没有可用 recon/surface，不要声称测试完成。
- `enrich`：browser/source/JS enrichment 可能改变下一步。
- `hunt`：有 P1/P2 或 recommended target。
- `continue`：有 high-value coverage gap。
- `continue`：存在 active case_state backlog / enrichment action 时，优先输出 exact replay draft 或缺失证据动作。
- `continue`：coverage gap 为空但 Actor Matrix 仍有缺口时，也不能声称全面完成。
- `checkpoint`：存在 action-gated scanner lead 或需要人工授权的 lane。
  若来自目标专属脚本、默认凭据、写操作、上传、登录尝试或高风险 payload，先按 `templates/phased-surface-validation-plan.md` 分层：具体事实留在目标作用域，通用层只保留抽象阶段规则和安全门槛。
- `handoff`：本轮可停，但必须保留下一步、dead end 和交接摘要。
