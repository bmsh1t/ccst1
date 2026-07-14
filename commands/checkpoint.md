---
description: 为当前目标生成 autopilot checkpoint、覆盖摘要和目标记忆写回建议。用法：/checkpoint <target> [--apply-target-memory]
---

# /checkpoint

生成目标 checkpoint。

这个命令用于 `/autopilot`、`/hunt`、长会话结束、切换目标、或准备汇报前。
它不是扫描器，也不是报告器；它把当前目标的状态压缩成可续接的目标记忆建议。

默认不写 target memory，但会先让 `finding_index` owner 受限地归档有效 root finding
claim，再刷新派生 coverage、通过 `action_queue` owner 幂等同步可执行 next-action，并原子更新
`state/<target_key>/checkpoint_latest.json` runtime-v2 witness。只有用户明确要求时，才使用
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
- `next_action_queue` 的 durable action queue 同步结果
- target memory 的 `lead`
- target memory 的 `next`
- target memory 的 `dead-end`
- target memory 的 `handoff`
- 可复制执行的 `tools/target_memory.py` 命令
- `/retrospect <target>` 后续沉淀入口

## 自动写入边界

默认允许自动写入，仅限：

```text
state/<target_key>/checkpoint_latest.json
state/<target_key>/action_queue.json（仅同步 checkpoint 已生成的可执行 action）
evidence/<target_key>/coverage_matrix.json（使用 --no-refresh-coverage 时不写）
findings/<target_key>/findings.json（仅通过 finding_index 归档有效 root finding claim）
findings/<target_key>/mutation-events.jsonl（仅记录上述 owner mutation provenance）
```

传入 `--apply-target-memory` 后额外允许：

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
```

除上述受限 reconciliation 外，禁止直接改写 root claim、finding lifecycle、validation/report
artifact。root claim 推荐使用显式 schema：

```json
{
  "kind": "finding_claim",
  "schema_version": 1,
  "title": "Observed impact",
  "target": "<target>",
  "vuln_class": "<class>",
  "endpoint": "<known-path-or-url>",
  "impact": "<observed-impact>",
  "evidence": {"artifact": "<raw-evidence-path>"}
}
```

缺失 endpoint/type 可以保留为显式 incomplete claim，不能编造；未知 `kind`、错误 schema、
off-target endpoint/target 或普通状态 JSON 不会被归档。知识库、Skills、Rules 的沉淀必须走
`/retrospect`，默认只输出建议。

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
- Durable action queue sync:
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

- `validate`：存在 pending structured finding，应进入 `/validate`；只有 target-memory prose 时先补可定位原始证据。
- `report`：存在 validated finding 且没有更高价值可执行深挖动作；含未填占位符的草稿进入 `complete_report_draft`，不是 report-ready。
- `refresh-recon`：没有可用 recon/surface，不要声称测试完成。
- `enrich`：browser/source/JS enrichment 可能改变下一步。
- `hunt`：有 surface review candidates、advisory score hints 或 target-memory continuation。
- `continue`：有 AI-actionable coverage hint，且无法被当前证据解释为 covered / n/a / blocked / deferred。
- `continue`：存在 active case_state backlog / enrichment action 时，优先输出 exact replay draft 或缺失证据动作。
- `continue`：coverage gap 为空但 Actor Matrix 仍有缺口时，也不能声称全面完成。
- `checkpoint`：存在 action-gated scanner lead 或需要人工授权的 lane。
  若来自目标专属脚本、默认凭据、写操作、上传、登录尝试或高风险 payload，先按 `templates/phased-surface-validation-plan.md` 分层：具体事实留在目标作用域，通用层只保留抽象阶段规则和安全门槛。
- `handoff`：本轮可停，但必须保留下一步、dead end 和交接摘要。
