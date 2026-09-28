---
description: 读取当前目标的 checkpoint、覆盖、材料和未决工作。用法：/checkpoint <target>
---

# /checkpoint

从已初始化的活动 Store 读取目标状态。普通查询不创建行动、登记 Finding、发布 Coverage
缓存或 witness，也不保存目标记忆。缺库、preview、损坏或待导入目标明确报错。

```bash
python3 tools/checkpoint.py --target target.com
python3 tools/checkpoint.py --target target.com --note "finished API authz pass"
python3 tools/checkpoint.py --target target.com --repo-root /path/to/data --json
```

`--note` 仅在本次输出保留用户意图。需要跨会话保存时，显式使用 `target_memory.py`
的 note/next/handoff 或 Store 领域命令。`--apply-target-memory` 和
`--no-apply-target-memory` 只保留兼容解析，前者返回 skipped；两者都不写记忆。
`--no-refresh-coverage` 同样不会改变只读保证，缓存发布使用显式 Coverage rebuild。

## 输出与展开

- `next_action_queue` 按 ID 展示最多 5 条已保存的未决行动，包括 blocked。
  `action_queue_window` 提供总量、余量和绑定数据根的完整查询命令；展开包含终态历史。
- `default_candidate`/`recommended_executable_action` 只指向真实认领中的行动。
  活跃 Recon/Scan phase 锁返回瞬时 wait 指针；没有认领时保留空指针和 continue。
- Coverage、Actor Matrix、Case、未裁决 Finding、Runner candidates、条件化经验都保持可见。
  覆盖缺口有总量、窗口和完整查询入口，不按类别分数代替 AI 选工作。
- `material_sources` 展示原始 root claims、人工复核/危险动作线索和源码材料的预览、余量及
  Autopilot state 完整查询。材料不是技术裁决，也不由 Checkpoint 自动入队。
- `target_write_back.lead/next/dead_end` 为空；`handoff` 是当前状态的展示摘要，不写回源。
  `runtime_witness.status=not_published` 表示普通查看没有持久副作用。

AI 决定测试顺序、下一行动、全局复核结论和是否重开历史负结果。Store/证据 owner 校验
目标归属、当前状态、claim、真实完成引用和证据完整性；摘要或 AI 主张不能替代这些事实。

## 显式轮次与复核

`--round-begin`、`--record-round-lane`、`--record-round-lane-result`、
`--record-round-closure` 和 `--record-global-review` 是写 witness 的独立命令。
轮次预算、并发 lane claim、证据可用性、终态重放和全局 review 的快照绑定由 owner 校验。

`browser:` lane 的完成引用若是 focused MCP capture manifest，显式 lane-result 命令会导入
浏览器材料并记录导入结果；失败保留可诊断状态，heartbeat 仍保存。导入默认不登记待审
行动；需要登记时单独运行 `browser_mcp_import.py --focused-manifest ... --enqueue`。

完成一次有实质 lane 的 Autopilot round 后，目标范围的最终综合复核仍由同一
Checkpoint owner 记录。先读取 Closure 返回的 `snapshot_digest`，再写入当前证据引用：

```bash
python3 tools/checkpoint.py --target target.com --record-global-review \
  --review-status complete --snapshot-digest <closure.snapshot_digest> \
  --evidence-refs-json '["evidence/<target_key>/review/summary.json"]' \
  --cross-source-links-json '["browser -> JS -> Source"]' \
  --residual-unknowns-json '[]' --decision "<decision>" --json
```

`follow_up` 必须把 `--next-action` 指向现有活动 Queue action；缺失、过期或无效
复核会让 Closure 保持 handoff，不会创建新的状态 owner。
全局复核只接受 `--evidence-refs-json`；`--evidence-ref` 属于 lane-result，
与 `--record-global-review` 同用时返回 `2`，不写 witness，即使同时传入合法 JSON。
证据列表缺失、为空、超限或引用不属于目标的非空文件时，诊断的
`state_changes[].field` 为 `evidence_refs`，`expected` 指明修正要求。
同一物理仓库的绝对、相对和符号链接根路径共享 Closure 身份；历史非规范路径
产生的 review 若显示 stale，重新读取 Closure 并明确复核，不自动改写历史 witness。

如果 `snapshot_digest` 已过期，Checkpoint 会拒绝写入并返回可恢复诊断：

```json
{
  "status": "stale",
  "reason": "global_review_stale",
  "state_changes": [
    {"field": "snapshot_digest", "provided": "<old_digest>", "current": "<current_digest>"}
  ],
  "action_required": "Re-run closure check and resubmit the review with its returned snapshot_digest."
}
```

恢复方式：重新运行 Closure check，使用返回的最新 `snapshot_digest` 重提交 Global Review。

## 相关只读查询

```bash
python3 tools/context_pack.py --target <target>
python3 tools/autopilot_state.py --target <target> --json
python3 tools/coverage_matrix.py find-gaps --target <target>
python3 tools/evidence_ledger.py summary --target <target>
python3 tools/target_case_state.py summary --target <target>
```

需要新鲜状态时重新查询；只有显式 owner 命令可以改变领域事实。旧 JSON/Ledger/Case
文件仅供显式迁移和历史检查，不作普通查询的后备来源。知识沉淀继续走 `/retrospect`
和现有审核流程。
