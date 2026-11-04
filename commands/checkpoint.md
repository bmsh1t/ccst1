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
- 文本输出显示 `Handoff`，即当前状态的交接摘要，不写回源。
  `target_write_back.lead/next/dead_end` 只保留为空的兼容 JSON 字段，不展示空建议栏。
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

### Global Review

Autopilot 声称耗尽前，以及 Round 返回 `review_required` 时，先读 Coverage 与 Closure，
再综合复核当前目标：Surface/Observation 长尾、Coverage/Ledger/Finding、Case/业务链、
Queue/待报告/Runtime、资产关系/`chain_context`、Browser/JS/Source/Intel，及范围、
外部依赖、阻塞和残余候选。按需展开证据；外部关系只作被动背景，缺失或截断不算完成。
Actor 缺口只限制对应比较；观察残余不自动生成行动。

同一 Checkpoint owner 记录复核：先取 Closure 的 `snapshot_digest`，再提交当前证据引用。
写回后重读 Closure；只有 `closure.verdict=finish` 且 `can_claim_exhausted=true` 才能声称耗尽。
复核绑定当前 Store 的 `active_goal`；目标修改或清空后须重新复核。更新交接备注本身不使
复核失效。旧版 basis 返回 stale，按当前快照重审，不自动改写历史 witness。

```bash
python3 tools/checkpoint.py --target target.com --record-global-review \
  --review-status complete --snapshot-digest <closure.snapshot_digest> \
  --evidence-refs-json '["evidence/<target_key>/review/summary.json"]' \
  --cross-source-links-json '["browser -> JS -> Source"]' \
  --residual-unknowns-json '[]' --decision "<decision>" --json
```

`follow_up` 必须把 `--next-action` 指向现有活动 Queue action；缺失、过期或无效
复核会让 Closure 保持 handoff，不会创建新的状态 owner。

Claude Autopilot 正常自动结束还需在同一 `complete` 复核提交
`--termination-json '{"reason":"no_worthwhile_work","session_id":"当前host值","invocation_id":"当前host值","boundary":"当前证据为何支持停止；未测边界和重开条件"}'`。
`reason` 仅为 `scope_boundary`、`explicit_limit`、`global_blocker` 或 `no_worthwhile_work`。
`explicit_limit` 额外要求 `limit`，且只接受以下一种形态：

- `{"elapsed_seconds":720}`：须与入口 `--max-seconds=720` 保存的 `host.max_seconds` 一致。
  宿主用保留的 `host.started_at` 和当前时钟检查是否已到，
  resume/压缩不重置起点。提前预留写回时间不等于总时限已到。
- `{"round_id":"当前round_id"}`：当前 Round 必须有显式 `max_lanes` 且已达到；
  须匹配入口绑定的活动 Round，或本次显式额度下的新 Round，不能借用旧已完成 Round。

阈值及其入口/owner 来源写入 `boundary`；机器检查入口绑定与实际经过时间/owner，
未绑定的自然语言时限不能在结束复核里自行新增或缩短。费用限制由原生宿主执行，
当前适配没有独立费用回执，不能仅凭估算正常结束。
其他 reason 不带 `limit`。整体阻塞说明为何其他独立路径也无法推进。
仍有已知可执行 owner 工作时不能用 `no_worthwhile_work`；因范围、限制或整体阻塞退出，
须在 `residual_unknowns` 保留未完成 owner 和重开条件。历史无 termination 的复核仍可读，
不能授权新调用结束。机器仅核对绑定和事实，不证明价值判断或所有攻击面已穷尽。
已到范围/显式限制或确认整体阻塞时，当前有效复核可在保留未测项后结束，
不要求 `closure.verdict=finish`。`form_insufficient` 中的缺失覆盖 token 继续阻止
耗尽声明，不抹去已核验的停止依据；`no_worthwhile_work` 仍需完整复核。
交接与其他写回在读取最后一次 digest 之前完成；复核成功后不要为清除 handoff 重复改写。
用户主动打断不需要先提交本表。
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
