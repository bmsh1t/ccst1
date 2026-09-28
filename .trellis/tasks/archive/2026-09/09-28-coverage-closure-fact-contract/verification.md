# 实施验收与提交边界

日期：2026-09-28；基线：`7c05aa9`；分支：`fix/closure-evidence-snapshot-consistency`。
用户 `go` 批准实施，随后强调维护成本。主会话完成实施/检查，无子代理；验收阶段未提交或 push。

## 实际变更

- Coverage 仍是三项一致性比较的唯一 owner；原错误消息不变，以
  `CoverageEvidenceChangedError(StoreError)` 区分装配输入变化。
- Closure 获取 truth 后立即复用 guard，在 witness 读取、构造 Closure 和 digest 前拒绝混合输入。
- CLI/coordinator 只在既有两次循环内捕获该异常；首错重建 state/closure，次错原样传播。
  普通 Store/I/O 错误不增加重试，原 marker handoff 保留。
- 无新增状态 owner、依赖、查询或重试框架；无 hash/schema 改动。
  Checkpoint/Surface/Resume 产品实现未修改；完整材料和未完成工作不被裁剪。

## 实跑检查

```bash
python3 -m pytest -q \
  tests/test_closure_snapshot_stability.py \
  tests/test_autopilot_round.py \
  tests/test_checkpoint.py::test_shared_coverage_rejects_raw_damage_during_assembly \
  tests/test_checkpoint.py::test_primary_checkpoint_restores_pending_actions_without_generated_routes \
  tests/test_checkpoint.py::test_round_lane_result_survives_resume_and_terminal_replay_is_idempotent \
  tests/test_autopilot_state_tool.py::test_closure_tracks_store_revision_without_legacy_owner_markers \
  tests/test_autopilot_state_tool.py::test_closure_marks_owner_snapshot_stale_when_source_changes_during_read \
  tests/test_autopilot_state_tool.py::test_closure_cli_retries_only_evidence_changes \
  tests/test_autopilot_state_tool.py::test_damaged_store_evidence_blocks_closure_and_rotation \
  tests/test_surface_primary_owner.py::test_primary_pickup_preserves_surface_and_coverage_expansions
```

退出码 `0`，工具汇总 `Pytest: 68 passed`。未运行全仓测试、构建或线上验证；通过后未重复测试。

- 真实临时 SQLite/raw 在两次获取之间损坏/恢复，两方向均拒绝直接 Closure、复核和封轮；
  Store binding、owner markers 和既有 witness 字节均保持不变。
- CLI/coordinator 注入具体异常，验证瞬时恢复、持续变化两次停止，以及普通 Store/I/O
  故障不重试。正常路径只装配一次；成功重试重建 state，而非仅重复 Closure。
- 稳定 partial 诊断、时间/full/bounded digest 稳定性、真实事实变化失效、marker handoff、
  完整材料展开、12 条待办恢复、lane 进度和幂等回放均在上述定向集合中验证。
- `git diff --check` 通过；逐项审阅本次产品、测试与规范 diff，未发现重复判定、宽泛吞错、
  新状态源、hash 改动、额外正常态采集或无关产品变更。双导入分支已按代码检查保留。
- `sha256sum -c /tmp/fact-contract-baseline.vmDsm7/worktree.sha256` 两项均 `OK`；
  当前两份日志的 `git diff --cached --binary` 与基线 `staged-before.patch` 经 `cmp` 相同。

`research/reproduce_mixed_evidence.py` 是基线缺陷复现，断言旧缺陷；修复后没有将它作为成功验收命令。

## 提交计划（用户已确认）

用户于 2026-09-28 回复 `提交`，批准下列范围。

单一工作提交：`fix: reject mixed closure evidence snapshots`

产品和测试：

- `tools/coverage_matrix.py`
- `tools/autopilot_state.py`
- `tools/autopilot_round.py`
- `tests/test_closure_snapshot_stability.py`
- `tests/test_checkpoint.py`
- `tests/test_autopilot_state_tool.py`
- `tests/test_autopilot_round.py`

同批规范与任务记录：

- `.trellis/spec/backend/contracts/transactional-target-state.md`
- `.trellis/spec/backend/contracts/lifecycle-state.md`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/prd.md`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/design.md`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/implement.md`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/implement.jsonl`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/check.jsonl`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/research/findings.md`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/research/reproduce_mixed_evidence.py`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/task.json`
- `.trellis/tasks/09-28-coverage-closure-fact-contract/verification.md`

明确排除并保持原状的旧暂存修改：

- `.trellis/workspace/Codex/index.md`
- `.trellis/workspace/Codex/journal-1.md`

获批后仅按上述路径暂存/提交；忽略的 `.trellis` 路径按需 `git add -f`，使用
`git commit --only` 的精确文件列表，避免携带旧日志。任务归档在工作提交之后处理，
不得通过全局 journal 更新覆盖旧暂存内容。不 amend、不 push。

## 完成记录

- 工作提交：`916524c5e572f51513eaaff0e42c7e61a029a697`，实际提交文件集与上述 18 个路径完全一致。
- 提交阶段没有产品逻辑变更，沿用本任务的 68 项通过结果，不重复测试。
- 按计划随后归档本任务；归档使用 `--no-commit`，再以精确路径单独提交，防止带入旧暂存日志。
- 本节替代全局 journal 写入，保留两份旧日志及其暂存状态；其他任务不处理，无 push、合并或部署。
