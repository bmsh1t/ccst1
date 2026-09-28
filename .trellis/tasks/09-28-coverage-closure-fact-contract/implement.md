# 实施与验收计划

状态：实现、定向验收与规范同步完成；用户已回复 `提交` 批准提交计划。
全程由主会话实施/检查，不使用子代理。结果及提交边界见 `verification.md`。

## 顺序

1. 最终方案获批后创建本地任务分支并 `task.py start`，不改旧日志，不 push。
2. 将基线复现转为期望拒绝混合输入的真实回归：ready→partial、partial→ready，确认
   Store revision 和 owner marker 不变，防止测试误靠其他失效机制通过。
3. 在 Coverage 既有 guard 定义具体异常；Closure 在 digest 前复用 guard；保持双导入方式。
4. 在现有 CLI/coordinator 两次循环接入仅该异常的重试。瞬时竞态成功重建、持续竞态
   最多两次后失败；普通 StoreError 不被吞掉。Checkpoint 写入口异常后 witness 不变。
5. 仅将已明确改变的直接 loader 竞态测试预期改为新异常，保留 legacy 文件无影响、
   owner-marker handoff、稳定损坏以及正常复核/恢复断言。
6. 运行下列一条 focused 检查，复核 diff 并同步规范，记录实际结果；提交另行确认。

## 验收项

- 两种证据变化方向均拒绝发布混合 digest，稳定 healthy/partial 输入不受影响。
- 直接 loader 抛指定异常；CLI/coordinator 首次失败重建，第二次仍变化退出 2/向上抛出，
  不对一般损坏异常增加重试，不无限循环。
- 复核/封轮失败前后 witness 和 Store binding 不变；重读稳定后原待办/lane 可继续恢复。
- 现有跨时间/full/bounded digest 稳定、真正输入变化使复核失效、完整材料展开继续成立。

## 定向命令

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

`test_closure_cli_retries_only_evidence_changes` 为本任务新增的参数化测试。预计约 60 秒内完成，若环境或用例超时，
报告真实耗时和原因，不以此启动无关全仓修复。产品不再变化后停止重复检查。

## 最终审查

检查没有新 owner/通用管理器、重复比较规则、异常字符串分支、宽泛吞错、额外正常态
采集或材料裁剪；hash 与 schema 不变。新异常必须在任何 digest/见证写入之前产生。
区分“稳定数据已损坏”和“装配期间数据变化”，不能将前者反复重试或伪装为正常空状态。
