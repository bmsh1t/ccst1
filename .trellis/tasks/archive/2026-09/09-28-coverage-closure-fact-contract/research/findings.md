# 事实契约核查结果

基线：`7c05aa9`；2026-09-28；主会话只读源码并运行临时样本，未使用子代理。

## 归属和合法差异

| 事实或视图 | 当前 owner / 消费点 | 结论 |
|---|---|---|
| 已登记证据、当前健康和闭合授权 | `current_truth.current_cell_projection`，`tools/current_truth.py:64-107` | 一个来源；损坏记录保留，但闭合授权被抑制 |
| Coverage 采集快照 | `tools/coverage_matrix.py:966-1002,1321-1354` | source/health/projection 均绑定；as_of 是本次采集标签 |
| Closure 语义快照 | `tools/autopilot_state.py:3399-3504` | 去除 Coverage 采集时间是既定设计；保留原矩阵，不应为统一而改 hash |
| 同一装配中的再次证据读取 | `coverage_matrix.require_matching_truth`，`:997-1002` | 比较 evidence_source/evidence_health/closure_projection，已有一致性判定 |
| Checkpoint / Pack / Surface | `checkpoint.py:1088`、`context_pack.py:1348`、`surface.py:1102` | 已调用该一致性判定 |
| Resume | `runtime_state.py:1295-1360`、`resume.py:198-323` | 从同一 Coverage 构造 tested/untested，检查 Store binding；没有另一次同样的证据拼接需要复制 guard |

## F1：Closure 混合两次不同的证据状态（已复现）

`tools/autopilot_state.py:3526,3549-3553` 先读取 Coverage，再读取 current truth，却未调用
已有的 `require_matching_truth()`。`_owner_source_markers()`（`:1282-1308`）只绑定 Store
身份/版本和若干 owner 控制文件，不绑定所有已登记 raw 文件。私有证据的字节变化不增加
Store revision，也不改变这些 marker。

运行命令（基线专用，脚本只在 TemporaryDirectory 中造数据）：

```bash
PYTHONPATH=. python3 .trellis/tasks/09-28-coverage-closure-fact-contract/research/reproduce_mixed_evidence.py
```

结果：退出码 0，两种方向的断言全部成立。

| 操作发生于 Coverage 与第二次 truth 读取之间 | Coverage health | Closure health | Store / marker 变化 | 返回 digest / snapshot_stale |
|---|---|---|---|---|
| 改坏已登记原文件 | ready | partial | 均无 | true / false |
| 恢复已登记原字节 | partial | ready | 均无 | true / false |

同一真实输入交给现有 guard，均抛 `StoreError: primary coverage evidence changed during
assembly; rebuild the view`。因此不是 hash 设计问题，而是 Closure 漏用一致性契约。
两次 `can_claim_exhausted` 都为 false；**没有证明错误耗尽或虚假漏洞结论**。证明的是
公开快照混合了不同时点的事实，且没有被标记为过期，不能把它当成一致的复核依据。

## 恢复语义不能为小改动让步

仅插入 guard 并传播普通 StoreError 会丢失这条竞态原有的有界恢复机会：

- `tests/test_autopilot_state_tool.py:6082-6100` 明确测试读取中 Store revision 变化原来成为
  `state_snapshot_stale`，而不是直接异常。
- CLI 的两次尝试位于 `tools/autopilot_state.py:4439-4480`；round coordinator 的两次尝试
  位于 `tools/autopilot_round.py:49-88`。普通 ValueError 会直接退出它们。
- Checkpoint 的 `record_global_review` / `record_round_closure` 在装配后才写 witness
  （`tools/checkpoint.py:556-629,633-723`），检测失败应在任何写入前向上抛出。

因此方案采用 owner 定义的可区分一致性异常，并让**已有** CLI/coordinator 重试循环识别它。
不捕获所有 StoreError、不匹配异常字符串、不新增重试框架。直接 loader 拒绝混合输入；
面向恢复的入口最多重新装配一次。稳定损坏（两次都 partial）仍走原 store_partial 诊断。

## 已有能力证据与边界

同一 HEAD 的上一切口已实跑 36 项定向回归，包括时间/full/bounded 稳定性、真实变化失效、
Surface 证据变动和三个 pickup CLI 的完整展开；本轮没有把它重复报告为新测试。
`tests/test_checkpoint.py:199-250,709-748` 另有 12 条待办完整展开和 lane 恢复/幂等回放测试，
本轮按源码核对，安排在改后定向验收中执行。

本修复只覆盖两次已取得输入之间可检测的不一致；不会让文件系统成为事务，也不保证最后
一次校验后再发生的变动被提前预知。未发现的新疑点不纳入本次修复。
