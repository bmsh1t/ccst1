# C5 G2 Owner Continuity Review

日期：2026-10-13。状态：**partial / bounded engineering review**。

本次只复核既有源码与 E2/G2 证据，不修改产品代码、不新增测试设施、不重跑已经接受的
E1/E2/F1，也不把合成恢复写成真实目标恢复。

## 复核范围

确认以下链路是否保持同一 owner、同一当前性绑定以及显式失败语义：

- schema、migration receipt、archive fence、切换后新写入、坏索引/缺模型和用户修改 runtime；
- Context Pack、Resume、Autopilot、Target Memory、Experience Recall 和 counterevidence 的读取归属；
- `partial`、`unavailable`、`error` 是否保留当前事实，而不是投影为 `clean`、空历史或已完成。

## 结果

| ID | 结论 | 证据 | 边界 |
|---|---|---|---|
| G2-OC-01 | **covered, bounded** | `e2-evidence-acceptance.md/json`、`migration-rehearsal.md`、`rollback-rehearsal.md`；`tools/target_migration.py:1472-1500` 在 archive receipt 完整前不删除原件，`tools/migration_receipts.py:155-222` 固定 receipt、manifest 和 archive fence | 仅隔离合成；没有真实目标 writer 或真实切换 |
| G2-OC-02 | **covered by source inspection** | `tools/target_memory.py:151-212` 从 `runtime_store` 生成目标记忆投影；`tools/context_pack.py:843-935` 取得同一 Store binding 并在组装后复核；`tools/resume_read.py:148-262` 读取 Store/目标记忆并在返回前复核 binding | 本次没有新增跨入口运行回放 |
| G2-OC-03 | **covered by source inspection** | `tools/autopilot_state.py:1207-1363` 先复用 Resume、Queue、runtime 和 Surface owner；`tools/autopilot_state.py:1484-1563` 只投影 owner-backed continuation；不建立第二状态写入者 | Autopilot 全量能力仍不等于 C5 G3 能力验收 |
| G2-OC-04 | **covered, bounded** | `tools/experience_recall.py:130-177,252-270` 使用当前 Store/source binding；`tools/recall_context.py:42-53,141-200` 对不可用根保留显式记录；`tools/target_store.py:1245-1253` 要求 exact Store binding | 未声称真实跨入口恢复演练 |
| G2-OC-05 | **covered, bounded** | `tools/current_truth.py:63-132` 将损坏/截断 Store 投影为 `partial` 并抑制受影响 closure；`tools/context_pack.py:338-392` 保留本地材料诊断；`tools/recall_index.py:375-422` 分区失败返回 `partial/unavailable`，不覆盖 owner | 缺模型路径是合成覆盖；F2 真实 encoder/reranker 未验收 |
| G2-OC-06 | **covered, bounded** | `tools/recall_index.py:205-219` 将坏/缺 generation 标为不可用或 stale；缺 encoder 时保留 previous generation；`rollback-rehearsal.md` 记录坏索引/缺模型恢复路线 | 没有下载或运行真实模型 |
| G2-OC-07 | **covered, bounded** | `tools/runtime_doctor.py:326-430` 通过 ownership manifest、原文件 hash 和冲突列表保护用户修改；`current-engineering-handoff.md` 记录 59 文件临时装配 clean | 未执行用户个人 runtime 或全局安装 |
| G2-OC-08 | **covered, bounded** | `migration-rehearsal.md` / `rollback-rehearsal.md` 的 `post_commit_new_writes` 保留当前 primary/WAL/Store binding，不恢复旧 metadata | 只是合成 post-commit 场景，不能替代真实 writer 演练 |

## Owner 结论

| 领域 | 唯一当前 owner | 读取/投影层 | 结论 |
|---|---|---|---|
| 目标状态、Action、Observation、Experience、Finding | `TargetStore` | Target Memory、Resume、Context Pack、Autopilot、Recall | 投影不拥有写入权；没有第二 Store |
| 当前证据 closure | `current_truth` + `TargetStore` | Context Pack、Coverage/报告消费者 | `partial` 会抑制 closure，不会变成 clean |
| 共享知识 | registry/review/source owner | Context Pack catalog、Recall knowledge partition | 不可用或未审源保留健康状态，不伪造已召回 |
| 派生索引 | `recall_index` generation owner | lexical/semantic query | generation 可失效或重建，不能回滚 primary owner |
| runtime 文件 | `runtime_doctor` ownership receipt | install/compare/sync | 用户修改产生 conflict，不能被 prune 覆盖 |
| 迁移与归档 | `target_migration` + `migration_receipts` | cutover/recovery | receipt、manifest、archive fence 先于删除 |

## 未覆盖与下一阻塞点

1. 当前 checkout 没有可迁移的 per-target Store，D1 仍为 `not_applicable_for_current_checkout`；
   不能从空范围推断其它部署根也为空。
2. E2 是有限工程接收，未执行真实目标迁移、全局 runtime 安装或真实新写入恢复。
3. F2 已按用户决策 `descoped / not accepted`；本地 encoder/reranker 语义能力没有验收。
4. G2 尚无一次覆盖所有入口的实时故障注入回放；已有 123 项回归、E1 45 项收尾和合成恢复证据
   继续有效，但不升级为完整 G2 或 G3。

## 决定

本复核没有发现需要新增产品修复的 owner 分裂或错误清洁投影。G2 继续保持
`partial`，`release_decision` 继续为 `not_ready`。下一阻塞点是 C5 的 G3 能力/默认评审以及
单独结算的 D1、G5、G6、G7；不启动后置 C2 蒸馏、盲答、知识晋升或模型实验。
