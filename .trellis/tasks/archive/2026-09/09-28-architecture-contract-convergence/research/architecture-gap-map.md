# 需求复核（基线 846670c）

原始要求见 archive/2026-09/09-20-native-first-practical-optimization/prd.md；完成归属以该任务 research/final-delivery-20260926.md 为准，旧规划空框不是当前缺口。

| 要求 | 当前 owner 与已交付证据 | 本轮剩余结构检查 |
|---|---|---|
| R1 原生认知 | native_judgment_boundary / neutral_surface_selection / direct_only_skill_contracts | 不新增固定路线、价值排序或 Agent runtime |
| R2 单一领域责任 | target_store；Case/Action/assessment/delivery/report 分离；writer-inventory.md | 领域核心依赖只有 evidence_identity、scope_context、target_paths；消费者层存在五组反向环，需消除 |
| R3 事务/故障 | Store 原子事务、fence、幂等；target_store/target_migration tests | 不改 Store；外置普通发布初查九个同形实现，完整逐项核对后共归一 40 处，权限/失败不可减弱 |
| R4 开放类别 | evidence_identity、Store/Runner 的 observation；canonical Coverage 单独授权 | 共享 wire vocabulary 从执行器迁到纯契约，类别/事实判断不变 |
| R5 技术/交付 | Store assessment 与 delivery/report 分层，validate/decision_scaffold | 骨架反向导入 CLI 的 schema，迁到纯契约 |
| R6 显式副作用 | hunt/init 显式初始化；Checkpoint/Resume 查询不写回 | runtime 不再导入 browser publisher；状态不再导入 Resume CLI |
| R7 记忆闭环 | target_memory/experience_recall/Store；新进程与条件展开已有回归 | Resume 查询独立，保留完整窗口、来源与明确根绑定 |
| R8 完整访问 | revision-bound page、closure_projection/current_truth；D13/D14/D15 已修 | 不改分页/投影语义；复跑相应用例覆盖移动的读取链 |
| R9 Scope/信任 | scope_context/target_paths/private_artifacts；scope/auth/lock tests | Scope/路径互相依赖需单向化；私密/CAS/锁协议保留 |
| R10 与 M8 在线 | 固定 48 阶段已执行、收益未证实，用户接受 | 不重开在线试验；结构变化不宣称模型收益 |

M1–M7 工程闭环已交付。平台自动 compaction、活跃 writer 备份压力、AI 草稿质量及整体维护工时没有新的证明，本轮不把它们写为已测。

## 可复核静态基线

- 五个强连通分量：scope_context/target_paths；action_queue/browser_mcp_import/runtime_state；autopilot_state/checkpoint/resume；request_diff/validation_runner；decision_scaffold/validate。
- 九个相同 JSON writer：finding_index._write_finding_payload、action_queue、technology_inventory、intel_artifact、web_intel_artifact、target_memory.write_json、runtime_state、checkpoint、intel_sources。
- 两个相同的换行 JSON writer：surface_projection、surface_index。其他 writer 按格式/权限/多文件事务逐项检查，不按函数名强行合并。
- 旧 staged patch SHA256：8d9d6801cb745a626465a4fd20b4a43a20e4359fd6f9c1eff4177e3791a893ee。
- journal index SHA256：c37d7cac5eb10bd3847d32c82cbb632f1f8a94aae12690d740b53f347acf9c92；journal-1 SHA256：779a823ffbc902284d246067e9cccf39850af3ac27bf86892390e5f07f3c2cb2。

## 实施后的完整落点

40 个发布实现分布于 36 个模块，统一到 artifact_io；Runner 也直接使用共同实现。
保留 ASCII/排序/JSONL/流式绑定差异，保留私密、CAS、Store fence、独占快照、多文件顺序。
证据准入从 Action Queue 私有 helper 迁到 target_paths；公共观察文本校验从 Queue
迁到 contracts。两者不引入新 schema 或业务 owner。具体验证和测量见验收报告。

复核补齐内嵌发布：Request Guard、scanner pass、intelligence Markdown、ReconAdapter、
knowledge retire、OAST markers、Recon URL 流、migration 两处激活 receipt。共 9 处。
保留的替换协议：Scope CAS+目录 fsync、migration backfill receipt+目录 fsync、
Action/Validate/Report 不可变排他发布、Case 整组 staging、spray 指定权限写入；
repo_secret_scan 和 param_discovery 临时文件是执行输入/输出，不是可替换产物发布。
