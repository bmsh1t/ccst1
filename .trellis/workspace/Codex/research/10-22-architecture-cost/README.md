# 架构与成本优化验收

2026-10-22。基线 `d8a91a1eaf0eb71758565279c385b000de2761e9`，分支
`refactor/10-11-capability-architecture`。实现位于 `ccst3/ccst`。

## 已完成

保留每目标单一 Store、原生模型判断和现有投影边界。修改 7 个生产 Python 文件、
2 个用户文档、2 个契约文档；没有新服务、依赖、schema 或持久缓存。

| 改动 | 合成验收结果 |
| --- | --- |
| Coverage 同次输入清单与内部指纹复用 | 40 URL：总指纹 3→2 次，输入清单 8→3 次，仍完整构建一次；固定 as_of 全 DTO 与基线相同 |
| Surface 提前拒绝旧 Store/revision | 明确 stale 时完整 manifest/truth 读取 1→0；同 revision 原件篡改仍被检测 |
| 文本检索只构造一次文档文本 | 250 条 4KiB 文档、12 个未命中词：序列化 3000→250 次 |
| 同次索引代和知识解析复用 | 双分区 query 各读一次 generation；重新校验分区 binding 和最终原件/fences |
| 来源链复用已校验直接节点 | 120 节点链、逐根求依赖：版本全文读取 7260→120 次；环、菱形、精确版本与外部 refs 不丢失 |
| 健康状态反向传播 | 链、菱形、有坏源/无坏源循环和 origin/basis 的完整 DTO 与旧实现一致；传播阶段 O(V+E) |
| handoff 与 claim 健康复用 | 页内 handoff 展开 2→1 次，页外仍保留；claim 版本展开仅一次 health；返回对象保持独立 |
| 关系分页推进 | setup 超时后允许一次有界状态推进；含循环/条件冲突的 7 页完成且无重复 cursor；首条路径超字节预算明确报错 |
| 接口导航 | 裸 help 展示 10 个现行命令、保留旧 help；target 文档补版本/来源/纠错参数；README 修正已退役工具与模型继承说明 |

所有次数为指定合成输入上的操作计数，不能换算成完整 Autopilot 延迟或美元节省。

## 验证证据与复现

```bash
python3 .trellis/workspace/Codex/research/10-22-architecture-cost/check_architecture_cost.py
python3 .trellis/workspace/Codex/research/10-22-architecture-cost/check_memory_compatibility.py
```

- [新增验收](optimized-result.json)：16 个场景全部通过，其中 27 组 FTS/缺失索引/损坏索引、
  中文、空串、标点等完整结果对照；包含文件/Store 竞态、来源坏哈希、同 revision 字节变化、
  旧游标拒绝和页外 handoff。
- [兼容验收](memory-compatibility-result.json)：复用已有研究配方，16 个场景、168 条断言通过，
  约 18 秒；覆盖保存、纠错、撤回、旧版本、1000 条记录、跨进程读取和启动恢复视图。
- 两份结果保留生产源文件 SHA-256，主线程确认与最终实现一致。
- 三个独立只读探子分别复核 Store、Surface、检索/分页，未发现阻断项；主线程完成最终
  diff、Python 语法与相关 spec 检查。
- 原件篡改夹具首轮因错误归属路径被 Store 拒绝；仅修正合成路径后通过，未放宽产品校验。

脚本归档固定基线的 `tools/`、`memory/` Python 源码并覆盖本次生产文件，在临时目录创建
合成 Store 和私有 runtime。audit guard 禁止读取原 checkout 数据、项目 tests、个人配置和
网络；已有记忆验收配方仅在隔离环境运行。输出固定 `/tmp` 文件仅作本地诊断，可随时删除。

## 剩余限制

Coverage 仍读取完整输入；召回仍为完整候选排序与准确余量扫描。来源链优化去除了重复
SQL/解析/hash，但各根仍独立遍历内存图，最坏仍可能平方增长；未引入跨请求 closure 缓存。
关系图准备时间仍计入预算，允许超时后一次推进；这是软时间边界，边/深度/路径/字节限制保留。

本轮没有新付费模型运行、真实目标/真实知识修改或大规模长期实测。未读取/运行项目 tests，
未改原 6k 方法、宿主恢复规则或个人 runtime。以前宿主压缩续接的失败结论仍保留；本轮
工程验收不证明该行为已修好，也不承诺模型费用下降。

建 Trellis 任务的可选确认未收到回复，未新建或修改任务状态。验收资料保存在工作日志目录；
不归档旧记忆任务、不推送远端。

原始只读审计见 [audit.md](audit.md) 与 [baseline-result.json](baseline-result.json)。此前
固定模型会话的成本复算见 [prior-model-cost.json](prior-model-cost.json)，包括恢复续接合计
$2.772660，为 CLI list-price 估计，非本轮开销或供应商账单。
