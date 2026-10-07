# F10 执行计划

## 启动门

- [x] 两项独立探索完成；主线程亲读 owner、provider search、测试、消费者及架构契约。
- [x] partial 保全策略已收敛，PRD/设计/执行计划与真实 jsonl 上下文已建立。
- [x] 用户以“go”批准最终规划摘要；已激活既有任务为 in_progress。

## 顺序与范围

1. 批准后激活现有 F10，不创建重复任务。读取五文件范围的开发规范及确切实现，
   再核对两个查询 helper 的全部调用方。
2. 在 `tests/test_disclosed_pattern_dedup.py` 用真实 writer、fake client 与临时 cache 补
   最小失败回归；固定时钟和 tech hint，复现 total failure 毁旧 cache、partial 丢诊断。
3. 只改 provider search 的 envelope/节点消费点；mock `_graphql_request` 而非 provider
   输出，证明 malformed 不再变成成功空列表，合法空 nodes 与无 report 节点仍可用。
   对 report/team 的缺失、null、空对象保留兼容，对 `[]`、false、0、空字符串拒绝；
   至少一条真实 provider→owner 用例证明假值类型错误也不会覆盖旧成功 cache。
4. owner 保留每次请求结果与错误；实现 design 状态表、独立 cache 有效性/TTL 和准入。
   complete 才发布新成功 cache；复用已有 atomic writer，不修改其实现。
5. Markdown 传入材料来源／真实查询时间／过期与查询状态；同步 disclosed-researcher
   与 error-handling 契约，不改推理职责、增加判断器或扩展 CLI 协议。
6. 运行单条 focused 验收；主线程检查完整 diff，安排一次独立只读复核。若发现具体问题，
   只修范围内缺陷并重跑受影响用例，不因无关失败扩范围。
7. 更新 PRD 验收和本文件结果，展示准确五文件提交计划；用户确认后依次工作提交、
   archive、journal。不自动推送或启动 F11。

## 验收矩阵

| 条件 | 最小测试证据 |
|---|---|
| AC1 | stale cache＋全抛错／client None：旧报告可读，bytes/mtime/时间戳不变；无 cache 不新建 |
| AC2 | 所有请求成功为空可保存新空快照；健康 program-empty→keyword-hit 刷新继续成立 |
| AC3 | partial 有报告／零报告／fallback 成功：请求继续、诊断明确、不缓存、不混快照 |
| AC4 | fresh cache 不请求；固定时钟确认真实材料时间；no-mcp 预置 cache 仍完全跳过 |
| AC5 | provider 坏 envelope、owner 坏列表／记录、cache 坏编码／形状／时间、写失败保全 |
| AC6 | 真实 provider→owner→cache→Markdown 接线；原表顺序／recall／Store binding 不变 |

独立 healthy 请求的报告不可因其它请求坏值丢失。数据协议失败不是成功零结果；已知失败
cache 不能阻止重新查询。写失败用注入 replace 故障证明旧 cache/Markdown bytes 保留，
不重复 shared artifact_io 的完整协议测试。

## 验证命令与证据

单条行为验收（约 60 秒预算；主线程已运行，80 passed）：

```bash
python3 -m pytest -q tests/test_disclosed_pattern_dedup.py
```

另做本批 diff 检查。新增回归可先用相同文件的 `-k` 子集确认预期 red，再运行完整该文件。
不运行全仓 suite/build、安装、真实上游请求、真实 target/HOME 读写或 provider 线上 smoke。
所有网络入口用 fake client 或 mock `_graphql_request`，不依赖真实 MCP 连接。

## 当前状态

实现及全范围独立复核完成，用户已批准提交；两份上下文各三条，task.py validate 通过且无截断警告。
独立规划复核指出
falsey report/team 可掩盖坏类型；主线程已在设计和回归矩阵明确拒绝，保留缺失/null/对象
兼容。实现前 red 子集 2 failed；实现阶段新增子集 65 passed，随后 TTL=0 子集 2 passed。
主线程补齐直接 renderer 不推断查询成功、非有限 TTL 拒绝后，完整定向文件 **80 passed**，
`git diff --check` 通过。两项独立复核覆盖完整生产 diff 与测试／消费者／契约；唯一 P2
为非法 coverage_status 被当作历史兼容数据，现仅缺少字段时推导。新鲜坏 cache 增加
`{}` / `partial` / null 参数，主线程运行 `-k 'bad_cache or healthy_cache or failed_refresh'`：
**30 passed**，diff check 通过；其余无阻塞项。没有运行全仓测试、构建、安装或线上请求；
没有宣称最终 83 项整文件重跑。

2026-10-07 按用户“ok”执行五文件工作提交 `6245fb0`，随后归档；元数据绑定工作提交，
上下文引用改为实际归档位置。journal 独立记录，不推送、不启动 F11。收尾未修改产品代码
或重复行为测试，提交及归档 diff check 通过。
