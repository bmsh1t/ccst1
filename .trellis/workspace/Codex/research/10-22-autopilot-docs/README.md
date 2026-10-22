# Autopilot 文档精简验收

2026-10-22，基线 `eebaa01`，分支 `refactor/10-11-capability-architecture`，
实现 checkout 为 `ccst3/ccst`。用户要求文档优化，能力优先。

## 改动与保留

| 活动文档 | 原字节 | 当前字节 | 减少 | 内容变化 |
| --- | ---: | ---: | ---: | --- |
| commands/autopilot.md | 10,326 | 10,211 | 115（1.11%） | 合并当前记忆复用、owner 展开与继承判断的重复说明 |
| agents/autopilot.md | 10,481 | 9,261 | 1,220（11.64%） | 使用现有 handoff 内容包，精简重复方法/执行路由说明，明确完整方法先于首请求 |
| docs/ccst-runtime-adapter.md | 4,796 | 3,760 | 1,036（21.60%） | 材料、恢复、方法读取、执行接口引用现有完整 owner 合同，保留来源与历史 |

这三份活动文档合计 25,603→23,232 字节，减少 2,371 字节（9.26%）。
CLAUDE.md 与其 13 个 imports 常驻合计 141,888→140,852 字节（0.73%）；
可选专家不会默认加载，因此其减少量不能算作默认启动收益。bytes/chars 不等于 token，
也不能证明模型费用或调查效果变化。

保留命令/agent frontmatter、动态 Bootstrap、critical manifest、完整 Shared Automation H2
及 lane 标题/章节边界。主命令的 Investigation Skill、State Consumption Loop、Execution
Invariants、Transition And Finish Contract 保持原文；round、CLAUDE.md、完整 6k 规则、
runtime-protocol、src-hunter（含 description/矩阵）及 lane 正文未改。
专家的 owner 写入边界与结果格式、adapter 来源与历史保持原文。

开发契约补充：压缩后引用必须指向仍含完整约束的真实章节；分别测量常驻、命令、按需 lane
和可选 agent；不能由文档字节推导实际模型行为收益。

## 验证

```bash
python3 .trellis/workspace/Codex/research/10-22-autopilot-docs/check_document_contracts.py
```

约 0.42 秒完成，结果见 [result.json](result.json)，保留三份活动文档 SHA-256。

- 在临时源码副本执行真实纯 Markdown lane 提取函数，比较每个选中 section 全文。
- 原文比较保护 frontmatter、Bootstrap、manifest、主调查/结束合同与 round/6k 加载链。
- 39 个 Markdown 引用验证路径存在及提供的 section anchor；此数量包含普通路径链接，
  引用可定位不单独证明语义保真。
- 使用当前源码和完整合成 ownership receipt，在临时 runtime 执行真实 `compare_runtime`；
  source inventory、critical manifest 均通过。没有运行安装器或同步个人 runtime。
- `git diff --check` 通过；两位一次性只读探子分别复核能力合同与接口/验收，未发现阻断。
  主线程亲读并检查修改文件与关键约束 owner。

首次 runtime 夹具未写 ownership receipt，被产品拒绝为 unowned native entry；只补齐夹具，
产品校验未放宽。最后修正验收输出的引用统计表述，没有改变检查逻辑。

## 限制与状态

未读取或运行项目 tests/，未修改原方法、真实目标/报告/知识审核或个人 runtime，未安装依赖，
未做付费模型验收或完整安装器执行。静态/接口验证不证明模型能力完全无损，也不承诺实际
token、美元费用或耗时下降。此前真实宿主 compaction 恢复限制仍保留。

建 Trellis 任务的可选确认未收到回复，本轮未创建任务或修改旧任务状态；验收记录保存在
workspace research，不归档旧记忆任务、不 push。
