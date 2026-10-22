# 技术设计

## 边界

依据父任务 research/memory-acceptance-result-20261022.md。主线程负责实现与最终验证；子代理仅探索和只读复核。用户方案已批准；本设计细化实现，不增产品范围。

1. 原生入口：临时 private runtime command 产生本地 argv/marker 回执，区分预展开与模型 Bash 重演；只留可见数据。发现入口问题先定位，不用强塞答案掩盖。
2. 恢复：compact_autopilot_state 保留 resume_summary.target_memory 及 source_binding，复用五条窗口；不第二次查 Store，不取 raw_active。列表无单目标恢复，恢复字段不得改 gate/next_action。现有 CLI/Shared Memory Continuity 指明恢复字段和按需 owner 查询。
3. 文本召回：_query_partition 在语义融合前合并 FTS 排序与 fresh substring 额外候选，FTS优先、额外按现有source-order追加；通道与排序digest反映真实来源。无索引继续原有机制。
4. 摘要：Context Pack 的经验 anchors 在正文前保留状态/适用条件/来源ID与按ID展开入口；防止 resume 再裁切吞警告。完整 provenance仍归 target_memory 现有formatter，不新算review_state。
5. 蒸馏：保留 current_truth 的当前health及有限 observation预览；通过 target_store 现有 page(operations)/execution 加薄CLI接线提供完整历史起点和按ID展开。明确 operation ID升序与观察预览顺序不同，不能把该cursor当观察下一页。当前原件校验继续通过 verify_operation/current_truth，不以历史bytes证明当前健康。

预期产品文件：tools/autopilot_bootstrap.py、recall_index.py、context_pack.py、target_store.py、distill_target.py；如需处理二次摘要截断涉及resume.py。必要调用文档commands/autopilot.md、runtime-protocol.md、commands/distill.md、架构与对应spec。同层调用与实际CLI验收，不读tests。

## 验证与兼容

旧Store schema不变；只加投影字段和operations只读CLI。失效cursor拒绝，索引无需自动重建。新增入口不写状态。旧历史保留，条件纠错不全球替代。所有模板/活动调用按搜索同步。
