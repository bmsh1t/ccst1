# 全仓架构与质量审核

## Goal

对当前项目进行证据化、可复现的全仓只读审核，明确真实缺陷、运行风险、架构债务和测试盲区，
给出按严重度、修复收益和依赖关系排序的治理建议，而不是以文件大小或抽象偏好推动重构。

## Background

- 仓库为单包 Python/CLI 项目，核心入口与协调逻辑主要位于 `agent.py`、`brain.py`、
  `tools/hunt.py` 及 `tools/` 下的 runtime/state owner。
- 状态边界包含 Runtime State、Autopilot State、Target Case State、Evidence Ledger、Finding、
  Checkpoint 和 Action Queue；审核必须验证 owner、身份、原子写、损坏输入和重放收敛契约。
- 知识链包含 cards、registry、candidate、lifecycle、value review、recall 和 capability governance；
  审核必须区分 advisory collision、治理错误和真实召回退化。
- 当前 `main` 相对 `ccst1/main` 领先一个已提交的召回治理提交，同时工作树另有 27 项未提交改动，
  涉及 runtime 文档、知识卡、Action Queue、Checkpoint、Context Pack、scanner、测试及新工具。
- 审核以当前工作树为主，并逐项对照 `HEAD`；正式问题必须标注为 `HEAD`、`WORKTREE` 或
  `BOTH`，从而区分已提交缺陷与未完成改动风险。
- 已知边界包括 `hunt.md` runtime drift advisory、协调器体积与耦合、Legacy 双入口，以及多 owner
  最终一致性；这些是待复核线索，不预设为本轮 findings。

## Requirements

1. 建立仓库职责图：入口、协调器、状态 owner、知识治理、外部工具、测试和文档契约之间的边界。
2. 审核关键数据流：输入与 scope -> recon/surface -> hypothesis/action -> validation/evidence ->
   finding/queue/checkpoint -> context/knowledge recall，验证身份、schema、错误传播和重放语义。
3. 审核所有核心持久化路径的原子性、锁粒度、损坏 JSON 行为、临时文件清理和直接覆盖写入。
4. 审核运行时契约、命令/工具索引、打包依赖、runtime doctor 漂移及 Legacy 兼容边界。
5. 审核知识卡触发、排序、预算、召回原因、candidate/lifecycle 晋升和治理门禁，区分 error、warning
   与 advisory。
6. 审核安全与可靠性边界：命令执行、路径处理、凭据/敏感信息、外部输入、失败降级、超时和并发。
7. 审核测试有效性：关键 invariant 是否被真实行为测试覆盖，识别 tautological、只测 mock、缺少
   负向/故障注入、与生产入口脱节及未覆盖的跨 owner 契约。
8. 审核依赖、重复实现、死代码、隐式 fallback、第二真相源、文档漂移和高耦合技术债；不因文件
   行数本身提出拆分。
9. 每个问题必须包含严重度、可信度、用户影响、根因、`file:line` 证据、验证方式和最小修复方向；
   未经代码验证的猜测不得进入正式 findings。
10. 输出独立的已验证 findings、advisories、技术债、测试缺口和未证实线索清单，并给出 P0-P3
    治理顺序及可拆分批次。
11. 审核过程只读生产代码；不得回滚、格式化、暂存或混入当前用户工作树改动。
12. 审核开始和结束时记录 `HEAD`、dirty path 清单及 diff 摘要；若期间工作树变化，必须重新
    标定受影响证据，不得把并发修改误归因于原始基线。

## Acceptance Criteria

- [x] 形成覆盖入口、状态、知识、运行时、外部集成、测试和文档的架构/数据流地图。
- [x] 所有 P0/P1/P2 findings 均有可点验的 `file:line`、实际调用链或最小复现证据。
- [x] 对已知 runtime drift、trigger collision、最终一致性、协调器和 Legacy 线索逐项给出复核结论。
- [x] 对核心状态 owner 和跨 owner 重放矩阵给出覆盖结论，不把 advisory 误报为行为缺陷。
- [x] 运行与风险匹配的静态门禁和目标测试；记录通过、失败、环境阻塞及其归因，不为通过测试修改代码。
- [x] 最终报告按“已验证问题 -> advisories/技术债 -> 测试缺口 -> 整改批次 -> 残余风险”组织。
- [x] 当前用户改动保持原样，审核任务除 Trellis 规划和报告外不产生项目代码 diff。
- [x] 每个正式问题均标注基线来源 `HEAD` / `WORKTREE` / `BOTH`，工作树漂移得到显式记录。

## Out of Scope

- 在审核阶段修复发现的问题或进行全仓重构。
- 删除/移动 Legacy 入口，拆分大型协调器，或引入数据库、事件总线、全局 writer/transaction 抽象。
- 对真实目标执行扫描、验证或任何外部网络测试。
- 将 advisory 自动升级为缺陷，或仅凭测试通过宣称实现正确。
