# Govern recon budgets and autopilot state convergence

## Goal

修复 Deep recon 全局预算、完成态续跑与 scanner 噪声；治理 Intel/Queue 膨胀、Observation 外部来源、Ledger 归属、Journal 历史噪声和 Runtime 状态漂移，保持原始证据、兼容入口与既有能力。

## Requirements

- 为 `/recon --deep` 增加可观察、可中断的全局运行预算；阶段超时保留已有产物并发布 `partial`，不能继续无界执行，也不能复用旧的成功状态。
- 完成态路由必须以当前 Ledger/Finding/Queue/Intel 状态为准；旧 target-memory、静态 scanner 候选和历史 `untested_endpoints` 只能作为有界提示，不能重新驱动已闭环目标。
- Intel raw advisory 仍保留，但生成和 Queue 投影必须有条数、字节、时间预算、稳定去重和历史迁移策略；旧的缺 ID action 必须可诊断、可压缩，不影响当前可执行 action。
- Observation inventory 保留完整原始来源，同时将目标拥有、外部来源、扫描器元数据区分为不同事实类别；外部/原始材料不得凭 `untouched` 自动形成主动工作。
- Ledger 允许子域/服务独立归属，但父目标必须有可重建的 aggregate closure projection；不得复制或移动子目标原始 Ledger。
- Journal 读取必须隔离历史非法行的告警噪声，当前有效记录仍严格校验；不自动把损坏历史伪装成有效记录。
- Runtime session 状态必须能从 recon、finding、queue 及 scan/recon 结果派生出当前结论；历史 `scan_failed` 不得覆盖已完成的 recon/finding closure。
- 充分利用现代 AI 做语义 triage、跨证据关联、假设生成与轮换，不用静态扩展名/关键词列表替代模型判断；确定性代码只负责预算、身份、范围、持久化和完成门禁。
- 所有被降级或停放的 scanner/Intel/Observation 信号必须保留 bounded evidence packet、选择/停放原因和重新激活条件，使 AI 能在出现新证据时恢复深挖。
- 不引入数据库、事件总线或新 writer 抽象；复用现有原子 JSON 写入、Queue dedupe、Ledger summary、runtime derive 和 bounded projection 机制。

## Acceptance Criteria

- [ ] 全局 recon budget 超时会在下一安全边界停止后续阶段，`run_budget=partial`，旧成功 summary 不被复用；正常运行仍保持现有 raw artifacts。
- [ ] 已报告 finding、空 Queue、完成 Intel 的目标不会回到 `resume_untested` 或静态 bundle；有新证据的候选仍可进入 `hunt_p1`。
- [ ] Intel/Queue 投影在固定预算内稳定，重复刷新不增长；legacy 缺 ID action 不再成为当前 next action。
- [ ] Observation summary 对外部来源有显式分类/排除原因，主动候选仅消费 target-owned 或明确关联证据。
- [ ] 父目标 closure 能汇总子目标 Ledger，且子目标 Ledger 仍是唯一原始证据 owner。
- [ ] Journal 读取对历史非法行只产生一次有界诊断，不在每次 autopilot state 读取中重复刷屏；新写入仍 fail-fast。
- [ ] Runtime derived view 对 recon/finding/queue 完成态给出稳定结论，旧失败 breadcrumb 仍可追溯但不再错误驱动续跑。
- [ ] AI 每轮看到的是有界、可解释、证据锚定的候选包，而不是成千上万条 advisory/action；新证据可重新激活被停放信号，避免硬编码造成能力缩水。
- [ ] 相关 focused tests、`bash -n`、`git diff --check` 通过；不修改 `hunt.md` runtime drift。

## Notes

- Keep `prd.md` focused on requirements, constraints, and acceptance criteria.
- Lightweight tasks can remain PRD-only.
- For complex tasks, add `design.md` for technical design and `implement.md` for execution planning before `task.py start`.
