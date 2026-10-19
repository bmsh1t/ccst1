# ccst 两轨规划历史摘要（2026-10-14—15）

> 当前状态（2026-10-19）：6k 与 cleanup 已交付，不再处于 planning，也不是待重做能力。
> 6k 原任务见[归档 PRD](.trellis/tasks/archive/2026-10/10-14-6k-full-integration/prd.md)。
> 后续权威范围见[审核与文章吸收](.trellis/tasks/10-18-audit-learning-convergence/prd.md)，
> 既有增量的逐路径处置只记在[15 项 WIP 清单](.trellis/tasks/10-18-audit-learning-convergence/research/wip-inventory.md)，
> 当前由[B 收口任务](.trellis/tasks/10-18-wip-closeout-alignment/prd.md)实施。
> 下文保留当时决策与顺序，不代表当前授权；19/79 是历史快照计数，不能用于恢复或丢弃当前 WIP。
> Track 2 的卸载个人 runtime、去注册、固定 token 门槛与冷命令退役不自动启动；
> B 只审核入口保真和既有增量，C 分开验收机械恢复与另行授权的宿主消费，不以旧瘦身建议代替新设计。

历史版本：v2（2026-10-14，主会话审核版）。以下为原规划摘要、审核结论与两轨关系，非当前执行清单。

---

## 1. 优先级（prd 权威）

**能力完整性与实际效果 > 架构职责清晰 > 使用成本 > token 或文件数量**

---

## 2. Track 1：6k 完整接入（历史规划，现已归档）

### 范围摘要（R1-R6）

| 条 | 核心 |
|---|---|
| R1 完整内容与实际生效 | 62 源文件（AGENTS 1 + rules 11 + src-hunter 50）完整正文迁入，不以摘要/蒸馏卡替代；通过当前调查入口实际可发现可执行；保留来源与缺损记录；迁入后运行不依赖 `/root/out` |
| R2 单一决策与能力保留 | 主会话唯一调查控制器；重叠方法职责明确衔接不竞争；保留本项目独有专项/工具/执行器/恢复能力；调查不强制先经 Recon/scanner/Queue/Autopilot；开发治理与调查运行分开 |
| R3 记忆与连续性 | 事实恢复/经验召回/写回/handoff/来源展开/纠错全保留；目标数据、schema、实体标识、历史版本、原始证据、恢复收据不迁移不清空不重建；跨目标种子进度不丢 |
| R4 结果保存与复用 | 中性原生观察有真实证据与记忆接线；不建占位 Finding；浏览器素材与完整实验取证区分；登记重试不重放动作；方法差分可保存、回写唯一正文、版本可追溯 |
| R5 三方择优 | 2.3 参考不限字段（方法组织/专家分层/宿主适配/交接机制）；不照搬重复控制器/平行账本/未核实工具能力；已接入的 cleanup、degraded、advisory、reframe、指标增量不回滚 |
| R6 可控切换 | 保留现有命令与 owner 语义；主入口/记忆接线/消费者就绪后整体切换；安装/同步/提交/模型下载/真实目标操作不在本轮授权内 |

### 验收（A1-A9，摘要）

62 文件唯一去向+来源记录、运行不依赖 /root/out；完整方法实际可用且无第二控制器；原有 owner 与数据不破坏；切换与续接后目标内事实/handoff/跨目标活面可恢复；中性观察与方法差分接线成立；恢复/cleanup/发布语义保持；宿主归属清楚；用最小临时隔离材料验证，不新增测试文件或 benchmark 设施。

### 本会话实测事实（审核依据）

- 6k 快照已 bundled 于 `knowledge/methods/clown/`（53 条目，`root_env=CCST_CLOWN_SNAPSHOT`），运行资产（CLAUDE.md/rules/skills/knowledge/commands/docs/tools）零 `/root/out` 引用
- 6k 源目录 `/root/out/clown-src-6k-skill` 完好可读；4 个已入库方法文件尺寸与源一致（dig-scope 64637B / hunt-iter 15019B）
- prd 声称「白盒规则快照存在正文拼接缺损」——尺寸一致≠内容完整，接入时须逐文件内容级校验
- 工作树现有 **19 个未提交脏文件** = 并行会话在途接入增量（CLAUDE.md、rules/campaign|context-loading|hunting、skills/runtime-protocol、knowledge manifest/capabilities/index、tools/capability_profile|validate|validation_runner|report_generator|context_pack|hot_method|autopilot_bootstrap|target_store、docs/tool-index、.trellis spec 两份）

---

## 3. 边界四张表

### 迁入

62 源文件全量：完整正文、短表、知识模块、适用条件、反例、调查节奏与迭代要求。每个文件唯一去向 + 来源记录；缺损与适配明确说明，不声称适配后仍与源逐字相同。完整保留≠每次全量加载——遵循 6k 短表 + 相关模块按需展开。

### 保留

ccst 记忆与事实内核全量（R3 清单）；R4 全部操作语义；已接入增量（cleanup/degraded/advisory/reframe/指标）；现有命令与 owner 语义；工具面与恢复能力。

### 冲突（design 输入）

| # | 冲突 | 衔接方向 |
|---|---|---|
| **D1**（阻塞 design） | 方法正文写入权限：6k hunt-iter 当轮直接改唯一短表 vs ccst 候选+人工审核晋升 | **推荐方案 A**：门槛内（6k 明确门槛+三问）单会话直接增补唯一活动方法正文；低于门槛/来源不完整/子代理产出/涉及共享卡片与规则架构 → 候选+审核；保留版本与来源记录，不写目标私有事实 |
| ① | CORS：6k 硬排除 vs `hunting.md:33` 不设仓库级禁令 | 目的地策略：类别照测，单独 CORS 默认不投 CN SRC（Q7 目的地资格承载） |
| ② | 「rules 不能限制能力上限」 vs 七问门/coverage/never-submit 硬门 | 边界声明：反限制适用于打法思考，不适用于证据判定（未过门不得称 Finding） |
| ③ | 交付报告：6k 两张表 vs report-writer 四要素 | 两张表为交付模板，保留证据 manifest/SHA-256/零凭据纪律 |
| ④ | R2「不强制先经 Recon/Queue/Autopilot」与 autopilot bootstrap 门 | design 期明确：不强制≠移除，是入口前置自由度 |

### 退役

**无内容退役**（本会话上午版本对 security-research-context/playwright-browser-mcp/desktop-task-folder 的选择性退役取消——全量保留完整原文，避免「等价覆盖」判断错误的风险；三件为零运行时成本文件材料）。仅退役 2.3 形态：重复控制器、平行账本、固定评分选路、未经核实的工具能力。

### 明确不做

全面改写 tools；删除尚有消费者的工具；批量改名；追求文件数量指标；新数据库；平行知识正文库；第二调度器；固定评分选路；自动模型安装；全量 benchmark；占位 Finding；覆盖 Trellis 管理资产或用户配置；将创建规划任务视为实施批准。

---

## 4. 裁决与冲突状态（2026-10-15 更新）

| # | 决策 | 状态 |
|---|---|---|
| D1 | 方法正文写入权限 | **已裁决：方案 A**（含细化：子代理只提交拟进/拟补，主控重新核对同一门槛后才可写入；治理参考/共享卡/编排仍走人工审核） |
| ① | CORS | 已解决：来源永久禁令仅存档（S62），不导入；hunting.md 保留类别推理能力 |
| ② | 反限制条款 | 已解决：表外方法与原生推理仍可用；短表命中必须展开完整方法 |
| ③ | 交付报告格式 | 已解决（保守路线）：vuln-report-format.md 仅作 6k 方法准入的来源参考，不接管 C 报告/定级 owner |
| ④ | R2 门禁衔接 | 已解决：不强制先经 Recon/scanner/Queue；autopilot 保留预算/回收职责 |

## 4.1 规划工件状态（2026-10-15）

任务 `10-14-6k-full-integration` 工件齐备：prd（D1=A）+ design 36K（v2 方法协议/A 维护/原生观察/浏览器基线/S-F 隔离切换）+ implement 24.7K（B1–B6 批次 + V1–V7 行为验收 + 环境白名单）+ 研究台账（62 来源处置矩阵、2.3 逐文件差分 123 项、三方能力矩阵、原文加载图）+ 两轮审核（final-plan-review + plan-recheck 六项修正：2 P1 + 3 P2 + 1 P3，均已落进当前设计）+ 窄静态核验通过（hash 一致/渲染完整/链接有效/脏树基线不变）。

## 4.2 主会话终审结论（2026-10-15）

**方案达到可批准状态。** 独立核验：D1=A 全链传播（design §4.1/§4.3 ↔ implement B2）；六项复审修正均在当前文本；62 项处置完整（6 条宿主规则=存档+provenance+映射既有 owner+显式不导入条款，优于退役或全量激活）；prd↔design↔implement 一致（R1-R6→设计节，A1-A9→V1-V7）。

批准前三项建议（可选）：
1. **基线提交授权**：脏工作树（19 跟踪 + 未跟踪目录，复审按文件计 79 项）目前仅靠 before-bytes 快照保护，git 层零保护窗口在拉长；实施启动前批准一次基线提交同时服务 R5 增量保护和 Track 2 顺序
2. **个人 runtime 误安装事件处置**：`~/.claude` 污染未恢复（规划明确不碰）；宜单独决定恢复或留给 Track 2，勿跨实施期
3. **B6 维护窗口机器独占**：设计自认「不能保证排他前提时不启动发布」——切换期间机器上不能有其他会话碰 ccst3（含本会话）

已知未证明边界（设计自行声明，非缺陷）：白盒缺损原文不恢复；2.3 延期方法效果未验证；V1-V7 全在合成 fixture 上，**在线调查效果需 lab/实弹另证**。

---

## 5. Track 2：运行时瘦身（后置，Track 1 收口后启动）

本会话上午定稿、prd 明确后置（「先接入，再按实际问题优化」）：

| 包 | 内容 | 验收硬线 |
|---|---|---|
| P1 运行时重构 | trellis 退出运行时；`.claude/commands`+`agents` 链接仓库源；skills 去注册（已验证零 Skill 工具使用）；`~/.claude` 卸载 | 单一源；`~/.claude` ccst 资产=0；新会话命令/代理可发现 |
| P2 入口压缩 | CLAUDE.md 8.7K→≤5K（6k 风格：路由表/备忘/一行式冲突消解） | 入口 ≤5K token；lab 靶场行为无回归 |
| P3 2.3 四件 | degraded 标记 / unknown→最小探针投影 / cleanup 门 / reframe 卡（部分已在 Track 1 脏文件中在途） | 每件一次性行为验证 |
| P4 冷命令清点 | 38 命令→热集（可选） | 路由引用完整 |

**顺序硬约束**：Track 1 的 19 个脏文件先收口提交 → D1 裁决 → design.md → implement.md → 批准实施 → 全部提交 → 才启动 Track 2。CLAUDE.md、rules/hunting.md、knowledge manifest 是两轨共同表面，乱序执行 = 同一批文件被两个任务先后改造（churn）。

---

## 6. 审核结论（本会话对 prd 的审核）

**方案成立，采纳为权威范围。** 四个点优于本会话上午版本：

1. **D1 方法治理决策**——上午版本未覆盖的真冲突（6k 当轮迭代节奏 vs ccst 审核晋升）
2. **62 文件全量保留**优于选择性退役——三件「等价覆盖」判断有错判风险，保留完整原文零成本更安全
3. **R4 操作深度**（中性观察/方法差分回写/重试不重放/不建占位）——6k 真实工作流需求
4. **授权边界 + A9**——planning≠实施批准、无测试设施、不动 Trellis 资产

注意点（design 期处理）：
- 19 个脏文件须先收口提交，避免基线漂移；R5「已接入增量」与脏文件清单的对应关系收口时核对
- 快照缺损做内容级校验（尺寸一致≠完整，prd 自证）
- R2 门禁衔接（冲突④）明确后再动入口

---

## 7. 当时的状态与下一步（历史，不再执行）

```
[2026-10-15] planning，工件齐备，D1=A 已裁决，二次复审六项修正已落，主会话终审通过
  ↓ 用户最终实施批准（建议先做 §4.2 三项：基线提交授权 / 个人 runtime 处置 / B6 机器独占确认）
task.py start → G0 门槛（WORK/S/F 隔离准备）
  ↓
B1–B5 在 S/F（reader v2 → 来源台账 → 入口目录 → 原生观察/浏览器 → 记忆/campaign）
  ↓
B6 维护窗口切换（停消费者 → 兼容代码 → C 实际 bootstrap → 入口/Rules/critical 清单 → 回读一致）
  ↓
V1–V7 行为验收 → A1–A9 汇总 → 提交授权（另行批准）
  ↓ 全部提交后
Track 2 瘦身（P1→P2→P3）→ lab 靶场实弹效果验证 → night-watch N0
```
