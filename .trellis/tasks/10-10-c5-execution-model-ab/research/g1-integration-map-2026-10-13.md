# G1 集成与父 AC 映射

日期：2026-10-13。范围：ccst3 当前 checkout 的 C0～C8 工程交付、能力验收和发布
边界。本文是 C5 G1 的接收映射，不是能力通过、默认选择或发布批准；不读取真实目标
数据，不运行模型，不启动知识候选晋升。

## 子任务状态

| 子任务 | 当前可接收内容 | 保留未完成项 | G1 判定 |
|---|---|---|---|
| C0 | 基线、协议和错误分母规则已形成 | 正式 A/K、held-out 与默认收益实验未开展 | `partial` |
| C1 | `src-hunting` 核心、旧入口迁移、消费者引用和工程接线已收口 | 行为守卫/全量回归/模型收益延后 | `engineering_accepted_behavior_deferred` |
| C2 | 既有正文承接、审核/晋升 owner、热方法只读接线、4 份 v2.3 draft | 完整源清单、真实差分、盲答和晋升后置 | `engineering_partial_content_deferred` |
| C3 | query/history 分流、入口/写回时机和共享协议接线 | F→E 行为收益、完整跨层验收和发布 | `engineering_accepted_behavior_deferred` |
| C4 | whitebox-audit、源码字节绑定和受控 partial 取证桥 | 正例/反例/部署错配的完整能力验收，F1 partial | `partial_not_accepted` |
| C6 | Experience provenance v15、来源/纠错/claims 工程链 | 全部来源 owner、复杂迁移/故障矩阵和完整恢复验收 | `partial` |
| C7 | FTS、分区、来源健康、索引代和失败语义工程接线 | 本地 encoder/reranker 未运行，语义能力未验收 | `engineering_partial_semantic_not_accepted` |
| C8 | relation v4、多跳/条件/反证、执行来源和共享 method_relations 接线 | 完整能力消融、增量并发/规模验收和默认选择 | `engineering_partial_capability_not_accepted` |

## 父 AC 映射

| 父 AC | 依赖与当前证据 | 当前判定 | 阻塞原因 |
|---|---|---|---|
| AC1 | C1 核心与 C4/C2 方法入口已存在 | `partial` | C4 能力、C2 完整方法利用和模型行为未验收 |
| AC2 | C2 审核/来源/单源正文及 4 份 draft | `not_ready` | 4 份 draft 未晋升，完整 clown 吸收和真实差分后置 |
| AC3 | C6 provenance、C8 消费者链、C5 E2 有界恢复证据 | `partial` | 全部 schema/迁移/真实数据范围和故障恢复未闭合 |
| AC4 | C6 correction/refutes/depends_on 工程规则 | `partial` | 完整来源失效传播、版本边和全矩阵恢复未验收 |
| AC5 | C7 词法索引与不可用/partial 语义接口 | `not_ready` | 真实语义编码器/重排器未运行，不能用 mock/CLI 替代 |
| AC6 | C4/C6/C8 已有身份、条件、来源和反证边界 | `partial` | 真实模型反例、跨场景拒绝和完整关系能力未验收 |
| AC7 | C5 E2 `accepted_bounded_engineering`、C6/C8 来源绑定 | `partial` | 当前 checkout 无 per-target Store；真实数据迁移与有新写入恢复未完成 |
| AC8 | H1 checkpoint、安装/退役 evidence 已有 | `accepted_bounded_only` | 只证明临时装配，未证明一次发布切换或全局安装 |
| AC9 | C0 协议与判据已冻结 | `not_started` | A–F/K、留出集、重复运行和默认组合未执行 |
| AC10 | 各 child 有 focused/隔离回执 | `partial` | 不将 focused 回执或用户延期的测试套件写成完整跨层回归 |

## C5 收尾包映射

- E1：`passed`，45 项相关回归和 1 项最终断言证据已存在；本记录不重跑。
- E2：`accepted_bounded_engineering`，安装文件/Store 依赖和 cutover backup 证据已存在。
- F1：`partial / not accepted`，保留因果/部署过推失败和旧原件。
- F2：`descoped / not accepted`，按用户决定不下载模型或依赖；C7 语义保持未验收。
- D1：`not_applicable_for_current_checkout`，当前 `state/` 无 per-target Store；不推断其他
  数据根为空，也不宣称真实迁移通过。
- H1：`committed`，工程检查点为 `c970a5b`；后续本批热方法/候选/规范提交另有提交记录。

## G1 结论与下一关

G1 的映射已完成，但 C5 不能据此关闭父任务：工程接收与能力、默认、发布四轴仍分离。
下一关是 G2 的恢复/错误来源/跨入口工程链核对；不重跑 E1/E2/F1，不启动模型实验，不恢复
C2 盲答或晋升。G3～G9 仍按原计划保留，发布状态继续为 `not_ready`。

## 证据来源

- `research/finite-closeout.md`
- `research/e2-evidence-acceptance.md`
- `research/f1-closeout.md`
- `research/f2-descope-record.md`
- C1/C2/C3/C4/C6/C7/C8 各自 `research/implementation-status.md`
- `research/committed-head-assembly.json`

