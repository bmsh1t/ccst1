# 6k 接入：实现与审核原文加载图

只作原文导航，不替代规范、设计、方法正文或来源台账。
C=`/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`；下列路径相对 C。
T=`.trellis/tasks/archive/2026-10/10-14-6k-full-integration`，SPEC=`.trellis/spec/backend`。
S/F 为历史隔离副本。任务已完成；下文保留实施时的阅读合同，见 [审核收尾](risk-review-closeout-2026-10-16.md)。

## 1. 必读顺序

1. 确认仓库和批次；B1–B5 仅改 S、验收仅运行 F，C 活动文件留到 B6。
2. 主会话完整亲读 `docs/architecture-contract.md` 及 T 的 `prd.md`、`design.md`、
   `implement.md`。架构是当前基准，设计的新接口不是已有能力；探子不得替代基础阅读。
3. 读 `SPEC/directory-structure.md` 和下表涉及的 canonical 规范全文；已完整读过且
   未变化的不重复加载。改动跨批则合并读取范围，新增 owner 按 backend index 补读。
4. 修改前亲读确切代码、调用者和受影响测试。旧 legacy/top-k/selected-skill 示例
   不覆盖当前架构，不能据它们恢复第二控制器。注入成功不代表已读或验收成功。

## 2. 各批次的完整原文入口

表内 SPEC/T 必须按上述根展开；定位主题不授权只读摘录。

| 批次 | canonical 文档 | 重点 |
|---|---|---|
| B1 文件发布/读取 | `SPEC/database-guidelines.md`、`SPEC/contracts/transactional-target-state.md` | 对照设计 §3–§4；旧 compensating rollback 不等于新协议。 |
| B2 来源/初次绑定 | `T/research/source-disposition-matrix.md` 及同名 `.json`；`T/research/v23-delta-matrix.md`、`T/research/v23-delta-inventory.json`、`T/research/capability-disposition-matrix.md` | 62项全部原件/消费者；机械差分、治理、延期分开，声明不是能力。 |
| B3 共同调查入口 | `SPEC/contracts/runtime-autopilot.md`；沿用B1规范 | 亲读 native Skill/commands、hot_method/context_pack；目录不等于已读。 |
| B4 中性观察/浏览器 | `SPEC/contracts/transactional-target-state.md`、`SPEC/contracts/validation-evidence.md`、`SPEC/contracts/browser-js.md`、`SPEC/scope-context.md` | 亲读 importer/Store；捕获基线、claim/重试、kind/lane 与 Scope 分开。 |
| B5 记忆/campaign | B1规范及 `SPEC/contracts/runtime-autopilot.md` | Memory Consumer Contract；写回时机以 `skills/runtime-protocol.md#cognitive-write-timing` 为准。 |
| B6 切换/隔离部署 | `SPEC/contracts/runtime-autopilot.md`；沿用B1/B4规范 | F内代码/测试和白名单环境；C排他后独立bootstrap，不复制F收据/见证，不回放目标数据。 |

涉及Action认领或文本消费者时，另完整读 `SPEC/action-queue-dumb-interface.md`。
本表不是修改白名单，实际边界以设计/实施计划为准。

## 3. 来源台账

必须一起读来源JSON顶层 `source_root/target_repo/planned_archive_root/archive_state`
及全部 `items`。逐行核对 `id, source, source_sha256, planned_archive_path, kind,
current_path, current_sha256, current_status, planned_destination, planned_consumer, exceptions`。
`planned_archive_path` 相对 `planned_archive_root`，只是规划落点，不证明档案已创建。
八项 `current_sha256=null` 连同治理/缺损说明解释，不自动判遗失或已生效。来源hash、
当前副本hash与未来活动版本是不同对象；62项和2.3台账均完整保留在原文件。

## 4. 上下文与边界

默认 manifest 单文件32768 B、规划artifact单文件65536 B、总131072 B；依据
`.trellis/scripts/common/config.py` 和 `.codex/hooks/inject-subagent-context.py`。
两个JSONL只注入基础规范、本图及能力矩阵；本图列出的原文不会递归注入，必须显式补读。
不提高全局预算、不虚设loader不支持的行切片、不拆成重复规范以绕过限制。
修改后用真实 `get_implement_context/get_check_context` 渲染显式T，再包装native上下文，
核对每个manifest正文及三件套全部出现、无 `truncated at/not inlined`，并检查包装后字节数；
validator exit 0不能单独证明完整。预览不需激活任务。

个人runtime事件见 [历史收尾](planning-closeout-2026-10-15.md)，既有六项修正见
[二次复审](plan-recheck-2026-10-15.md)。本轮审核不证明个人runtime已恢复；不得把它
当验收来源。未加载对应owner全文或未满足B6排他时，不越过相应门槛。
