# Implement：执行计划

施工顺序：**零-0 → 零-A → 零-B → 零-C → 零-D → 阶段一 → 阶段二**。
每批次收尾跑全量测试；日常迭代用 `pytest -x --lf`。
基线：1870 passed（批次开始前复核一次）。

---

## 批次 0：文档减负（零-0）

- [ ] 0.1 复核基线：契约口径 KB 实测（commands+skills+rules+agents，2026-09-11 实测 405 KB）记入 commit message
- [ ] 0.2 死文档删除：`commands/distill.md` 旧版整删（名字留给零-C 重写）、kb.md :26-122 promote/lifecycle 段、retrospect.md 死流程段、promotion-rules.md 状态机段（保留落位规则表格）、repo-root-seams.md vision_browser 段
- [ ] 0.3 概念单一来源化，一次一个 commit：
  - checkpoint 写回 → `commands/checkpoint.md` 权威；16 处引用源降为 1-3 行引用（主战场 autopilot 家族 4 份 76 KB）
  - claim 契约 → `commands/hunt.md`；10 处降引用
  - recall gate → `skills/runtime-protocol.md`；8 处降引用
  - 红线/反早停/Skill 选择/lane contract → 各归 `rules/red-lines.md`/`rules/hunting.md`/`rules/playbook-router.md`/`docs/autopilot-lanes.md`
  - Four-Layer Runtime → `docs/architecture-contract.md`；三模式 → `commands/autopilot.md`；Credential Lane → `skills/credential-attack/SKILL.md`
- [ ] 0.4 autopilot.md/validate.md 字段复述段压缩（-30 KB 主力）；hunt.md 方法论 138 行**不动**
- [ ] 0.5 autopilot SKILL.md 275 → ~200 行；agents/autopilot.md 删三模式段与 Four-Layer 段（17 段人格契约保留）
- [ ] 0.6 文档契约测试成对修（引用锚点替换被删段）；验收：`pytest tests/ -k contract` 绿 + 总量 ≤310 KB + `rg` 确认 10 概念命令文档只剩引用
- [ ] **验证命令**：`python3 -m pytest -q`（全量）+ KB 统计脚本重跑
- [ ] **commit**：`docs: single-source contract concepts (-28%)`

## 批次 1：孤儿归档（零-A）

- [ ] 1.1 每文件重跑三零确认（import/文档/命令入口）：knowledge_value_review / noise_filter / self_review / distill_aggregate / vision_browser
- [ ] 1.2 `git mv` 五文件到 `archive/tools/`；archive/tools/README.md 追加一行说明
- [ ] 1.3 验收：`pytest -q` 全量绿（预期无任何测试受影响——三零孤儿）
- [ ] **commit**：`refactor: archive five orphan tools (-1,187 lines)`

## 批次 2：状态机拆除（零-B）

- [ ] 2.1 `git mv tools/knowledge_candidates.py tools/knowledge_lifecycle.py tools/distill_reports.py` → archive/；`_scrub` 函数先抄到新家（零-C 用）
- [ ] 2.2 `context_pack._reviewed_candidate_hints` 退役：删函数 + :2938 调用点 + 输出字段 `reviewed_candidate_hints/pool/matches`；test_context_pack 相应断言删
- [ ] 2.3 `commands/retrospect.md` candidates 段改写指向新 /distill（占位：批次 3 落地前先指向"即将上线"或不提，随批次 3 一起提交）
- [ ] 2.4 `knowledge/candidates/` 旧 lifecycle.jsonl 与死格式草稿清空（git rm，git 历史保留）
- [ ] 2.5 验收：`pytest -q` 全量绿；`rg -l 'knowledge_candidates|knowledge_lifecycle|distill_reports' tools/ commands/` 仅剩 archive/
- [ ] **commit**：`refactor: retire knowledge-governance state machines (-2,700 lines)`

## 批次 3：新 /distill（零-C）

- [ ] 3.1 `tools/distill_target.py`（~150 行）：`prompt` 子命令——拉 ledger/findings/case_state 原始证据 + 类型学四选一出题
- [ ] 3.2 `commit` 子命令：`--triple-json`（pattern/trigger/action + evidence_refs）→ `_scrub` 脱敏 → card-template 渲染 → `knowledge/candidates/<slug>.md`
- [ ] 3.3 `commands/distill.md` 重写（直线流程 + mv 即 promote / rm 即 reject + 出题-收卷协议说明）
- [ ] 3.4 测试：脱敏负测试（IP/token 出现即拒）、slug 冲突、类型学校验、evidence_refs 必须指向真实 ledger/finding 路径
- [ ] 3.5 **实跑验收**：`/distill 127.0.0.1:3001`（ctf_mode）——BOLA basket 素材产出第一张草稿卡，人工 `mv` 进 knowledge/cards/，frontmatter `maturity: draft→reviewed`
- [ ] **commit**：`feat: /distill straight-line knowledge capture`

## 批次 4：死出口清理（零-D）

- [ ] 4.1 删 `_write_back_commands`（checkpoint.py:4516-4533）+ `checkpoint["commands"]` 字段（:4499）+ main 输出 + resume.py:517/:714 展示分支
- [ ] 4.2 删 `--max-lanes-reached` flag 与 `max_lanes_reached` 参数线：autopilot_state.py:5106/:6358/:6473/:7448、autopilot_round.py:73、recon_artifact_gc.py:117、checkpoint.py:608/:694 改为不传（默认 False 语义已由 round_progress.budget_reached 覆盖）；:5598 的 `or` 分支简化
- [ ] 4.3 `_normalise_endpoint_path` 迁 `tools/target_paths.py`，autopilot_state/checkpoint 改 import
- [ ] 4.4 同步删 commands/checkpoint.md 的 record-commands 段、rules/context-loading.md 提案流程段（若 0.3 未覆盖）
- [ ] 4.5 验收：`pytest -q` 全量绿；`rg -n 'write_back_commands|max_lanes_reached' tools/` 仅剩 archive/；target_write_back/next_action_queue 字段快照对比不变（跑一次 --bounded/--closure diff）
- [ ] **commit**：`refactor: remove dead command-render exits and max-lanes flag (-80 lines)`

## 批次 5：claim 模板（阶段一 #1）

- [ ] 5.1 `tools/claim_templates.py`：注册表（首批 idor-cross-actor / sqli-error-based / authz-header-swap / ssrf-url-param / auth-bypass-header）+ `--list-templates`
- [ ] 5.2 `action_queue claim --template <name>`：合并优先级 `{**template, **from_evidence, **metadata}`，显式值永远赢
- [ ] 5.3 四判断字段（hypothesis_id/expected_learning/kill_condition/decision_reason）不进任何模板；缺字段 gate 不变
- [ ] 5.4 测试：预填正确 ×5、三层覆盖优先级、未知模板拒绝、模板+from-evidence 组合、判断字段不可预填负测试
- [ ] 5.5 分桶测试加负断言：模板文件里 `rg 'hypothesis_id|expected_learning|kill_condition|decision_reason'` 零命中（防模板变内容门槛）
- [ ] **commit**：`feat: claim templates --template (16 fields -> 4 judgment fields)`

## 批次 6：record 极简 + bootstrap 摘要 + 结构化 leads（阶段一 #2/#3/#4）

- [ ] 6.1 `evidence_ledger record --from-probe <event_id>`：按 event_id 反查复制机械字段，AI 只补 result/notes
- [ ] 6.2 `autopilot_state --bounded` 输出加 `summary` 字段（派生自 priority_frontier[0]/hard_gate/queue active/round_progress，零新状态）
- [ ] 6.3 `target_memory` lead/next 支持 `--structured-json`（四字段），纯文本兼容
- [ ] 6.4 `resume.py` 场景摘要段（structured 条目 + closure 状态合成人话）
- [ ] 6.5 测试：from-probe 复制正确、摘要与投影字段一致性、structured 读写兼容、resume 摘要退化路径
- [ ] **commit**：`feat: minimal record/bootstrap summary/structured leads`

## 批次 7：拆 autopilot_state.py（阶段二 #6）

- [ ] 7.1 搬 `autopilot_state_read.py`（状态加载/路径解析，~1,200 行）→ 全量绿
- [ ] 7.2 搬 `autopilot_loop_guard.py`（~600 行）→ 全量绿
- [ ] 7.3 搬 `autopilot_gate.py`（hard_gate/frontier/决策，~1,000 行）→ 全量绿
- [ ] 7.4 搬 `autopilot_projection.py`（投影构建，~1,800 行）→ 全量绿
- [ ] 7.5 `autopilot_state.py` 保留 CLI + 组装 + re-export（外部 import 零破坏）；验收 `rg 'from tools.autopilot_state import'` 全部消费方无需改动
- [ ] 每步：函数体逐字搬动（diff 审查无逻辑变更）；import 方向 read ← guard ← gate ← projection 单向
- [ ] **commit**（每步一个）：`refactor: extract autopilot_state_read` 等 ×4

## 批次 8：斩循环依赖（阶段二 #7）

- [ ] 8.1 `ingest_checkpoint` 的 `checkpoint is None` 懒加载分支（:1756）移到 CLI 层；action_queue.py 顶层零 checkpoint import
- [ ] 8.2 验收：`rg -n 'from tools.checkpoint' tools/action_queue.py` 零命中（含函数内 import）；test_autopilot_hypothesis_replay / test_validation_runner 等显式传 dict 的用例不变绿
- [ ] **commit**：`refactor: break aq<->ck import cycle (one-way ck->aq)`

## 批次 9：谁思考列 + contracts 层（阶段二 #8/#9）

- [ ] 9.1 38 个 commands/*.md 参数表加"谁思考"列（AI 判断/机器推导/机械）；B5 字段分类映射复用
- [ ] 9.2 `tools/contracts.py`：收编 validate 终态、claim 必填字段、锁序三个常量；action_queue/validate/checkpoint 改 import 共享
- [ ] 9.3 测试：contracts 常量与 owner 实际使用一致性（防漂移）
- [ ] **commit**：`feat: who-thinks column + shared contracts layer`

## 批次 10：收尾

- [ ] 10.1 全量测试 + 分桶测试专项（151 闸门清单 diff = 0）
- [ ] 10.2 KB/行数终账复核（prd 验收标准逐条对）
- [ ] 10.3 `python3 .trellis/scripts/task.py` 收尾流程：spec 更新、journal、archive

---

## 全程红线（每批次 commit 前 checklist）

1. `python3 -m pytest -q` 全量绿（1870 基线只增不减）
2. `python3 -m pytest tests/test_gate_buckets.py -q` 分桶专项绿
3. 涉及删除的批次：`rg` 引用面确认仅剩 archive/
4. 涉及写回/投影的批次：`--bounded`/`--closure` 输出 diff 审查
5. 一个 commit 一个语义单元（git mv 保留文件历史；不用 cp+rm）
