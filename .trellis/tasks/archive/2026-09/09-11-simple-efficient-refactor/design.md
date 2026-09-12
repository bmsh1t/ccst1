# Design：简单高效重构

## 总体架构立场

**加壳不拆墙**。本任务不触碰五个状态 owner（Coverage/Ledger/Queue/Checkpoint/Closure）
的语义、闸门桶、锁序与写回协议——9 批次 roadmap 刚验证过这些资产。改变的是三样东西：

1. **文档层**：概念单一来源化（重复解释 → 权威文件 + 引用）
2. **交互层**：AI 输入收敛到判断字段（机械字段模板/证据推导）
3. **摆放层**：大文件按职责拆分、循环依赖斩断（零逻辑变更）

```
零-0 文档  →  零-A 孤儿  →  零-B 状态机  →  零-C /distill  →  零-D 死出口
     （每步全量绿，独立可回滚）
阶段一 #1-#4 交互面（claim 模板 / record 极简 / bootstrap 摘要 / 结构化 leads）
阶段二 #6-#9 结构（拆 autopilot_state / 斩循环 / 谁思考列 / contracts 层）
```

---

## 零-0 文档减负

### 概念权威文件落位（10 个）

| 概念 | 权威文件 | 当前重复源数 |
|---|---|---|
| checkpoint 写回 | `commands/checkpoint.md` | 16 |
| claim 契约（激活字段） | `commands/hunt.md` | 10 |
| recall gate | `skills/runtime-protocol.md#shared-knowledge-recall` | 8 |
| 红线 | `rules/red-lines.md`（已有） | 7 |
| 反早停 | `rules/hunting.md` | 6 |
| Skill 选择 | `rules/playbook-router.md` | 5 |
| lane contract | `docs/autopilot-lanes.md`（已有） | 5 |
| Four-Layer Runtime | `docs/architecture-contract.md` | 4（autopilot 家族） |
| autopilot 三模式 | `commands/autopilot.md` | 4 |
| Credential Lane | `skills/credential-attack/SKILL.md` | 3 |

### 手术纪律

- 命令文档保留"何时用/参数/验收"，删除机制性解释，改 1-3 行引用：
  `见 commands/checkpoint.md#写回`。
- **hunt.md 的 138 行方法论叙述不动**（真东西）；只删 autopilot.md/validate.md
  复述 bootstrap JSON 字段与 decision schema 的段落（③，-30 KB）。
- agents/autopilot.md 只删三模式段（:103-116）与 Four-Layer Runtime 段；
  17 段子代理人格契约（Use When/Inputs/Prime Directive）**保留**——
  它与 commands 版角色不同，不是重复。
- autopilot SKILL.md 275 → ~200 行，砍与 lanes/commands 重复段。
- 契约口径基线（实测 2026-09-11）：commands 178 + skills 94 + rules 54 +
  agents 79 = 405 KB（docs/ 另计）。验收线 ≤310 KB 按 commands+skills+rules+agents 计。
- 文档契约测试（test_command_contracts 等）成对改：引用行替代被删段落后，
  测试里的锚点同步更新，不留双源。

---

## 零-A 孤儿归档

5 个文件 `git mv` 到 `archive/tools/`（capability_governance.py 先例）。
每文件动手前重跑三零确认（零 import / 零文档 / 零命令入口）。
vision_browser.py 的 seam 提及（repo-root-seams.md）随零-0 一并删。

## 零-B 知识治理状态机拆除

```
现状（3,154 行，0 运转）：candidates(1135) → lifecycle(766) → distill_reports(~800)
目标（~150 行，直线）：    /distill 出题 → AI 提三元组 → 草稿卡 → 人工 mv
```

- `git mv` 三文件到 archive/；`commands/distill.md` 旧版整删（零-B 里名字让给新版）
- `knowledge/` 目录形态**不变**：cards/、capabilities.yaml、index.md 全保留
  （召回链路是活的：context_pack → knowledge_registry → cards）
- `context_pack._reviewed_candidate_hints`（:2845，唯一读 candidates 的活代码）：
  退役该 hint。理由：它读 `lifecycle.jsonl` 中 status=reviewed 的条目——
  新形态下没有 lifecycle.jsonl；重建等价物（扫草稿 frontmatter）复杂度高于收益，
  且该 hint 在全部实测运行中匹配数为 0（41 条存量数据全是旧格式，status 无 reviewed）。
  退役后 context_pack 输出少一个字段，`reviewed_candidate_pool/matches` 计数随之删除。

## 零-C 新 /distill（`tools/distill_target.py` + `commands/distill.md` 重写）

### 数据流（出题-收卷协议）

```
① machine: pull(target) → ledger entries + findings + case_state 原始证据
② machine: render prompt（类型学四选一：Pattern / Target→Vuln / 失败教训 / 绕过关系）
③ AI:     在当前会话读 prompt，提三元组 {pattern, trigger, action} + evidence_refs
④ machine: render --commit（AI 把三元组通过 --triple-json 或 stdin 传回）
           → scrub 脱敏 → card-template 渲染 → knowledge/candidates/<slug>.md
⑤ 输出:    "review 后 mv 进 knowledge/cards/ 即 promote；rm 即 reject"
```

### 关键设计决定

- **两段式而非一体式**：机器出题（①②）和收卷渲染（④）是两个子命令
  （`prompt` / `commit`），中间的认知由 AI 在会话内完成——机器不能伪造认知，
  这与 /sub 出题-收卷同构。
- **脱敏**：从被归档的 knowledge_candidates.py 抄 `_scrub` 片段（IP/密钥/token
  正则），其余不抄。脱敏不过 → commit 拒绝写入（FORMAT 桶）。
- **草稿目录**：复用 `knowledge/candidates/`（清空后重用——旧 41 条
  {text,ts} 数据是死格式，已随零-B 失去读者）。
- **slug 规则**：`<类型学短码>-<kebab-summary>`，机器生成，冲突加序号。
- **不做状态机**：草稿文件的 `maturity: draft` 只是 frontmatter 展示字段，
  人工 mv 到 cards/ 时改成 `maturity: reviewed`——git diff 就是生命周期审计。

### 验收实跑

`/distill 127.0.0.1:3001`（ctf_mode 靶场）：BOLA basket 模式是现成素材——
ledger 里有 basket 加/查的 owner/peer 对照条目。产出第一张草稿卡并人工 mv。

## 零-D 死出口与卫生（设计复核修正版）

**设计复核推翻了 prd 初版的"proposal 家族 1,126 行可归档"**：

```
checkpoint["target_write_back"]  ←  _lead_proposals/_next_proposals/_dead_end_proposals
        ↓                                    （1,126 行的主体——活！apply_target_memory 的数据源）
apply_target_memory (B2 默认开) → target_memory 写回
checkpoint["commands"]           ←  _write_back_commands (18 行)
        ↓
resume.py:517/:714 展示 commands[:3]（无执行路径——死）
```

实际处置：

| 项 | 行数 | 处置 |
|---|---|---|
| `_write_back_commands` + `checkpoint["commands"]` 字段 | ~25 | 删；resume.py:517/714 展示分支删 |
| `--max-lanes-reached` flag + `max_lanes_reached` 参数线 | ~50 | 删；CLI/内部调用方（autopilot_round:73、recon_artifact_gc:117、checkpoint:608/694 全部硬编码 False）与 :5598 `or round_progress.budget_reached` 语义等价 |
| `_normalise_endpoint_path`（两文件 AST 哈希相同） | 2×2 | 迁 `tools/target_paths.py`，两处改 import |

`target_write_back` / `next_action_queue` / `apply_target_memory` / witness /
round 生命周期全部不动。分桶测试 checkpoint 最小闸门数 15 不受影响（删的是
输出渲染，不是 raise gate）。

---

## 阶段一 #1：claim 模板注册表

### 模板形态

`tools/claim_templates.py`（新文件，~120 行）：

```python
CLAIM_TEMPLATES: dict[str, dict] = {
    "idor-cross-actor": {
        "family": "IDOR",
        "technique": "cross_actor_access",
        "active_dimension": "object_access",
        "skill_route": {"skill_id": "web2-vuln-classes", "skill_path": "skills/web2-vuln-classes/SKILL.md", "required_dimensions": [...]},
        "risk_tier": "medium",
        "max_hypothesis_actions": 4,
        "depth_contract_version": DEPTH_CONTRACT_VERSION,
    },
    "sqli-error-based": {...},
    "authz-header-swap": {...},
    # 首批 3-5 个，覆盖实测高频形态
}
```

### 合并优先级（关键不变量）

```
final = {**template, **from_evidence_derived, **metadata_json}
```

显式 `--metadata-json` 永远赢 > 证据推导 > 模板。这与现有
`{**derived, **metadata}` 合并（action_queue.py:1959 附近）同构，
模板只是在前端多加一层默认值。

### 分桶纪律

模板是 FORMAT 桶的削减（少打字），不是门槛的削减：
`hypothesis_id/expected_learning/kill_condition/decision_reason` 四个判断字段
**不在任何模板里**——缺了照样 raise（缺字段 gate 属 FORMAT 桶，不变）。
`--list-templates` 只列名字与适用场景一句话。

### 测试

- 模板预填正确（每个内置模板一条）
- 优先级：模板值 < from-evidence 值 < metadata 值（三层覆盖测试）
- 未知模板名拒绝（FORMAT gate，错误信息含可用模板清单）
- 模板 + from-evidence 组合
- 四判断字段不可被模板预填（负测试）

## 阶段一 #2：record 极简形态

`evidence_ledger record --from-probe <event_id>`：

- 从 ledger 里按 event_id 反查 probe 事件（ledger 已按 event_id 索引），
  复制 endpoint/method/actor/variant/evidence_ref/evidence-timestamp。
- AI 只补 `--result`（默认 lead）与 `--notes`。
- 极简日常路径：`record T <event_id> --from-probe --result tested_clean --notes "..."`。
- 28 参数复杂面原样保留（进阶用法文档区），只加不减。

## 阶段一 #3：bootstrap 人话摘要行

`autopilot_state --bounded` JSON 顶部加 `summary` 字段（非顶层行——
机器消费方读字段，不解析自由文本）：

```json
"summary": "Next: wait_recon（recon 未跑）| Gate: hard_gate=run_recon | Queue: 3 active | Round: 2/16 lanes"
```

- 摘要内容全部**派生自既有字段**（priority_frontier[0]/hard_gate.action/
  queue active 数/round_progress），不引入新状态。
- 一致性测试：摘要的每一段都能在投影 JSON 里找到对应字段源。

## 阶段一 #4：结构化 leads + 场景化 resume

- `target_memory.py` 的 lead/next 条目接受 `--structured-json`：
  `{hypothesis, evidence_ref, next, stop_condition}` 四字段；纯文本条目
  （现状）继续可读可写——向后兼容。
- `resume.py` 输出末尾的"场景摘要"段：由 target_memory 的 structured 条目
  + closure 状态合成一段人话（"上次在验证 X，卡在 Y，下一步 Z"）。
  有 structured 条目用 structured，没有则退化为现状纯文本列表。

---

## 阶段二 #6：拆 autopilot_state.py（纯搬动）

### 拆分清单（git mv 语义，函数体逐字不动）

| 新文件 | 内容 | 目标行数 |
|---|---|---|
| `autopilot_state_read.py` | 状态加载、路径解析、artifact 读取 | ~1,200 |
| `autopilot_projection.py` | build_closure_projection 及投影构建族 | ~1,800 |
| `autopilot_gate.py` | hard_gate/frontier/决策函数 | ~1,000 |
| `autopilot_loop_guard.py` | Loop Guard 独立 | ~600 |
| `autopilot_state.py`（保留） | CLI 入口 + 组装 | ~800 |

- import 方向单向：`autopilot_state.py` → 四个模块；四模块之间只允许
  read → projection → gate 的既有调用方向，禁止反向。
- 现有 `from tools.autopilot_state import X` 的外部消费方
  （checkpoint/action_queue/resume/autopilot_round/recon_artifact_gc 等）
  **不受影响**：autopilot_state.py 里保留 re-export（`from .autopilot_projection import build_closure_projection`）。
- 顺序：read → loop_guard → gate → projection，每搬一个跑全量。
- 分桶测试 OWNER_SOURCES 不含 autopilot_state.py，不受影响。

## 阶段二 #7：斩 aq↔ck 循环依赖

现状：`action_queue.ingest_checkpoint`（:1753）在 `checkpoint is None` 时
**函数内 import** `tools.checkpoint.build_checkpoint`（:1756）；而
checkpoint.py 顶部 import action_queue（:41）——模块级循环。

```
改法：ingest_checkpoint(repo, target, checkpoint=None) 保留 None 默认，
     但把"None → build_checkpoint()"的懒加载分支移到调用方：
     - CLI 层（action_queue main 的 ingest-checkpoint 子命令）：调 build_checkpoint 传入
     - checkpoint.py:766 的 sync_checkpoint_action_queue：本就传 checkpoint（不受影响）
     - tests：显式传 dict（test_validation_runner 等已这么写）
改后：action_queue.py 顶层零 checkpoint import；依赖单向 ck → aq。
```

零行为变化：None 分支的语义（现网生产路径从不走 None——所有真实调用方都传
checkpoint dict，实测 transcript 与代码确认）平移到 CLI 层。

## 阶段二 #8：命令文档"谁思考"列

38 个 `commands/*.md` 参数表加一列：

| 参数 | 谁思考 | 说明 |
|---|---|---|
| `--metadata-json` 里的 16 字段 | 4 个 `AI 判断` + 12 个 `机器推导` | 模板/from-evidence 可预填 |
| `--result` | `AI 判断` | 观察判定 |
| `--target` | `机械` | owner 上下文 |

B5 已有的字段分类映射直接复用；`action_queue.py` 注释 :1901 的
"Everything else stays AI-supplied" 原则文档化。

## 阶段二 #9：contracts 层

`tools/contracts.py`（新，~100 行起步）：

```python
# 跨 owner 不变量集中声明。改契约的一方动这里，另一方 import 同一常量。
VALIDATE_TERMINAL_STATES = frozenset({...})       # validate ↔ queue 共享
QUEUE_CLAIM_REQUIRED_FIELDS = ACTIVATION_REQUIRED_CLAIM_FIELDS  # queue ↔ checkpoint 共享
LEDGER_REDLINE_EVENTS = frozenset({...})          # ledger ↔ runner 共享
CHECKPOINT_QUEUE_LOCK_ORDER = ("checkpoint_witness_lock", "queue_mutation_lock")  # ck ↔ aq 锁序
```

- 起步只收编 3-4 个：validate 终态、claim 字段（action_queue 从 contracts
  import 常量）、锁序（两文件 import 同一元组做运行时断言）。
- 不做 ORM/DSL——就是常量模块。validate↔queue 集成缺口（本会话藏两轮
  才暴露的那次）的编译期根治。
- **依赖方向**：contracts.py 零 import（纯常量），owner 们 import 它——
  不引入新循环。

---

## 兼容与回滚

| 批次 | 回滚单位 | 验证 |
|---|---|---|
| 零-0 | 每概念一个 commit | 文档契约测试 + 人工抽查引用可达 |
| 零-A/B/D | 每文件一个 commit（git mv 保留历史） | 全量 pytest |
| 零-C | 新文件独立 commit | /distill 实跑 + 脱敏负测试 |
| 阶段一各项 | 独立 commit | 新测试 + 全量 |
| 阶段二 #6 | 每搬一个文件一个 commit | 全量（函数体逐字不动，diff 可审） |
| 阶段二 #7/#9 | 独立 commit | 全量 + import 图断言 |

全任务红线：分桶测试 151 闸门清单不变（gate 语义零变化）、
closure/validate/owner 写回协议零变化、1870 基线测试逐批只增不减。

## 风险与缓解

| 风险 | 缓解 |
|---|---|
| 零-0 删段后 AI 读不到机制解释 | 权威文件保留完整解释；引用行精确到锚点 |
| 拆 autopilot_state 引入 import 循环 | import 方向预声明；每步全量绿再搬下一个 |
| claim 模板变成隐性内容门槛 | 四判断字段永不出现在模板；P0 分桶测试加负断言 |
| /distill 草稿被误 promote | mv 是显式人工动作；scrub 是写入 gate 不是展示装饰 |
| resume 删 commands 展示后信息丢失 | target_write_back 内容仍在（apply_target_memory 默认写回）；摘要段（#4）补位 |
