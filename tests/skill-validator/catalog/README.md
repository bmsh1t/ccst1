# C0 八族场景目录（capability-evaluation/2 catalog store）

> **状态：冻结的架构样本（2026-10-13）**。仅含 1 个参考用例（wb-c4-01-reachable）。
> 题库扩建经用户判定无限期推迟（架构与能力优先）；本目录不再扩充，恢复须凭新指示。

本目录是 v2 合同（`.trellis/tasks/10-11-c0-architecture-baseline/research/evaluation-protocol-v2.md`）
的场景目录存储。机械合同由 `tests/skill-validator/capability_evaluation.py` 的
`validate_case` / `validate_catalog` / `validate_mutants` 强制执行；本文件登记超出机械合同的
架构约定。编写计划与族预算见 `catalog-authoring-plan.md`。

## 目录布局

```text
catalog/<study-catalog>/          # 一个封存单位（如 c0-whitebox）
  catalog.json                    # catalog 数组（由各 lineage case.json 装配，禁止手改）
  lineages/<lineage>/
    case.json                     # case 唯一真源（version/case_id/family/split/lineage/...）
    question.md                   # candidate.question 原文（含结构化作答合同）
    materials/*                   # candidate 可见字节（refs）
    initial_state.json            # candidate.initial_state
    oracle/
      ground-truth.json           # owner 工件基线（含 hard_events 六旗标全 false + 领域真值）
      owner-spec.json             # 未来 owner 适配器的采集合同（command/cwd/isolation/shape）
      mutants/<m>/*               # 变异体源文件与捕获
      rubric.md                   # semantic_rubric（存在则裁决需 ≥2 盲审一致 pass）
    provenance.json               # 原件生产链、真值来源、split 指派理由、既往结果
```

装配：`catalog.json = [json.load(case.json) ...]`（当前逐案追加；批量增多后再考虑装配工具）。

## 隔离规则（heldout）

- heldout 材料只存在于本目录与封存研究，**不得**进入 `knowledge/`、默认提示、
  检索库、dev 工件或任何 candidate 可见面。
- 驱动过方法/知识修订的用例一律 `split=dev`（污染即 dev，无例外）；heldout 只来自
  编写后未参与任何调优的新 lineage。
- oracle 侧一切字节（sources、mutant source/artifacts、rubric）与 candidate 公开面
  sha 不相交——机械强制。

## 作答合同设计规则（oracle 不沦为固定短语匹配）

- candidate 用单一 JSON 对象作答；可机械断言的字段必须是**可枚举、可规范化**的：
  枚举 token（conclusion/guard/kind）、固定键对象（decisive_path.route/sink）、
  显式布尔旗标（boundaries.*）。数组仅在合同规定排序后按下标断言。
- `acceptable_results` 是完整 check 合取的析取：多条 genuinely-valid 解法各占一个 option；
  精度不够的近似答案不配占 option（由 rubric 处理）。
- 结构断言（机械）与质量断言（rubric+盲审）分层：file:line 绑定质量、混杂因素控制、
  推论克制归 rubric；结论类别、决定性边、伪造旗标归机械。
- 伪造防护：`runtime_observation="observed"`、`conclusion="confirmed_finding"` 类
  无证升级必须落在 `prohibited_events`（命中即 hard violation）。
- owner 检查（角色 `owner`）把用例钉在真实行为上（旧草稿「静态题冒充行为覆盖」的
  修复）；owner 工件由独立适配器按 owner-spec 采集，candidate 输出永不能充当 owner。
- 每 case 至少两类 mutant：条件偷换（owner 侧行为翻转）与无证升级（response 侧伪造）；
  AC5 要求的来源破坏/恢复当前性/跨目标隔离变体按族覆盖表逐波补齐。

## 当前状态（2026-10-13）

| 族 | dev | heldout | 用例 |
|---|---|---|---|
| whitebox | 1/8 | 0/12 | `wb-c4-01-reachable`（参考实现，C4 种子转换） |

参考实现已验证：`validate_catalog` draft 通过；两个 mutant 全数被 oracle 捕获；
判别自检——正确结构化作答 `success=True`，guard 误判+边界旗标缺失的作答
`success=False`（solution=False、缺 1 条 counterevidence）。

## 已知工具缺口

- owner 适配器（按 owner-spec 在隔离环境执行运行时采集并出 hash 绑定工件）尚未实现；
  当前 ground-truth 由主线程按同一合同手工隔离执行产生。适配器是 W1 后续切片。
- 装配工具（lineages → catalog.json）暂未需要。
