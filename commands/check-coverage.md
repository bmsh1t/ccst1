---
description: 检查当前目标或本轮输出是否满足覆盖基线。用法：/check-coverage
---

# /check-coverage

按完整 `rules/ccst/coverage-gate.md` 复核本轮覆盖、证据深度、残留和停止理由。
这是 AI 覆盖审查入口，不执行扫描、不裁决漏洞，也不替代 Closure owner。

## 目标与读取

优先使用 `$ARGUMENTS` 的目标；没有参数时可读 `memory/goals/active.json` 选择指针。
无法确定目标就要求明确目标，指针不代替当前 Store 的领域状态。
复用当前有效的 Coverage、Actor Matrix、Surface 和目标经验；只查询缺失或变化的视图：

```bash
python3 tools/coverage_matrix.py find-gaps --target TARGET --limit 50
python3 tools/evidence_ledger.py summary --target TARGET
```

以上按问题选择，不要求每次都运行。`find-gaps` 返回全部未处置格的有界窗口、
总数、余量及完整展开命令；不按语义/分数筛选，没有 `--all` 参数。
AI 根据业务、原始证据和实际覆盖深度判断哪些 gap 值得追，矩阵不是逐格实测清单。
输入变化且需要发布派生缓存时，显式使用 `coverage_matrix.py rebuild` 或 `/surface --refresh`；
普通 checkpoint 或读卡不强制重建。

## 审查与收尾

- 说明核心输入、角色/对象/状态、真实观察和验证深度；`tested` 需要对应证据。
- 未处置格非空不自动要求逐格测试；值得追的 gap 选择不追时说明理由和续接条件。
- Actor Matrix 的缺口不能被匿名请求或单一身份结果补成完整 authz/IDOR 覆盖。
- 空矩阵、没有 live host 或扫描零结果不证明全面完成；保留输入缺失与其他工作。
- 按 gate 交代 lead/signal/candidate、blocked、n/a、dead-end、unknown 和下一步；
  原因、证据和实际未覆盖范围不可省略，红线阻塞沿现有规则处理。
- 普通查看不写记忆。有稳定结论、转向或交接时按
  `skills/runtime-protocol.md#cognitive-write-timing` 写回；实际结束仍走 Coverage/Closure，
  Autopilot 的 claim、回收、heartbeat 和全局复核责任不变。

## 输出

```text
COVERAGE CHECK
- Target / Phase:
- Covered inputs, roles/state and evidence depth:
- Worthwhile gaps / Actor Matrix gaps:
- Leads / Signals / Candidates:
- Blocked / Not applicable / Dead ends:
- Unknown / Intentionally deferred, with reason and reopen condition:
- Next evidence action:
- Decision and stopping reason: continue / handoff / validate / report-not-ready
```

有 Candidate 时 follow `/validate`；已有 single-step 报告消费收据，deferred text
或明确新交付才 `/report`。没有证据和覆盖说明时，不宣称“全面测试，没有问题”。
