# 本地靶场端到端测试报告（juice-shop @ 127.0.0.1:3001）

日期：2026-09-12 | 基线 HEAD：d76db02 | ctf_mode: true

## 结论

重构后工具链**完整跑通**，validator 100/100 PASS；发现并修复 1 个真实缺陷。

## 阶段结果

| 阶段 | 内容 | 结果 |
|---|---|---|
| A 基线 | 17 ledger / 1 finding / 13 recon / 1843 passed | 冻结 |
| B 狩猎 | bootstrap→recall gate→probe 三对照→claim→resolve→checkpoint | 全通 |
| C 校验 | check_autopilot_run 100/100 PASS；closure 判定链完整 | PASS |
| D 对照 | 重构收益实测 4 项 | 见下 |
| E 报告 | 本文件 | — |

## 漏洞验证（BOLA 复现）

- anonymous GET /rest/basket/1 → **401**（认证层拦截）
- owner GET /rest/basket/1 → **200**，body sha16 `352c60e6`，1310B
- peer  GET /rest/basket/1 → **200**，body sha16 `352c60e6`，1310B（**完全相同**）
- 判定：对象级归属校验缺失，跨角色读取成立（AQ-0003 → candidate）

## 阶段 D 回归对照（重构收益实测）

| 项 | 旧 | 新 | 结论 |
|---|---|---|---|
| probe 记账 | 手工 record | probe 自动落账 | 本轮 5/5 自动落账，evidence_ref 全非空 |
| record 补账参数 | 9 个 | `--from-probe` 4 个（-56%） | 生效 |
| claim 字段 | 手拼 16 字段 | `--template` 预填 7 + 4 判断 | 生效 |
| /distill | 无（旧 corpus 死线） | prompt→commit 两段式 | 生效（拉 23 ledger 出题→草稿卡落盘） |
| checkpoint commands 死出口 | 输出 commands 字段 | 已删 | 确认消失 |
| 状态投影结构 | 61 键 | 61 键（零变化） | 零-D 未破坏 |

## 发现的缺陷

1. **`distill_target.py prompt` 缺 `--json`**（真实缺陷）
   - 现象：`prompt ... --json` → argparse `unrecognized arguments: --json`
   - 影响：`commands/distill.md` 与 `build_prompt` 的 next 提示都写的是带 `--json` 的调用形态
   - 修复：补 flag + 2 回归测试 → commit 已提交

## 遗留（非缺陷，属正常 handoff）

- recon bounded residual 7 项（remaining=0）需 complete-status 复核消费 → closure 正确返回 `blocked: bounded_recon_residual_deferred`
- 10 条 checkpoint 提案入队待下轮执行（AQ-0004..0013）
- 草稿卡 `knowledge/candidates/rest-numeric-id-cross-actor.md` 待人工审核 mv
