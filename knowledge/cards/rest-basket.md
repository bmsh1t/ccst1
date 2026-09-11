---
id: rest-basket
type: technique-card
related_skills: []
trigger_tags:
  - rest-basket
risk: low
maturity: tested
load_priority: low
source_refs:
  - type: target-evidence
    target: 127.0.0.1:3001
    refs: ["evidence/127.0.0.1:3001/validation/request_diff-rest_basket_1/20260911T074447486119Z-22ed619c/diff.json", "evidence/127.0.0.1:3001/probe/20260911T160420335Z-352c60e6.json"]
updated: 2026-09-11
---

# REST 购物车类接口的匿名可读越权： basket 端点对未认证请求返回其他用户购物车内容

蒸馏类型：Pattern（可复用模式）

## 触发信号

- GET /rest/<resource>/<numeric-id> 无 Authorization 头仍返回 200 且含他人数据；同端点 owner 基线与 anonymous replay 产生内容差异（diff.json 中 tested_finding）

## 思路分支 / 最小验证

- 最小验证：同 URL 三对照 —— anonymous 无头 GET / owner 带凭证 GET / peer id_swap GET，比对响应体对象归属字段；无 Authorization 层直接判定对象级越权

## 证据

- 来源目标：127.0.0.1:3001（脱敏后写入）
- 原始证据：
- `evidence/127.0.0.1:3001/validation/request_diff-rest_basket_1/20260911T074447486119Z-22ed619c/diff.json`
- `evidence/127.0.0.1:3001/probe/20260911T160420335Z-352c60e6.json`

## 误判边界

- 返回 200 但只有当前用户自己的数据 → 是正常行为，不是越权（对照 owner 基线）
- 401/403 → 无越权，保持 Signal
- 响应体内容差异但对象归属字段相同 → 可能是模板/缓存差异，需比对数据字段

## 人工审核（review 后改这里）

- promote 前检查：trigger 是否可观察、action 是否最小、误判边界是否写清。
