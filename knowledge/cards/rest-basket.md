---
id: rest-basket
type: technique-card
related_skills:
  - web2-vuln-classes
trigger_tags:
  - rest-basket
risk: low
maturity: tested
load_priority: low
deep_refs: []
source_refs: []
updated: 2026-09-11
---

# REST 购物车类接口的匿名可读越权

蒸馏类型：Pattern（可复用模式，/distill 首张 target-evidence 卡）

## Quick Recall

- 触发：`GET /rest/<resource>/<numeric-id>` 无 Authorization 头仍 200 且含他人数据。
- 最小验证：同 URL 三对照（anonymous / owner / peer id_swap），比对响应体对象归属字段。
- 证据门：必须保留 diff.json（owner 基线 vs anonymous replay 的机器差异）。
- 停止：无 Authorization 层直接判定对象级越权；有 401/403 则止步为 Signal。

## 触发信号

- GET /rest/<resource>/<numeric-id> 无 Authorization 头仍返回 200 且含他人数据；同端点 owner 基线与 anonymous replay 产生内容差异（diff.json 中 tested_finding）

## 思路分支 / 最小验证

- 最小验证：同 URL 三对照 —— anonymous 无头 GET / owner 带凭证 GET / peer id_swap GET，比对响应体对象归属字段；无 Authorization 层直接判定对象级越权

## 证据

- 来源目标：127.0.0.1:3001（脱敏后写入）
- 原始证据：
- `evidence/127.0.0.1:3001/validation/request_diff-rest_basket_1/20260911T074447486119Z-22ed619c/diff.json`
- `evidence/127.0.0.1:3001/probe/20260911T160420335Z-352c60e6.json`

## 常见误判 / 死路

- 返回 200 但只有当前用户自己的数据 → 是正常行为，不是越权（对照 owner 基线）
- 401/403 → 无越权，保持 Signal
- 响应体内容差异但对象归属字段相同 → 可能是模板/缓存差异，需比对数据字段

## 下一步或晋升

- 已有可复跑 diff 证据（maturity: tested）；两个以上独立目标命中后再升 proven。
- 适用面扩展：把 `<resource>` 泛化到其他数字 ID 端点前，先在当前目标验证 2-3 个资源族。

## 人工审核

- promote 完成（2026-09-11）；来源目标与 evidence_refs 见"证据"节。
