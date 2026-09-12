---
id: rest-numeric-id-cross-actor
type: technique-card
related_skills: []
trigger_tags:
  - rest-numeric-id-cross-actor
risk: low
maturity: draft
load_priority: low
source_refs:
  - type: target-evidence
    target: 127.0.0.1:3001
    refs: ["evidence/127.0.0.1:3001/probe/20260912T003757450Z-352c60e6.json", "evidence/127.0.0.1:3001/probe/20260912T003757670Z-352c60e6.json"]
updated: 2026-09-12
---

# REST 数字对象 ID 端点的跨角色读取：匿名被认证层拦截，但任何已认证角色都能读到他人对象

蒸馏类型：绕过关系（A 失败 → B 绕过成立）

## 触发信号

- anonymous GET 401，owner 与 peer 带各自凭证 GET 同一对象返回完全相同的 body（sha256 相同、字节数相同）

## 思路分支 / 最小验证

- 最小验证：同 URL 三对照（anonymous 无头 / owner 自己凭证 / peer 他人凭证），比对 body sha256 而非仅状态码；状态码全 200 时哈希相同即证明缺少对象级归属校验

## 证据

- 来源目标：127.0.0.1:3001（脱敏后写入）
- 原始证据：
- `evidence/127.0.0.1:3001/probe/20260912T003757450Z-352c60e6.json`
- `evidence/127.0.0.1:3001/probe/20260912T003757670Z-352c60e6.json`

## 人工审核（review 后改这里）

- mv 进 `knowledge/cards/` 即 promote；rm 即 reject；git log 即审计。
- promote 前检查：trigger 是否可观察、action 是否最小、误判边界是否写清。
