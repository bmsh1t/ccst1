---
id: rest-numeric-id-cross-actor
type: technique-card
related_skills:
  - web2-vuln-classes
trigger_tags:
  - rest-numeric-id-cross-actor
risk: low
maturity: draft
load_priority: low
deep_refs: []
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

- 最小验证：同 URL 三对照（anonymous 无头 / owner 自己凭证 / peer 他人凭证），比对 body sha256 而非仅状态码。owner/peer 哈希相同只是差异比较信号，不单独证明缺少对象级归属校验——两个主体拿到相同公开资源、按设计共享的资源或相同通用错误对象都会满足这个现象。成立对象级越权需三者齐备：资源非公开且归属受限、对象归属字段证明跨主体、其他身份凭据无法解释该访问（与 Quick Recall 判定条件一致）。

## 证据

- 来源目标：127.0.0.1:3001（脱敏后写入）
- 原始证据：
- `evidence/127.0.0.1:3001/probe/20260912T003757450Z-352c60e6.json`
- `evidence/127.0.0.1:3001/probe/20260912T003757670Z-352c60e6.json`

## Quick Recall

- 触发：anonymous GET 401，owner 与 peer 带各自凭证 GET 同一对象返回完全相同的 body。
- 判定条件：资源非公开、对象归属字段证明跨主体、其他身份凭据无法解释访问，三者齐备才成立对象级越权。
- 停止：服务端对 peer 稳定拒绝（401/403），或响应仅含请求者自身数据。

## 常见误判 / 死路

- 仅状态码相同（全 200）不构成证据——必须比对 body sha256；状态码全 401 时认证层存在，不能推出对象归属校验存在或缺失。
- 响应体内容差异但对象归属字段相同 → 可能是模板/缓存差异。

## 下一步或晋升

- 两个以上独立目标命中后再升 proven；泛化到其他资源族前先在当前目标验证 2-3 个资源。

## 人工审核（review 后改这里）

- 审核通过后 `python3 tools/knowledge_promote.py --id <slug>` 即 promote（mv + 登记 + audit 一条命令，失败回滚）；rm 即 reject；git log 即审计。
- promote 前检查：trigger 是否可观察、action 是否最小、误判边界是否写清。
