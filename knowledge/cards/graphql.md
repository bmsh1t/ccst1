---
id: graphql
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - graphql
  - node-id
  - introspection
  - subscription
risk: medium
maturity: draft
load_priority: high
deep_refs: []
---

# GraphQL / Subscription / Global ID

## Quick Recall

- 触发：GraphQL endpoint、合法 query/variables、global ID、字段差异或 subscription 线索。
- 最小验证：从已观察 operation 出发，优先做双主体只读 node/字段或事件 role diff。
- 证据门：introspection 本身不是漏洞；权限类候选需要实际边界差异，资源放大候选需要稳定的 alias 数量与延迟/错误趋势。
- 停止：没有合法请求样本或可比较证据，或只能靠无界深层递归、alias 洪泛和大查询继续；已有合法 operation 时，可先做一次有界 alias 差异检查。

## 适用场景

- 目标暴露 `/graphql`、`/api/graphql`、GraphiQL、Apollo、Relay、Hasura 或类似接口
- 前端 JS 中出现 query、mutation、subscription、fragment、node、edges、cursor
- API 使用全局 ID、base64 ID、tenant/org/user/object id
- WebSocket 或 subscription 推送与 GraphQL 相关
- 已观察 operation 会触发验证、搜索、导出、转换或其他可重复的后端工作

## 触发信号

- 响应出现 `{"errors":[{"message":...}]}` 或 GraphQL-shaped JSON
- JS bundle 暴露 operation name、fragment、mutation 名称
- 请求 body 中存在 query、variables、operationName
- 存在 node(id)、viewer、me、organization、tenant、admin、export 等字段

## 发散问题

- query、mutation、subscription 是否使用同一权限模型？
- node/global ID 是否做 per-object auth？
- 字段级权限是否弱于对象级权限？
- 不同角色能否看到同一 schema，但字段返回不同？
- 同一 operation 的 `1/2/4` alias 对比是否出现稳定的线性或超线性延迟、超时或错误增长？

## 推荐动作

- 先从 JS 或合法请求中收集 operation 名称，不盲目爆破。
- 对 node/global ID 做双账号只读 role diff。
- 对 mutation 只做 dry-run、测试资源或请求构造层面的低风险验证。
- 对 subscription 比较不同角色/租户是否收到不应接收的事件。
- 对已观察的 operation，最多构造 `1/2/4` 个 alias variant，比较基线与变体的延迟、
  状态码、超时和错误增长；只记录可复现的放大候选，不把一次慢响应直接当作结论。
- 禁止无界深层递归、alias 洪泛或大查询；有界差异检查没有稳定趋势时回到对象/字段权限验证。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`

## 停止条件

- 没有 operation 名称、schema 线索或合法请求样本
- 既无对象 ID、角色/租户边界，也无可做有界对比的 operation
- 只能通过无界压力型 query 继续，或有界 alias 对比没有稳定差异
- 服务端稳定拒绝跨对象、跨角色、跨租户访问

## 检查要求

- GraphQL introspection alone 不等于可报告漏洞。
- 权限类 Candidate 前必须证明字段、对象、租户或订阅事件的实际越权影响。
- Alias 放大 Candidate 至少要有稳定的 alias 数量、延迟/错误趋势或变体超时证据；
  单次偶发慢响应只作线索。
- 所有 mutation 和批量查询先过 `rules/red-lines.md`。

## 可晋升经验

- 某类 operation 命名稳定提示高价值权限边界
- subscription 比 query/mutation 更容易漏权限的目标模式
- global ID 解码模式和目标对象边界之间的复用经验
