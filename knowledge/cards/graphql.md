# GraphQL / Subscription / Global ID

## 适用场景

- 目标暴露 `/graphql`、`/api/graphql`、GraphiQL、Apollo、Relay、Hasura 或类似接口
- 前端 JS 中出现 query、mutation、subscription、fragment、node、edges、cursor
- API 使用全局 ID、base64 ID、tenant/org/user/object id
- WebSocket 或 subscription 推送与 GraphQL 相关

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
- 批量查询、alias、深层嵌套是否只是风险线索，而不是压力测试目标？

## 推荐动作

- 先从 JS 或合法请求中收集 operation 名称，不盲目爆破。
- 对 node/global ID 做双账号只读 role diff。
- 对 mutation 只做 dry-run、测试资源或请求构造层面的低风险验证。
- 对 subscription 比较不同角色/租户是否收到不应接收的事件。
- 禁止用深层递归、alias 洪泛或大查询做压力测试。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`

## 停止条件

- 没有 operation 名称、schema 线索或合法请求样本
- 无对象 ID、角色差异或租户边界
- 只能通过压力型 query 继续
- 服务端稳定拒绝跨对象、跨角色、跨租户访问

## 检查要求

- GraphQL introspection alone 不等于可报告漏洞。
- Candidate 前必须证明字段、对象、租户或订阅事件的实际越权影响。
- 所有 mutation 和批量查询先过 `rules/red-lines.md`。

## 可晋升经验

- 某类 operation 命名稳定提示高价值权限边界
- subscription 比 query/mutation 更容易漏权限的目标模式
- global ID 解码模式和目标对象边界之间的复用经验
