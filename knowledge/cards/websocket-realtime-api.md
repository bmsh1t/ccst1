---
id: websocket-realtime-api
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - websocket
  - cswsh
  - realtime
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# WebSocket / Realtime API

## Quick Recall

- WebSocket 要同时看握手鉴权和消息级权限；连接成功不代表频道、对象、动作都授权正确。
- 高信号点：Origin、Cookie/token、Sec-WebSocket-Protocol、订阅频道、对象 ID、消息 type/action。
- 前端输入框 sanitization 不代表消息级安全；需要直接观察/重放 WebSocket frame。
- CSWSH 需要证明跨站页面能带凭据建立连接并读取/触发敏感消息。
- WebSocket 漏洞不只在 frame 内容里；握手 header、Origin、Cookie、IP/rate-limit/WAF 上下文也会影响可利用性。
- Realtime API 常有 REST sibling，可以用同对象/角色矩阵做对照。

## 能力定位

本卡给 `web2-vuln-classes` 补充 WebSocket/订阅类 API 的权限、消息 schema 和跨站边界。

## 触发信号

- 浏览器 Network 出现 `ws://`/`wss://`、Socket.IO、STOMP、GraphQL subscription。
- 消息包含 channel、room、tenant、userId、orderId、action、subscribe、publish。
- 握手依赖 Cookie 或 bearer token，Origin 校验不明显。

## 思路分支

- Handshake auth：匿名/低权/高权是否都能连接。
- Message auth：改频道、对象 ID、action、tenant 是否泄露或执行。
- CSWSH：跨站 Origin 是否能建立带 Cookie 的连接。
- Replay/state：旧 token、重连 token、订阅恢复是否越权。
- handshake header mutation：改 Origin、Cookie/token、Sec-WebSocket-Protocol、X-Forwarded-For、Host/Forwarded 后，连接身份、过滤器、封禁和消息处理是否变化。

## 技巧家族 / Payload 家族

- 消息变体：订阅、发布、对象 ID 替换、action 改写、批量消息。
- Raw frame 变体：绕过 UI 编码，直接发送 JSON frame 或协议消息，验证服务端/接收端是否正确编码；例如 UI 表单带 `encode=true` 时，仍要 replay 原始 frame 看接收端 DOM sink。
- Origin 变体：合法 Origin、null、攻击者 Origin、同站不同源。
- CSWSH exfil 形态：跨站页面建立 `wss://target/chat`，发送初始化消息如 `READY`，把首批 server messages / history 低噪声回传到测试日志，证明读取的是 victim session 数据。
- Handshake bypass 形态：过滤器触发断连或 IP ban 后，不要只换 payload；用新握手带 `X-Forwarded-For` 或等价代理头验证封禁/风控是否按可伪造来源判定，再发送最小混淆 payload。
- 对照形态：同消息在 REST sibling 和 WebSocket 的权限差异。

## 补充 Checklist

- 是否保存 handshake header 和首批 server messages？
- 是否理解消息 schema，而不是盲改 JSON？
- 是否比较了 UI 提交后的编码消息和 raw frame 的差异？
- 是否测试了重连握手 header 变体，尤其是 Origin、Cookie/token、Sec-WebSocket-Protocol、X-Forwarded-For 和 Forwarded？
- CSWSH 是否证明跨站脚本能读取 victim session 的非公开历史/消息，而不只是成功建立空连接？
- 是否测试订阅和发布两个方向？
- 是否确认泄露的是非公开消息或可执行敏感动作？

## 最小验证

- 用浏览器捕获合法连接和消息 baseline。
- 单变量改 Origin、对象 ID、channel 或 action，比较响应消息和状态。
- 如果 UI 编码或过滤器拦截，重放 raw frame 和新握手 header，对比错误消息、断连、ban 和服务端回显。
- CSWSH 链按 `cross-site page -> handshake with cookie -> READY/subscribe -> sensitive server message -> exfil log` 验证。
- Candidate 前需要可 replay 消息、角色/对象对照和影响说明。

## 常见误判 / 死路

- 连接成功但没有敏感订阅不等于漏洞。
- 服务端回显错误消息不等于越权。
- 公开广播频道通常低价值。
- 只看前端 chat 输入框编码会漏掉 raw frame 漏洞；只换 payload 不重连会漏掉 handshake 侧绕过。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有握手、消息 schema、单变量差异和权限影响时写入 action queue，类型 `websocket-realtime-api`。
