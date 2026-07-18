---
id: grpc-api-boundaries
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - grpc
  - grpc-web
  - grpc-reflection
  - protobuf
  - rpc-gateway
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# gRPC Transport、方法与授权边界

## Quick Recall

- 触发：`application/grpc`、`grpc-status`、HTTP/2 trailers、protobuf、reflection、gRPC-Web、
  grpc-gateway 或 JSON transcoding。
- status `12` 只说明 transport 到达但方法未实现/未匹配；`16`/`7` 表示认证/授权门在工作；
  `3` 表示方法可达但参数无效；status `0` 仍需私有数据、对象或状态影响证据。
- Reflection 是 schema/enumeration enabler，不是漏洞；公开 service/method 名也不是越权。
- 比较 edge proxy 与 backend 的 headers、trailers、authority、metadata 和身份传播，寻找边界差异。
- gRPC-Web、gateway、transcoding 可能把原本内部 RPC 暴露到浏览器/JSON 边界，仍按对象/角色差异验证。

## 能力定位

本卡补充 API/WebSocket/代理测试中的协议分支，帮助 AI 区分 transport 指纹、方法可达性、认证授权和
真实 RPC 影响。它不导入大规模 RPC fuzz 或 DoS 清单，也不替代 protobuf/schema 的目标特定分析。

## 触发信号

- HTTP/2 响应含 `content-type: application/grpc*`、`grpc-status`、`grpc-message` 或 trailers。
- JS/source/mobile binary 暴露 `.proto`、service/method、gRPC-Web client、Envoy transcoder 配置。
- 同一 RPC 同时存在直连 backend、edge proxy、gRPC-Web 或 REST/JSON gateway。
- metadata 中出现 `authorization`、tenant/user/account ID、`x-forwarded-*`、authority 或内部身份头。

## 思路分支

- Transport：h2/h2c/TLS/ALPN、content-type、framing 和 edge/backend 是否一致。
- Discovery：reflection、公开 proto、generated client、gateway descriptor 分别能提供哪些方法/字段。
- Authentication：cookie/bearer/mTLS/metadata/first-message 身份在 edge 到 backend 是否保真。
- Authorization：service、method、message field、object/tenant ID 和 streaming message 是否逐层校验。
- Re-exposure：内部 RPC 是否经 gRPC-Web/gateway/transcoding 变成匿名或低权限可达的外部接口。

## 技巧家族 / Payload 家族

```bash
grpcurl -plaintext HOST:PORT list
grpcurl -H 'authorization: Bearer TOKEN' HOST:PORT package.Service/Method
```

- baseline 族：不存在 service、存在 service/错 method、空 message、合法最小 message。
- 身份族：匿名、低权限、自有第二身份、edge 与 backend；一次只改变一个 metadata 维度。
- message 族：目标自身 proto 中的 object/tenant/resource 字段、oneof、wrapper/null/default 值。
- gateway 族：同一 method 的 binary gRPC、gRPC-Web 和 JSON transcoding 请求/响应差异。

## 补充 Checklist

- status 来自 HTTP status、gRPC trailers 还是 gateway JSON 映射？
- reflection 与实际 method invocation 是否在同一 listener/authority/身份边界？
- edge 是否剥离、覆盖或错误信任 caller-controlled metadata？
- unary、client/server streaming 和 bidi streaming 是否使用相同的每消息授权？
- gateway 暴露字段、默认值、枚举和错误信息是否与 backend protobuf 语义一致？

## 最小验证

1. 保存一次原始 h2 headers/body/trailers baseline，确认真正的 gRPC/gRPC-Web/gateway 形态。
2. 用不存在方法、合法方法+无效参数区分 status `12` 与 `3`；不要由 `12` 推导可利用方法。
3. 对单个目标特定 method 比较匿名/低权限/自有第二身份，记录 status、message 字段和状态 read-back。
4. 若存在 edge/backend 双入口，保持相同 method/message，只比较 authority/metadata 传播差异。
5. 只有 status `0` 或稳定差异产生非预期数据/动作/对象边界时进入 Candidate。

## 常见误判 / 死路

- HTTP 200 是 gRPC transport 常态，不能替代 `grpc-status` 和 message 证据。
- status `12`、reflection 开启、proto 泄露或 service 列表只算攻击面信息。
- status `3` 只说明参数校验路径可达，不等于认证或授权绕过。
- edge 返回不同错误页可能只是协议转换；缺 backend/object/state 差异时不要升级。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`
- `security-arsenal`

## 晋升到 Skill / Queue 的条件

- 只有 transport/reflection/schema 信号时回到 recon/API surface。
- 已有可调用 method 和身份/对象字段时，交给 `web2-vuln-classes` 的 API/access-control lane。
- 非预期数据或状态影响可复现后，进入 `triage-validation`。

## 可晋升经验

- 多目标复现的 edge/backend metadata 差、gateway 字段语义差或 streaming 授权遗漏。
