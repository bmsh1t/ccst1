---
id: api-testing-workflow
type: workflow-card
related_skills:
  - web2-vuln-classes
  - web2-recon
  - triage-validation
trigger_tags:
  - api-testing
  - rest-api
  - soap-api
  - mobile-api
  - openapi
risk: medium
maturity: draft
load_priority: high
deep_refs:
  - knowledge/cards/api-idor.md
  - knowledge/cards/missing-parameter-discovery.md
  - knowledge/cards/graphql.md
  - knowledge/cards/xxe-xml-parser.md
---

# API Testing / 接口攻击面验证

## Quick Recall

- API testing 不是只扫 `/api/`；要合并 docs/schema、JS/source、浏览器 XHR、mobile/旧版本、GraphQL/SOAP 和真实业务流量。
- 先建立 endpoint + method + auth + object + content-type matrix，再选漏洞 lane。
- 高价值优先看 BOLA/IDOR、Authz、mass assignment、隐藏特权参数、parser/content-type 差异、method override、HPP、版本差异和注入 sink。
- 示例参数可以具体，例如 `isAdmin:true`、`role:"admin"`、`scope:"internal"`、`sopa:true`，但它们只是候选形态，不是固定字典；优先来自目标自己的 schema、JS、错误和历史请求。
- 写操作优先用 dry-run、预览、自有测试资源、可回滚动作或只读差异验证，不为了覆盖率直接修改真实数据。

## 能力定位

本卡给 `web2-vuln-classes` 提供 API 类目标的组织方式和补漏 checklist。它负责让 AI 想到更多 API 入口和边界，不接管 `/surface`、`/autopilot` 或具体漏洞 Skill 的执行流程。

## 触发信号

- REST、GraphQL、SOAP/XML、mobile API、OpenAPI/Swagger、Postman、HAR、JS bundle、source-intel route 或浏览器 XHR。
- URL/JSON/body 中出现对象 ID、租户/组织字段、角色字段、批量查询、导出、邀请、成员、账单、审批、报表、文件和配置接口。
- 错误响应暴露 schema、required field、type mismatch、unknown field、method not allowed、unsupported media type 或 parser stack。
- 同一业务在 Web、mobile、v1/v2/v3、GraphQL/REST、browser/raw request 下行为不同。

## 思路分支

- Discovery：从 OpenAPI/Swagger/Postman、JS/source、browser-observed XHR、mobile endpoints、robots/manifest、错误页面和历史 URL 合并 endpoint。
- Auth Matrix：匿名、普通用户、同组织成员、跨组织成员、管理员或测试账号之间对比同一请求。
- Object Matrix：替换 path/body/query/header 中的对象 ID、租户 ID、批量数组、filter、include、fields、export 范围。
- Parser Diff：JSON、form、multipart、XML、text/plain、GraphQL batch、duplicate params、array/object wrap、method override、旧 API version。
- Hidden Capability：寻找 UI 未传但后端读取的字段，尤其是 role/scope/admin/internal/debug/preview/source/channel/provider 这类目标相关 selector。
- Injection Sink：搜索、排序、filter、GraphQL resolver、NoSQL operator、SQL-backed report、XML parser、template/render、webhook/import URL。

## 技巧家族 / Payload 家族

- Mass assignment 形态：在自有对象上尝试目标衍生字段，例如 `isAdmin`、`role`、`scope`、`plan`、`features`、`internal`、`sopa`；只看字段是否被接受或影响自有状态。
- HPP/duplicate 形态：query/body 同名参数、JSON 重复 key、数组包裹、对象包裹、路径 ID 与 body ID 不一致。
- Method/version 形态：同一路由的 GET/POST/PUT/PATCH/DELETE/OPTIONS、`X-HTTP-Method-Override`、`/v1` vs `/v2`、mobile vs web。
- Content-type 形态：JSON endpoint 是否接受 form/XML/text/plain/multipart；XML 命中后转 `xxe-xml-parser`。
- Docs/schema 形态：required/optional 字段、nullable、enum、hidden models、admin schema、deprecated endpoint、example body。
- Browser/raw diff：前端不发送的字段、token、CSRF、Origin、Referer、device/channel header 是否只是 UI 约束。

## 补充 Checklist

- 是否把 docs/schema、JS/source、浏览器 XHR 和历史 URL 去重合并？
- 是否记录 endpoint、method、auth state、content-type、对象 ID 来源和业务流程？
- 是否对同一业务测了 web/mobile/version/GraphQL/REST 差异？
- 是否做了角色/组织/对象矩阵，而不是只用一个账号成功访问？
- 是否检查了 list/detail/export/bulk/report/invite/member/billing/config 等高价值 API？
- 是否把 parser/content-type 差异路由到 SQLi、NoSQLi、XXE、SSRF、upload、template/RCE 等具体 lane？

## 最小验证

- 先保存合法 baseline：请求、响应、账号角色、对象归属、method、content-type 和业务状态。
- 每次只改变一个变量，例如对象 ID、角色字段、method、content-type、版本、hidden param 或 duplicate param。
- 读类影响用字段集合、对象数量、403/200 差异、错误结构和测试对象内容证明。
- 写类影响优先用自有测试对象、预览/dry-run、无副作用字段或训练资源；需要修改真实高影响状态时交给当前 Skill 做显式风险决策。

## 常见误判 / 死路

- Swagger/OpenAPI 暴露不等于漏洞；要证明未授权访问、越权对象、隐藏能力或注入影响。
- 400/415/422 只是 parser 或 schema 信号，不是 Candidate。
- OPTIONS/Allow 暴露方法通常只是线索；必须证明对应方法可被越权调用。
- Mass assignment 字段被回显不代表持久化或权限改变；必须证明服务端状态或授权行为变化。
- API key/client id/公开 token 暴露不一定高价值，除非能链到实际权限、数据或业务动作。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 发现对象/角色/租户矩阵差异时，转 `api-idor` 或 `auth-access`。
- 发现缺参/schema/隐藏参数信号时，转 `missing-parameter-discovery`。
- 发现 XML/SOAP/content-type 接受 XML 时，转 `xxe-xml-parser`。
- 发现 filter/search/sort/operator 语义时，转 SQLi/NoSQLi 对应卡。
- 需要批量补测 endpoint matrix 时，写入 action queue，类型 `api-testing-workflow`。

## 可晋升经验

- 某类 API 框架的错误、schema 或版本差异能稳定导向高价值漏洞。
- 某类 hidden parameter 或 mass assignment 字段在多个目标中可复用。
- 某类 browser/raw/mobile 差异反复揭示真实鉴权边界。
