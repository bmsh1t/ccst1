---
id: api-idor
type: technique-card
related_skills:
  - bb-methodology
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - idor
  - object-id
  - tenant
  - actor-diff
  - nextjs-data
risk: medium
maturity: draft
load_priority: high
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "158330"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "510759"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "2011431"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1773895"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "321444"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "778803"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1238017"
---

# API IDOR / 对象级越权

## Quick Recall

- 触发：请求可控对象 ID，且存在多账号、角色或租户边界。
- 最小验证：用 owner/peer 两个主体做单变量 ID 替换，保留可 replay 的 baseline。
- 证据门：必须记录主体身份、对象归属、响应字段/数量或实际操作差异；前端隐藏不算越权。
- 影响判断：先确认跨主体对象访问，再按证据区分单对象、多对象、集合/导出和跨租户范围。
- Next.js `/_next/data/<build-id>/...json` 和 `__NEXT_DATA__` 只是数据入口；必须做 anonymous、owner、
  peer/cross-tenant 的对象与字段差异，不能由 JSON 200 直接推导 IDOR。
- Presigned URL 是 capability bearer：验证对象/租户、HTTP method、过期时间和重放边界，不能把修改
  已签名 query 后被拒绝当作主要授权测试。
- Zipkin、Jaeger、OpenTelemetry trace 中的对象 ID 只是对象标识来源；必须另做 owner/peer replay
  才能证明 IDOR，trace 本身暴露敏感内容则单独按信息泄露判断。
- 停止：没有可复现请求、服务端稳定拒绝，或继续验证会改变真实资源状态。

## 适用场景

- API 中出现 `user_id`、`org_id`、`tenant_id`、`account_id`、`project_id` 等对象标识
- 存在多账号、多角色、多组织或多租户模型
- 前端隐藏管理入口，但 JS 或网络请求里能看到相关接口
- 导出、邀请、共享、删除、转移、账单、成员管理等操作围绕对象 ID 展开

## 触发信号

- URL 路径或 JSON body 中存在可替换对象 ID
- 同一接口在不同角色下返回字段不同
- JS 暴露 admin、export、invite、member、billing、share 等接口
- 响应中包含 owner、tenant、org、role、permission、scope 等字段
- Next.js 暴露 `/_next/data/<build-id>/<route>.json`、动态 route 参数或页面内 `__NEXT_DATA__`

## 发散问题

- 替换对象 ID 后，服务端是否重新校验归属关系？
- 列表接口、批量接口、导出接口是否比单对象接口更宽松？
- 低权限用户能否读取高权限对象的元数据或数量信息？
- 只读接口和写操作是否使用不同鉴权路径？
- 邀请、共享、转移类操作是否只校验发起人身份，没有校验目标对象归属？
- 序列化、导出、脱敏是否是独立后处理阶段？是否存在跳过它、直接读到越界字段的路径？
- `/_next/data` 与对应 HTML/API route 是否使用同一 session、对象绑定和字段脱敏逻辑？
- 资源是否按非唯一标识（拼接名、标签集、邮箱）识别？能否构造碰撞接管他人对象？
- Presigned URL 是否绑定正确对象、租户、method、有效期、上传 key/size/content-type？在登出、撤权、
  对象转移或租户变更后重放时，实际契约是否要求失效？
- Trace/observability 暴露的对象 ID 能否在独立的低权限主体请求中读取或修改非所属对象？

## 推荐动作

- 使用两个账号或两个组织做 role diff。
- 对 `/_next/data` 保持 build-id/route 不变，分别比较 anonymous、owner、peer/cross-tenant；动态 ID
  只替换一个对象变量，并和对应 HTML/API baseline 交叉确认。
- 单次只替换一个变量，例如对象 ID、组织 ID 或路径层级。
- 比较状态码、对象数量、敏感字段、错误信息和审计事件。
- 按以下范围梯度选择下一步，只在证据支持时晋级：单个跨主体对象 -> 第二个对象 ->
  列表/批量/导出 -> 跨租户或全局可达；未达到下一层时保留当前范围判断。
- 优先验证读取类影响，再评估写操作，避免直接造成破坏性副作用。
- Presigned URL 使用分别签发的 owner/peer、对象、method 和时间边界样本做矩阵；下载与上传分开，
  上传额外比较服务端实际落点、key prefix、size/content-type 限制和 read-back。不要以篡改签名覆盖的
  query 参数为主路径，因为签名失败只能证明完整性校验存在。
- 从 Zipkin/Jaeger/OpenTelemetry 只提取最小必要对象标识，再用独立 actor-object replay 验证授权；
  不把 trace UI 可达、trace ID 可猜或单次 200 直接升级为 IDOR。

## 关联 Skills

- `bb-methodology`
- `web2-vuln-classes`
- `triage-validation`

## 停止条件

- 没有可控对象 ID 或无法构造跨主体请求
- 服务端稳定拒绝跨租户或跨用户访问
- 只有前端展示差异，没有后端行为差异
- 需要破坏性写操作才能继续，但用户当前回合没有明确授权

## 检查要求

- 不能只凭前端隐藏按钮判断漏洞。
- `/_next/data`、`__NEXT_DATA__` 或 prerender JSON 可读不等于越权；公开页面数据、构建 metadata 和
  当前 owner 自身数据只能保持 Signal。
- 验证工具的 `tested_clean` 只是执行层标签；若 raw response 暴露订单、发票、地址、
  支付等私有业务对象，AI 可基于业务语义升级为 Lead/Candidate，并补可发现性、
  对象归属和影响证据。
- Candidate 前必须有可 replay 请求和权限差异证据。
- Presigned URL Candidate 必须证明 capability 超出预期对象、租户、method、时间或上传约束，并产生
  未授权数据/状态影响；仅“登出后仍可用”需先核对该 capability 的撤销契约。
- Observability 标识 Candidate 必须有独立 owner/peer 权限差异；trace 中 token、PII、请求体或内部地址
  的暴露属于 information-disclosure 证据，不能替代对象授权证明。
- 报告前必须能说明攻击者当前权限、受害对象、越权结果、数据敏感度和已证实影响范围；
  可枚举性或全局影响不能只由顺序 ID 推测。

## 可晋升经验

- 某类命名模式反复指向高价值对象边界
- 某个框架或产品形态中列表/导出接口反复弱于详情接口
- 某类字段组合能稳定提示多租户边界
