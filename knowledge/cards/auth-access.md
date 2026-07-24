---
id: auth-access
type: technique-card
related_skills:
  - bb-methodology
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - authz
  - role
  - org-boundary
  - session
risk: medium
maturity: draft
load_priority: high
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1424291"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "2081930"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "2323303"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "138869"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1122408"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1591412"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "351361"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "287758"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "587910"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "810880"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "665722"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1276373"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "128085"
---

# 认证与访问边界

## Quick Recall

- 触发：角色、组织、session、401/403 或管理路径存在权限边界差异。
- 最小验证：同一 replay 请求在最小身份矩阵中只改变一个 method/path/header/session 变量。
- 证据门：必须证明后端实际放行了不应访问的资源或操作，不能只凭 UI 差异。
- 停止：服务端稳定拒绝、没有可复现请求，或继续操作会影响真实账号/业务状态。

## 适用场景

- 目标存在登录、注册、邀请、团队、组织、管理员、SSO 或 API token
- 同一资源可被访客、普通用户、成员、管理员等不同身份访问
- 前端和后端权限表现不一致
- 发现 401、403、重定向、登录态刷新、角色切换或账号绑定行为

## 触发信号

- 响应或 JS 中出现 role、permission、scope、team、org、tenant、member
- 路径中出现 admin、internal、settings、billing、export、audit
- 登录后 API 返回的权限字段和前端展示不一致
- 邀请、账号合并、邮箱验证、SSO 回调、token 刷新流程复杂
- 管理接口或敏感操作只在某个 method、Referer、路径前缀、header 或前端路由下被拦截
- 使用 OPA、Cedar 或外部授权服务，且 gateway/backend/worker 可能在不同位置决策或执行
- 使用 presigned URL / signed download / signed upload 作为临时访问 capability

## 发散问题

- 权限判断是在前端、网关、BFF 还是后端服务完成？
- 角色变化后，旧 token 或旧 session 是否还能访问旧权限？
- 邀请链接、重置链接、邮箱验证链接是否绑定目标账号和组织？
- SSO / OAuth / SAML 流程是否存在账号绑定、state、redirect 或 email normalization 差异？
- 403 接口是否存在方法、路径规范化、header 或后端路由差异？
- 同一能力是否有多个入口（UI、API、GraphQL、移动端、旧版端点、批量接口）？各入口守卫是否一致？
- MFA、OTP、找回等认证因子是否绑定服务端会话身份，还是信任客户端传入的 user_id 或参数？
- Method-based access：管理员用 `POST /admin-roles`，普通用户是否能用 `GET /admin-roles?username=...&action=upgrade`、`X-HTTP-Method-Override` 或 body/query 迁移绕过？
- URL-based access：`/admin` 被拦，后端是否接受 `X-Original-URL`、`X-Rewrite-URL`、encoded slash、路径大小写、尾随点/分号或反向代理重写路径？
- Referer-based access：后端是否只检查 `Referer` 来判断请求来自管理页或同站页面？
- 如果浏览器态 `fetch` 无法伪造受限头（如 `Referer`），是否已经切到 raw replay、Burp、curl 或 Playwright request 层复测？
- 登录接口是否存在 UI 未传但后端读取的隐藏认证参数或认证源切换开关？如果有，转读 `knowledge/cards/auth-hidden-switches.md`。
- OPA/Cedar 的 policy decision point 收到了哪些 actor/action/object/tenant 输入，实际 enforcement point
  是否执行了同一决策？gateway、backend、async worker、cache 是否使用一致的身份与 canonical object？
- policy/version/cache 更新后，旧 decision、旧 session 或异步任务是否继续保留已撤销权限？
- Presigned URL 的 capability 是否按预期绑定 method、对象、租户、expiry，以及上传 key/size/content-type？

## 推荐动作

- 建立最小身份矩阵：访客、普通用户、成员、管理员。
- 对同一请求做单变量身份差异比较。
- 记录权限变化前后的 token、cookie、响应字段和状态码差异。
- 对 401/403 只做低频、单变量 replay，避免无意义绕过喷洒。
- 对管理/角色接口做 method/path/header 矩阵：GET/POST/PUT/PATCH、query vs body、Referer、有无 X-Original-URL/X-Rewrite-URL、method override；一次只改一个边界。
- URL-based access 最小验证：先记录直接访问敏感路径的拒绝基线，再把内部路径放入 `X-Original-URL` / `X-Rewrite-URL`，必要时把操作参数保留在外层 URL（如 `/?username=...` + `X-Original-URL: /admin/delete`），只比较一个路由边界。
- Referer-based access 最小验证：用同一个低权限 session 对比无 `Referer` 与可信 `Referer` 的 raw replay；不要因为浏览器 `fetch` 不能设置 `Referer` 就判定不可利用。
- OPA/Cedar 最小验证：保存 gateway/backend/worker 的同一业务请求 baseline，每次只改变 actor、action、
  object、tenant 或路径 canonicalization 中一个维度；对比 policy decision、实际数据/状态和审计记录。
- 检查 decision cache/policy version 时使用权限变更前后同一请求做有界 replay，区分 stale token、stale
  decision 和 PEP 未执行；没有未授权数据/状态影响时保持 Signal/Lead。
- Presigned URL 作为 bearer capability 单独建矩阵；签名 query mutation 只验证完整性，不替代对象、租户、
  method、expiry、撤权契约或上传限制的授权验证。

## 关联 Skills

- `bb-methodology`
- `web2-vuln-classes`
- `triage-validation`
- `security-arsenal`

## 停止条件

- 没有可复现请求或身份差异
- 所有关键路径均由服务端稳定拒绝
- 只能证明前端 UI 差异，不能证明后端权限问题
- 继续测试需要影响真实用户、发送批量消息或改变真实资源状态
- method/path/header 差异只导致不同错误页、WAF 页面或路由 404，不能推进真实权限边界

## 检查要求

- Candidate 前必须证明当前攻击者身份能触达不应触达的资源或操作。
- Method-based Candidate 必须证明低权限身份用替代 method/path/header 完成了原本只有高权限可执行的操作，或读取了不应读取的数据。
- OPA/Cedar Candidate 必须证明 PDP 输入缺失、PDP/PEP 不一致、cache/policy stale 或 canonicalization
  差异导致具体未授权数据读取或状态改变；policy 文本、decision log 差异或单次 allow 本身不足。
- Presigned URL Candidate 必须证明 capability 违反目标预期边界；标准 bearer URL 在登出后继续有效不自动
  等于授权缺陷，除非存在明确撤销/会话绑定契约。
- 涉及账号绑定、邀请、SSO 时必须说明攻击前置条件。
- 任何会改变账号、订单、钱包、支付、消息状态的动作都必须遵守红线规则。

## 可晋升经验

- 某类产品的权限字段命名和真实边界之间的稳定关系
- 某种身份矩阵能快速暴露访问控制缺陷
- 反复出现但低价值的 403 差异模式
