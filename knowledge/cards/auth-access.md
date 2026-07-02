# 认证与访问边界

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

## 推荐动作

- 建立最小身份矩阵：访客、普通用户、成员、管理员。
- 对同一请求做单变量身份差异比较。
- 记录权限变化前后的 token、cookie、响应字段和状态码差异。
- 对 401/403 只做低频、单变量 replay，避免无意义绕过喷洒。
- 对管理/角色接口做 method/path/header 矩阵：GET/POST/PUT/PATCH、query vs body、Referer、有无 X-Original-URL/X-Rewrite-URL、method override；一次只改一个边界。
- URL-based access 最小验证：先记录直接访问敏感路径的拒绝基线，再把内部路径放入 `X-Original-URL` / `X-Rewrite-URL`，必要时把操作参数保留在外层 URL（如 `/?username=...` + `X-Original-URL: /admin/delete`），只比较一个路由边界。
- Referer-based access 最小验证：用同一个低权限 session 对比无 `Referer` 与可信 `Referer` 的 raw replay；不要因为浏览器 `fetch` 不能设置 `Referer` 就判定不可利用。

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
- 涉及账号绑定、邀请、SSO 时必须说明攻击前置条件。
- 任何会改变账号、订单、钱包、支付、消息状态的动作都必须遵守红线规则。

## 可晋升经验

- 某类产品的权限字段命名和真实边界之间的稳定关系
- 某种身份矩阵能快速暴露访问控制缺陷
- 反复出现但低价值的 403 差异模式
