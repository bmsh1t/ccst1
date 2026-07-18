---
id: auth-hidden-switches
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - bug-bounty
  - triage-validation
trigger_tags:
  - hidden-auth-param
  - login-branch
  - auth-state-machine
  - alternate-auth-surface
  - legacy-auth-surface
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# 隐藏认证参数 / 登录分支开关

## Quick Recall

- 触发：登录请求或相邻材料暴露隐藏参数、认证源、模式、渠道或旧入口。
- 最小验证：用自有/测试账号建立三组 baseline，每次只改变一个分支选择器。
- 证据门：必须出现 session、token、角色、用户身份或后端认证状态的稳定差异。
- 旧 REST、mobile、SOAP/XMLRPC 或 native-auth 入口只有在相同测试账号下表现出更弱的 MFA、SSO、
  限速、session 或角色策略时才是认证绕过候选；端点可达本身不是漏洞。
- 停止：只有用户名枚举/文案变化，或需要爆破、OTP 绕过和真实账号尝试。

## 能力定位

本卡用于认证、ATO、登录绕过或管理入口测试中，补充隐藏认证分支、非 UI 参数、旧入口、移动端入口和认证状态机切换的联想方向。输出候选假设、发散问题和最小验证提示，供当前认证测试流程选择使用。

## 核心原则

- UI 展示的登录字段不等于后端真实认证状态机；隐藏字段、模式、来源、渠道、provider、feature flag 或旧入口可能切换认证分支。
- 标准验证链路是自有/测试账号 baseline -> 目标材料提取候选分支选择器 -> 单变量差异 -> session/token/role/身份状态验证 -> 最小证据停点。
- 用户名枚举、错误文案差异、旧端点、移动端端点、管理子域、调试字段和 source/browser 线索都只能作为入口信号，不能直接当漏洞。
- 自定义/branded 登录页只代表一个入口；相邻 mobile API、旧版本 REST、SOAP/XMLRPC、native login
  可能是独立认证 surface，必须与当前官方入口做同账号策略对照，而不是默认认为它绕过 SSO/MFA。
- 自动化默认不尝试真实第三方账号、无边界口令喷洒、OTP/验证码爆破、绕过锁定、社工或扩大接管；口令测试必须由 operator 或 `/autopilot` 按 `rules/red-lines.md` 切到受控 `/spray` / `credential-attack`。

## 方法模型

- 分支选择器思维：把隐藏参数看成认证状态机的 selector，而不是只猜某几个固定字段名。
- 目标材料提词：从 JS/source/browser XHR、历史请求、移动端 API、旧入口、错误字段、schema、表单残留和 sibling endpoint 提取候选字段和值。
- 身份矩阵验证：用正确用户名+错误密码、错误用户名+错误密码、自有账号正确登录作为 baseline，比较加入单个隐藏参数后的认证状态。
- Surface parity：保持测试账号、凭据和目标身份不变，比较 UI/SSO、mobile、legacy REST、SOAP/XMLRPC
  在 MFA/step-up、限速/锁定、session/token、角色/租户和 logout/password-change 生命周期上的结果。
- 状态证据优先：只有 Set-Cookie、token、角色、用户 ID、登录后页面、权限差异或服务端身份变化，才进入 Candidate；错误文案差异只是 Signal。
- 分流边界：当方向变成弱口令、默认凭据、password spray、OTP 或验证码测试时，退出本 lane，转受控凭据流程。

## 候选形态示例

这些只是联想种子，不是固定字典；只有目标材料、错误信息、JS/source、
历史请求、相邻接口或登录语义支持时才优先尝试。

- 布尔/开关值：`true`、`false`、`1`、`0`、`yes`、`no`。
- 角色/特权字段：`isAdmin`、`admin`、`superAdmin`、`privileged`、`role`、`permission`。
- 认证源/模式字段：`authType`、`loginType`、`source`、`provider`、`channel`、`mode`、`soap`。
- 替代入口：目标自身 JS/source/docs/error 暴露的 mobile/legacy/native/SOAP/XMLRPC/sibling login；
  只验证有证据的端点，不维护跨产品固定路径矩阵。
- 内部/预留账号语义：`cadmin`、`sysadmin`、`operator`、`test`、`debug`、`internal` 只能作为目标相关账号线索，不能无边界批量尝试。
- 组合形态：`isAdmin=true`、`admin=1`、`soap=true`、`source=mobile`、`provider=local`，需要单变量对照和认证状态证据。

## 默认不执行的动作

- 不把具体字段名、认证源、管理子域命名或绕过值固定为必选清单。
- 不把用户名枚举、错误信息差异或“无防爆破”直接升级为高价值发现。
- 不执行批量尝试真实用户、绕过锁定/验证码/OTP、扩大接管或访问他人真实数据的动作。

## 适用场景

- 目标存在登录框、管理后台、数据平台、旧版入口、移动端入口、第三方登录入口或多认证源迹象。
- 登录请求是 JSON、表单或 GraphQL mutation，且包含 `username` / `email` / `password` 等字段。
- JS、历史 URL、source-intel 或浏览器 XHR 暴露了未在 UI 中展示的登录参数、模式参数、来源参数、渠道参数或 sibling endpoint。
- 存在用户名枚举、错误信息差异、调试字段、测试环境、管理子域或旧版本登录路径。

## 触发信号

- 登录响应对“用户不存在”和“密码错误”有稳定差异。
- 登录接口附近出现模式、类型、来源、渠道、provider、认证源、调试、测试、自动校验、验证开关、feature flag 等字段名或值。
- 参数值为 `true`、`false`、`1`、`0`、`yes`、`no` 时，登录错误、状态码、响应字段或 session 行为发生稳定变化。
- 管理后台、数据平台、旧系统或移动端登录入口与已知子域/路径存在命名相似、版本相邻或业务相邻关系。
- 同一产品同时出现 branded SSO 页面和旧 REST/mobile/SOAP/XMLRPC/native authentication surface。
- 返回包异常包含用户名、角色、token、密码字段、后端认证源或调试信息。

## 发散问题

- 是否存在隐藏参数切换认证后端、认证源、模式、渠道、旧入口、测试分支、内部校验或 feature flag？
- 是否存在管理员预留的特权参数、内部账号分支、兼容认证源或调试登录路径？
- 服务端是否只校验用户名存在，然后由隐藏布尔参数跳过密码校验？
- UI 没有传的字段，后端是否仍然读取并影响认证流程？
- 相邻子域、旧版本 API、移动端 API 是否使用同一登录处理器但参数约束更弱？
- 相同测试账号通过替代入口后，是否真正绕过了官方入口要求的 MFA/step-up、IP/tenant policy，或获得
  生命周期/角色不同的 session，而不是只返回不同错误格式？
- 错误信息差异是否只是枚举信号，还是能进一步证明认证状态改变？

## 推荐动作

- 只使用自有账号、测试账号或明确授权的演示账号做验证；不要默认测试真实第三方账号。
- 先记录 baseline：正确用户名+错误密码、错误用户名+错误密码、正确用户名+正确密码。
- 每次只增加或修改一个隐藏参数，比较状态码、响应长度、错误码、Set-Cookie、token 字段和登录后身份。
- 对替代入口先匿名确认协议/方法，再用同一测试账号做一次官方入口与一次替代入口对照；记录 MFA、
  限速、session/token、身份页和角色结果，缺实际策略差异时立即停止。
- 候选隐藏参数和值来自 JS/source/browser/历史请求/移动端 API/旧入口/同业务接口/错误字段/schema，不做无边界大字典喷洒。
- 如果出现疑似绕过，立即停在最小证据：证明认证分支变化或自有账号异常登录即可，不扩大到任意真实用户。

## 关联 Skills

- `web2-vuln-classes`
- `bb-methodology`
- `bug-bounty`
- `triage-validation`

## 停止条件

- 差异只来自用户名枚举，无法影响认证状态。
- 隐藏参数只改变前端错误文案，不产生 session、token、角色或后端身份差异。
- 方向已经从隐藏认证参数验证转为口令爆破、验证码/OTP 绕过、批量用户枚举或真实账号尝试；当前 lane 停止，转 `skills/credential-attack/` 或受控 `/spray` 流程。
- 目标有明确锁定、告警或速率限制风险，且没有低风险测试账号路径。

## 检查要求

- 不把“无防爆破”本身当作高价值发现；必须证明 ATO、凭证泄露或认证绕过影响。
- 不把 legacy/mobile/SOAP/XMLRPC/native endpoint 可达、返回 200/401、列出方法或接受请求格式直接
  当作绕过；Candidate 必须证明认证策略或最终 session/identity/role 的非预期差异。
- 不把用户名枚举直接升级为 Candidate，除非能链到可证明的登录绕过或敏感数据泄露。
- Candidate 前必须有可 replay 请求、最小身份矩阵和认证状态差异证据。
- 涉及真实账号、密码、OTP、验证码、批量枚举时，必须先区分受控口令测试与红线行为；可测的口令场景转 `skills/credential-attack/` 或受控 `/spray`，无边界/高频/会造成锁定或轰炸的场景按 `rules/red-lines.md` 降级或停止。

## 可晋升经验

- 某类登录框架或内部平台反复暴露隐藏认证分支选择器。
- 某类管理子域命名规律能稳定引出更高价值登录面。
- 某类隐藏参数值能稳定切换认证分支，但验证方式必须保持低频和自有账号范围内。
