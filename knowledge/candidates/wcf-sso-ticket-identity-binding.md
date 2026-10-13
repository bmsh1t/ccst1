---
id: wcf-sso-ticket-identity-binding
type: technique-card
related_skills:
  - src-hunting
  - triage-validation
trigger_tags:
  - wcf-sso
  - service-ticket
  - identity-binding
  - wsdl
risk: high
maturity: draft
load_priority: low
deep_refs:
  - knowledge/cards/auth-sso-token-edge-cases.md
  - knowledge/cards/auth-access.md
  - knowledge/cards/information-disclosure-source-config.md
source_refs: []
---

# 老旧 WCF SSO 票据与身份绑定边界

候选状态：独立方法草稿，尚未完成目标复现、整链盲答或晋升审核。它只把“用户类型
判断 → 免密票据 → WCF 服务消费”的连接登记为待验证假设，不把接口名称或旧框架
指纹当成未授权结论。

## Quick Recall

- IIS/WCF 登录壳、旧 jQuery、`ServiceAddress` 指向内部端口和外部 `/WCF/` 前缀，
  只能说明存在值得核对的服务边界。
- `checkUserType`、`JudgeSSOLogin_*` 或 `encrypt` 字段的出现，不证明票据能代表
  任意账号；必须验证签发主体、目标账号和消费端是否一致。
- `?wsdl` 只提供操作目录。读操作、写操作、身份查询和成绩/档案返回分别结算，不能
  由一个成功响应外推整套服务权限。
- 票据拿到、服务返回 200 或 JSON 有字段，都不等于读取了不应访问的主体数据。

## 触发信号与适用条件

仅在已观察到以下材料时建立假设：登录页或前端出现 WCF/SOAP 路径；脚本暴露
`ServiceAddress`、`checkUserType` 或同类用户类型 oracle；同一站点存在
`/WCF/` 路由、`Login.svc`、`Student.svc` 或 `Teacher.svc`。需要自有或明确授权的
学生/教师测试主体、可读回的测试记录和可恢复的会话；不能通过递增学号或工号补齐
未知主体。

## 最小验证

1. 保存测试主体的正常登录基线、站点/vhost、请求方法、票据字段、账号标识和预期
   只读数据。匿名、合法票据、格式错误票据各保留一份对照。
2. 在相同 host 和 `/WCF/` 路由上，只改变一个登录标识或票据字段，确认响应中的
   `encrypt` 是否绑定该测试主体、有效期、会话或 challenge。内部端口拒绝或
     `EndpointNotFound` 只说明路由不可达，不是安全结论。
3. 先调用一个自有主体的只读服务，分别记录主体标识、档案、学期参数和返回状态。
   再用第二个自有测试主体做最小交叉对照；不使用真实他人号码，不遍历班级或全量
   学号。`SearchStuBasicInfo`、`SearchPersonal` 等名称只是入口线索，实际响应才
   决定是否访问了目标主体。
4. 若服务返回票据后可访问另一主体的受保护只读数据，沿同一票据记录签发、消费和
   服务端身份字段。密码字段、成绩、身份证号等影响分别绑定到最小必要证据；不保存
   完整敏感值。写操作或批量接口没有独立授权理由时停止。
5. 将 `?wsdl` 的操作列表与实际 handler/权限对照。WSDL 暴露写入操作不等于写入可达，
   不能为了证明能力调用会改变成绩、账号或档案的操作。

## 证据要求

证据至少绑定站点/vhost、测试主体、`loginID`/票据哈希、challenge 或时间、具体
service/operation、服务端返回的身份和只读状态。登录页提示、WSDL、状态码差异和
票面字段只能作为线索；Candidate 需要证明票据代表了错误主体，或证明受保护数据被
错误主体读到。

## 常见误判与停止条件

- `checkUserType` 能区分 1/3/4 只证明输入被分类，不证明可登录或可读取档案。
- `JudgeLogin_StudentSimple` 的限流、`JudgeLogin_Student` 要求密文 GUID、直连
  内部端口失败、路径少了 `/WCF/`，分别是请求/部署条件，不是漏洞正反证。
- 票据只返回测试账号、服务端仍要求 Cookie/二次验证、或错误主体被拒时，停止该
  分支并保留未知；不改用真实账号继续枚举。
- 没有可恢复测试主体、无法确认服务端身份或需要批量读取时，停止并转回当前
  auth/SSO 卡。

## 下一步与来源

准入后优先并入 `auth-sso-token-edge-cases` 的中间票据/身份绑定段，不创建第二套
WCF 卡。候选直接来自 v2.3 kill-chain shortlist 的老高校 WCF 行：
`skills/specialized/src-hunt-lane/references/kill-chains/shortlist.md`，源 SHA-256
`ac77785a8533d1153d66c83dd63cad8f690da5ed1c05169fd9e854d15a7c9ddd`，第 95 行。
该行仅作为方法来源，未被当作目标实测或晋升回执。

