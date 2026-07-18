---
id: cloud-cognito-identity-pool
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - cognito
  - identity-pool
  - unauth-role
  - get-credentials-for-identity
  - cognito-sts
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# Cognito Identity Pool 匿名身份到 IAM 权限边界

## Quick Recall

- 触发：JS、mobile config、source map 或网络请求暴露 `IdentityPoolId`、`cognito-identity`、
  `GetId`、`GetCredentialsForIdentity`、unauthenticated role。
- `IdentityPoolId` 是客户端可见标识，`GetId` 成功只证明 identity pool 接受该身份模式，不是漏洞。
- 核心链是 `IdentityPoolId -> GetId -> 临时 STS 凭证 -> caller identity -> 实际 IAM 动作 -> 影响`。
- 只有匿名主体获得临时凭证，并证明其 role 对目标资源存在不应有的实际权限，才进入 Candidate。
- 无凭证、凭证立即拒绝、只有预期公开资源或无法确认 role/action 时保持 Signal/Lead。

## 能力定位

本卡是 AWS Cognito Identity Pool 的按需 case-router，补充 `cloud-control-plane-pivots` 的产品边界。
它帮助 AI 从公开配置路由到身份、角色和权限证据，不把公开标识或 API 200 自动包装成云接管。

## 触发信号

- Web/mobile 配置出现 `IdentityPoolId`、region、`AllowUnauthenticatedIdentities` 或 Cognito SDK 初始化。
- 匿名页面调用 `GetId` / `GetCredentialsForIdentity`，响应包含 `IdentityId` 或临时凭证字段。
- IAM role 名称、STS ARN、S3/AppSync/API Gateway 等资源与该 identity pool 同时出现。
- authenticated 与 unauthenticated identities 映射到不同 role，或 role mapping/claim 选择逻辑可控。

## 思路分支

- 身份模式：区分 user pool、identity pool、authenticated、unauthenticated 和 developer identity。
- 角色绑定：记录实际 STS caller ARN、account、session 名称和 token audience，不能只看配置里的 role 名。
- 权限边界：从最小 `get/list/describe` 或测试资源动作确认资源、条件、前缀和 tenant 限制。
- 连接器：检查匿名 role 是否可达对象存储、GraphQL、API Gateway、日志/遥测或其他控制面资源。
- 对照：比较匿名、正常登录身份和自有测试身份的 caller/action/resource 差异。

## 技巧家族 / Payload 家族

以下命令是变量化验证形态，不是固定执行清单：

```bash
aws cognito-identity get-id \
  --identity-pool-id IDENTITY_POOL_ID \
  --region REGION \
  --no-sign-request

aws cognito-identity get-credentials-for-identity \
  --identity-id IDENTITY_ID \
  --region REGION \
  --no-sign-request

AWS_ACCESS_KEY_ID=ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=SECRET_KEY \
AWS_SESSION_TOKEN=SESSION_TOKEN \
aws sts get-caller-identity --region REGION
```

- role mapping 变体：authenticated/unauthenticated、provider claim、ambiguous role resolution。
- resource 变体：对象前缀、API stage、GraphQL operation、region/account 条件；只从目标证据派生。
- 凭证应只在当前验证进程内使用，证据中保存 role/action/result 摘要，不保存真实 secret material。

## 补充 Checklist

- `IdentityPoolId`、region、identity type、caller ARN 和 session expiry 是否分别记录？
- 是否确认临时凭证确由匿名路径签发，而不是浏览器已有登录 session？
- policy 中的 resource、condition、prefix、source identity 和 tenant 约束是否实际命中？
- 最小动作是预期公开读取，还是跨用户、跨环境、写入、部署或敏感数据能力？
- 是否把 user pool token 验证问题与 identity pool IAM 问题分开？

## 最小验证

1. 从目标自身 JS/config 记录 identity pool 与 region，建立匿名 baseline。
2. `GetId` 成功后继续确认是否真正签发临时凭证；未签发时保持 Signal。
3. 用 `sts get-caller-identity` 保存 role identity，不记录凭证值。
4. 对单个无副作用 action 或自有测试资源做 allow/deny 对照，保存 action、resource 和结果。
5. 只有“匿名凭证 + role identity + 非预期 IAM action + 具体影响”齐全时进入验证队列。

## 常见误判 / 死路

- `IdentityPoolId`、region、client ID、`GetId` 200 都是正常客户端材料，不等于凭证泄露。
- 获得临时凭证不等于越权；最小公开遥测/上传权限可能是产品设计。
- policy 文本看似宽不等于条件实际满足；caller、resource 和 action 缺一不可。
- user pool 注册/登录与 identity pool IAM 是两套边界，不要用一边的信号替代另一边证据。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`
- `security-arsenal`

## 晋升到 Skill / Queue 的条件

- 只有 `GetId` 或公开配置时保留为 target lead。
- 匿名临时凭证和 caller identity 已确认时，交给 `cloud-control-plane-pivots` 选择最小权限验证。
- 非预期 resource action 与可复现影响齐全后，交给 `triage-validation`，沿用既有 evidence/finding owner。

## 可晋升经验

- 多个目标重复出现的 role mapping、resource condition 或前端配置到 IAM action 的证据链。
