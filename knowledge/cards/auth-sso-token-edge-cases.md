---
id: auth-sso-token-edge-cases
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - triage-validation
trigger_tags:
  - jwt
  - jwe
  - jwks
  - oauth
  - oidc
  - saml
  - sso
  - token-binding
  - email-trust
  - audience
  - redirect-uri
risk: medium
maturity: draft
load_priority: medium
deep_refs:
  - /root/tool/ccst/ctf-skills/ctf-web/auth-jwt.md
  - /root/tool/ccst/ctf-skills/ctf-web/auth-infra.md
  - /root/tool/ccst/ctf-skills/ctf-web/auth-and-access.md
---

# Auth / SSO / Token 边界异常

## Quick Recall

- 认证系统的高价值点通常不在“是否能登录”，而在 token 信任边界、回调绑定、
  账号绑定、issuer/key 选择、state/nonce/PKCE、SAML RelayState/NameID/ACS。
- JWT/JWE/JWKS/OIDC/SAML 线索出现时，先做只读 decode、metadata 读取和合法
  流程 baseline，再做单变量差异。
- 重点证明服务端是否信任了攻击者可控 claim、key source、redirect/state、email
  或 account-linking 输入。
- OAuth/SSO 里最容易被低估的不是 token 语法，而是信任传递：邮箱归属、预注册
  半账户、cross-client `aud` 和 callback 锚定错误，经常直接落到账户接管。
- 不把公开 client_id、OAuth client_secret、用户名枚举、缺少 PKCE 文案直接升级
  为 Candidate；必须证明账号、会话、租户或权限边界影响。
- 深挖时读取 `deep_refs` 中的 auth 深度参考，提取 token/SSO 边界差异和验证模型，
  不照搬凭证收割、真实账号接管或 destructive IdP/API 操作。

## 能力定位

本卡为 `auth-access` 和 `auth-hidden-switches` 补充 token/SSO 深水区思路：
当目标出现 JWT/JWE/JWKS、OAuth/OIDC、SAML、SSO、IdP 或 account-linking 证据时，
帮助当前 Skill 选择高价值、低影响的验证路径。它不替代身份矩阵，也不替代
`triage-validation`。

## 触发信号

- 请求或存储中出现 JWT/JWE、`kid`、`jku`、`jwk`、`iss`、`aud`、`sub`、`nonce`、
  `state`、`RelayState`、`SAMLResponse`、`NameID`、`ACS`、JWKS/OIDC metadata。
- OAuth/OIDC callback、SSO callback、account linking、invite、email verification、
  password reset 或 tenant switch 流程复杂。
- JS/source/browser 暴露 auth client、issuer、JWKS endpoint、token refresh、role claim、
  org/tenant claim、email claim 或 callback allowlist。
- 同一用户在旧 API、移动端、管理面、SSO 后端之间有不同 token/role/session 表现。
- 401/403、redirect、callback、state mismatch、token refresh 错误里泄露 issuer、
  client、claim、key lookup 或 SAML 解析细节。

## 思路分支

- Token trust boundary：服务端是否只 decode 不 verify，或混用签名/加密/解析结果。
- Key selection boundary：`kid` / `jku` / `jwk` / JWKS / issuer metadata 是否可被攻击者影响。
- Claim binding boundary：`sub`、`email`、`role`、`org`、`tenant`、`balance` 等 claim
  是否和服务端状态二次校验。
- Callback binding boundary：`redirect_uri`、`state`、`nonce`、PKCE、RelayState 是否绑定
  当前 session、client、issuer 和 callback。
- Account-linking boundary：SSO 返回的 email / NameID / external_id 是否能绑定到错误账号。
- Session lifecycle boundary：refresh token、旧 token、登出、角色变化后 token 是否仍可访问旧权限。

## 技巧家族 / Payload 家族

- JWT/JWE 形态识别：3 段 token、5 段 JWE、header/claim decode、issuer/JWKS metadata 读取。
- Key source 差异：`kid` 选择、JWKS 路由、JWK/JKU header、issuer allowlist、key cache；必须和 claim-only tamper 分离，单独证明服务端是否真的采用了 header-controlled key source。
- Algorithm / verification 差异：算法白名单、none/HS/RS 混用、decode-only、aud/iss/exp/nbf 校验缺失；alg confusion 要固定 claim 与 key source，只改变算法/签名材料并观察身份差异。
- Claim tamper 差异：保持原 header/signature 或使用无效签名，只改 `sub`/role/org 等 claim；
  如果服务端身份随 claim 改变，说明存在 decode-only 或 verification bypass 线索。
- OAuth/OIDC 差异：redirect_uri 规范化、state/nonce 绑定、PKCE enforcement、code reuse、
  callback open redirect、client confusion。
- SAML 差异：NameID/email 映射、RelayState 绑定、ACS endpoint、签名覆盖范围、XML parser 差异。
- Account-linking 差异：email normalization、verified email、external_id、tenant/org 绑定。

示例是候选形态，不是固定字典；只有目标证据支持时才优先尝试。

## 补充 Checklist

- 是否已经保存合法流程 baseline：authorize request、callback、token exchange、session cookie、
  refresh、logout 或 role change？
- token 中哪些 claim 被前端展示，哪些被后端鉴权实际使用？
- issuer/JWKS/OIDC metadata 是固定配置，还是随请求、tenant、host、header、token header 改变？
- redirect_uri/state/nonce/PKCE 是否绑定到当前 session，而不是只做存在性检查？
- SAML/OIDC identity 是否绑定稳定 external_id，还是只靠 email / NameID 文本？
- 角色/组织变化后，旧 token / refresh token / SSO session 是否仍保留旧权限？

## 最小验证

- 先做只读 decode 和 metadata 读取，不修改真实账号状态。
- 用自有/测试账号记录 A/B baseline：普通登录、SSO 登录、refresh、登出、角色变化前后。
- 每次只改变一个 token/header/callback 参数，比较状态码、Set-Cookie、token、身份、角色、
  org/tenant 和后端权限差异；JWK/JKU/KID/alg confusion 先保存 claim-only invalid-signature 对照，再做 key-source/algorithm 单变量请求。
- JWT verification 检查先用 claim-only tamper 建立信号：改 `sub` 或 role 后访问只读身份页/
  admin 页面，确认服务端实际身份变化；不要把“token 可编辑”当成结论。
- 对 redirect/state/nonce/PKCE，用自有账号或本地 callback 证明绑定缺失，不诱导真实用户。
- 对 SAML/OIDC account linking，只证明测试账号或自有账号的错误绑定可能性，不接管真实账号。
- Candidate 前必须有 replayable 请求、身份差异、边界解释和影响说明。

## 常见误判 / 死路

- JWT 可 decode 不等于可篡改。
- 公开 JWKS / OIDC metadata 不等于漏洞。
- mobile/public OAuth client_secret 通常不是高价值发现，除非能链到实际 code/token misuse。
- redirect_uri 报错差异不等于可劫持；必须证明 code/token/session 会到攻击者控制位置。
- 缺少 PKCE 不一定是漏洞；要看 client 类型、code 绑定、client secret、redirect 约束和攻击前提。
- SAML XML 可解析不等于签名绕过；要证明签名覆盖范围或身份映射错误。

## 关联 Skills

- `web2-vuln-classes`
- `bb-methodology`
- `triage-validation`
- `security-arsenal`

## 晋升到 Skill / Queue 的条件

- 只有 token/SSO 线索时，作为知识启发，由当前 auth lane 收集 baseline。
- 出现明确 token/callback/issuer/key source/identity binding 的 next question 时，写入
  `tools/action_queue.py`，类型可标记为 `auth-sso-token-edge-case`。
- 出现稳定身份、角色、租户、session 或 account-linking 差异时，交给
  `triage-validation`。

## 可晋升经验

- 某类 IdP / SSO / JWT 库在目标里反复出现同类绑定缺陷。
- 某类 callback / redirect / token refresh baseline 能稳定暴露高价值 auth 边界。
- 某类 public client / metadata / error 差异多次低价值，应沉淀为 dead-end 条件。

## 源报告（on-demand）

- source_report_ids: `671406`, `1074047`, `101962`, `1889161`, `151058`, `892904`, `1923672`, `1567186`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
