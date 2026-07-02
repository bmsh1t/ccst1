# OAuth/SSO 邮箱信任与 audience/redirect 混淆致账户接管

## 适用场景

- 目标支持 OAuth/OIDC/SAML/SSO 登录或账号自动关联
- 登录后按 email/domain 关联到已有账户或组织
- 存在多应用共用 IdP、id_token 复用、邀请或域名信任

## 触发信号

- 回调按 email 精确匹配即登录，未校验邮箱归属或 IdP 可信度
- redirect_uri 允许子路径/子域/参数追加，response_type 可切换
- id_token 的 aud 未与当前应用校验，或 profile 字段可控

## 发散问题

- 谁保证 IdP 断言的 email 属于登录者本人？
- 预先用受害邮箱注册的"半账户"是否会被 SSO 静默接管？
- 为 A 应用签发的 token 能否在 B 应用被接受（aud 混淆）？

## 推荐动作

- 画出身份来源链：IdP -> 断言字段 -> 本地账户关联键。
- 对 redirect_uri 做单变量解析差异测试（子路径/编码/#截断）。
- 验证未验证邮箱注册后再走 SSO/找回是否合并到受害账户。

## 关联 Skills

- web2-vuln-classes
- bb-methodology
- triage-validation

## 停止条件

- 关联前强制校验邮箱归属且 aud/redirect 精确锚定
- 无法构造受害身份的断言或预置账户

## 检查要求

- 必须证明在不掌握受害凭据的前提下获得其账户/组织访问权，且可复现。

## 可晋升经验

- 联邦登录处优先追问"信任传递"三点：邮箱归属、aud、redirect 锚定。
