---
id: auth-credential-recovery-flows
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - password-reset
  - account-recovery
  - username-enumeration
  - credential-attack
  - mfa
risk: medium
maturity: draft
load_priority: high
deep_refs:
  - knowledge/cards/auth-access.md
  - knowledge/cards/proxy-cache-boundaries.md
---

# 认证 / 凭证 / 账号恢复流程

## Quick Recall

- 账号恢复要建模绑定关系：reset token 绑定哪个账号、提交表单里的 username/email 是否被信任、重置后是否直接建立 session。
- 密码重置、邮箱验证、MFA、remember-me、账号锁定、用户名枚举和口令测试属于同一类认证状态机边界。
- 典型候选：hidden `username` 可改、reset token 可跨账号复用、旧 token 未失效、Host/XFH 污染 reset link、错误响应暴露用户存在性。
- 口令/OTP/remember-me 测试不是绝对禁用；但真实目标必须有目标依据、低频边界、锁定/限速观察、停止条件和当前流程选择。
- Candidate 需要证明账号、session、token、MFA 或密码状态被错误绑定，或攻击者可进入目标账号。

## 能力定位

本卡给 `web2-vuln-classes` 补充认证恢复、凭证状态机和受控凭证测试思路。它提供技巧和补漏点，不替代 red-line、coverage gate，也不把认证测试自动扩大成无边界爆破。

## 触发信号

- `/forgot-password`、`/reset-password`、`/change-password`、邮箱验证、邀请、MFA、remember-me、账号锁定、登录错误差异。
- 表单里有 hidden `username`、`email`、`userId`、`token`、`redirect`、`next`、`challengeId`、`mfaId`。
- reset link、verification link、邀请链接或 magic link 由 Host/X-Forwarded-Host、tenant、callback 或 email 参数影响。
- 登录、注册、找回、MFA、锁定或 remember-me 响应在用户名存在性、密码正确性、限速、锁定状态上有稳定差异。

## 思路分支

- Reset binding：token 是否和账号强绑定；提交阶段是否信任 hidden username/email；token 是否一次性、过期、跨账号、跨 session 可用。
- Change password：是否需要旧密码；是否能用普通 session 改他人账号；是否存在 CSRF、IDOR 或 role/tenant 混淆。
- Username enumeration：错误文案、状态码、长度、响应时间、锁定提示、邮件发送差异、MFA 分支差异。
- Credential testing：默认凭据、已知弱口令、少量高依据用户名、remember-me cookie、离线 token cracking；按受控边界执行。
- MFA/OTP：预认证 session、challengeId、用户绑定、重放、跳步、备用码、限速、账号锁定和渠道切换。
- Host/proxy connector：reset link、email verification、OAuth callback 或 absolute URL 生成受 Host/XFH 影响时，转 `proxy-cache-boundaries`。

## 技巧家族 / Payload 家族

- Hidden identity swap：把 reset 表单里的 `username=wiener` 改成 `username=carlos`，验证服务端是否只校验 token 存在而不校验账号绑定。
- Token reuse：同一 reset/verify/invite token 是否可重复提交、跨 session、跨账号、过期后使用或被 URL 编码/大小写影响。
- Error diff：存在/不存在用户、正确/错误密码、锁定/未锁定账号之间的 status、length、文案、时间和下一步页面差异。
- Remember-me：cookie 是否为 `username:hash`、弱签名、可离线验证或只绑定用户名而不绑定设备/session。
- Rate/lockout：观察阈值、冷却、IP/账号/用户名粒度；只做低频受控验证，不把锁定规避当默认动作。
- MFA state：直接访问 post-MFA 页面、替换 challengeId/userId、重放已验证 challenge、切换 channel/provider。

## 补充 Checklist

- 是否记录了完整合法 baseline：请求重置、收邮件、打开链接、提交新密码、登录？
- token 是否绑定账号、session、email、tenant、设备、时间和一次性使用状态？
- 提交阶段是否有可改 hidden identity 字段？
- 是否比较了存在/不存在用户的响应差异和邮件发送差异？
- 是否观察了限速、锁定、验证码、MFA challenge 和异常提示？
- 如果进入口令测试，是否有明确用户名来源、候选口令依据、低频边界、停止条件和日志记录？

## 最小验证

- Password reset：用自有/训练账号请求 token，单变量修改 hidden username/email 或 token，验证目标账号是否被重置。
- Username enum：对少量存在/不存在候选做稳定对照，只记录差异，不批量枚举真实用户。
- Credential test：仅在受控条件下用少量高依据候选；记录请求数、阈值、锁定迹象和停止条件。
- MFA：优先验证状态跳步、challenge 绑定和重放，不默认高频 OTP 枚举。

## 常见误判 / 死路

- 发送了 reset email 不等于漏洞；要证明 token/账号/session 绑定错误。
- 用户名枚举本身通常低价值，除非能链到凭证攻击、MFA 绕过、账号锁定滥用或隐私影响。
- 口令测试无结果不代表认证安全；回到恢复流程、remember-me、MFA 状态机和错误差异。
- Host header 反射在 reset link 中只是 Lead，必须证明可投递、可点击并导致 token 泄露或账号接管路径。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 发现 reset/change-password/MFA/remember-me 的具体绑定差异时，写入 action queue，类型 `auth-credential-recovery-flows`。
- 发现 Host/XFH 影响 reset link 或 absolute URL 时，加载 `proxy-cache-boundaries`。
- 需要扩大到口令喷洒或 brute force 时，必须由当前 Skill / `/autopilot` 切到受控 credential lane，并记录边界。

## 可晋升经验

- 某类框架或产品的 reset token 只绑定 token 不绑定账号。
- 某类登录/找回/MFA 错误差异可稳定枚举用户或 challenge 状态。
- 某类 remember-me、magic link 或邀请 token 可离线验证或跨账号复用。
