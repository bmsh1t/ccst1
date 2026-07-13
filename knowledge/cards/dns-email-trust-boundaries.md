---
id: dns-email-trust-boundaries
type: technique-card
related_skills:
  - web2-recon
  - bug-bounty
  - triage-validation
trigger_tags:
  - dns
  - subdomain-takeover
  - dangling-cname
  - mx
  - spf
  - dkim
  - dmarc
  - email-trust
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# DNS、邮件认证与应用信任边界

## Quick Recall

- 触发：dangling CNAME/NS/MX、第三方托管残留、SPF/DKIM/DMARC、邮件发送/验证/邀请/重置流程。
- DNS 记录缺失、`p=none` 或供应商 404 只是配置信号；必须证明接管、投递、账号绑定或浏览器信任影响。
- 最小验证是被动 DNS/HTTP/邮件认证观察和自有收件箱/测试域对照，不注册第三方资源、不向真实用户投递。
- 子域接管、邮件伪造、email normalization 和 SSO account-linking 要分开建模，再沿已证实连接器推进。

## 能力定位

本卡补充 `auth-sso-token-edge-cases` 的 email identity 边界和既有 takeover 流程的证据要求，覆盖 DNS 记录与应用信任的连接器；不把 DNS posture 直接变成漏洞结论。

## 触发信号

- CNAME/NS/MX 指向已删除、未认领或第三方控制面；解析状态与 HTTP provider 错误页不一致。
- SPF include/redirect 过宽或不可解析，DKIM selector/密钥与发送服务不一致，DMARC policy/alignment 弱。
- 应用用 `From`/`Reply-To`/域名、MX、邮箱后缀或未验证 email 作为邀请、恢复、SSO 绑定或通知信任依据。
- 邮件模板、SMTP header、bounce、calendar/invite 或 webhook 进入后续身份/业务流程。

## 思路分支

- DNS 归属：记录类型、TTL、解析器结果、第三方服务 claim 条件和组织所有权是否一致。
- 邮件认证：SPF path、DKIM selector/key、DMARC alignment/policy 与实际发送域是否一致；缺记录不等于可投递。
- 应用绑定：verified email、external_id、tenant、From/Reply-To 和 callback 是否绑定当前账号/组织/流程。
- 投递/接收：只用自有地址和测试域确认认证结果、显示名/Reply-To 解析和应用状态，不向真实用户或第三方投递。
- 连接器：只有证明邮件能影响重置、邀请、SSO 或通知状态后，才进入对应业务卡和验证门。

## 技巧家族 / Payload 家族

- DNS 对照：权威解析、多个公共解析器、CNAME/NS/MX 链和 HTTP Host/证书指纹的只读差异。
- 邮件对照：自有发件域/收件箱的 SPF、DKIM、DMARC pass/fail/alignment 和 bounce 结果。
- 应用对照：自有账号的 email normalization、verified flag、tenant/external_id、From/Reply-To 和 callback 单变量差异。
- 解析差异只作为候选形态；不保存第三方注册命令、固定 provider 字典或真实邮件内容。

## 补充 Checklist

- 是否确认 DNS/域名/邮箱服务归属和授权范围，而非把第三方资源当作目标？
- 是否同时记录 DNS、HTTP/TLS、认证结果和应用状态，避免只凭一条记录定性？
- SPF/DKIM/DMARC 是否检查 alignment、selector、include 链和实际发送域？
- 邮件是否只使用自有/训练收件箱，保留清理、撤回和停止条件？
- 是否区分配置弱点、可投递伪造、账号绑定错误和实际业务影响？

## 最小验证

- 被动解析并保存记录类型、TTL、权威结果和 provider 错误指纹；不主动 claim 资源。
- 用自有测试域/账号发一封无害测试邮件，记录认证结果和应用是否改变状态。
- 对 email/link/callback 只改一个 normalization 或绑定变量，比较 session、tenant、账号和流程状态。
- 只有接管/投递/绑定和影响证据同时存在时，才升级为 Candidate；否则保留 Lead/配置建议。

## 常见误判 / 死路

- `NXDOMAIN`、SPF 缺失、DMARC `p=none` 或第三方 404 本身不是可报告影响。
- 显示名、Reply-To 或邮件到达不等于账号接管；必须证明应用信任了错误身份或流程状态。
- 证书/缓存/解析器短暂差异可能是运营问题，需重复只读确认并保留时间点。
- 未经授权注册第三方服务、发送真实钓鱼邮件或读取他人邮箱不属于最小验证。

## 关联 Skills

- `web2-recon`
- `bug-bounty`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- DNS/HTTP 证据指向托管残留时，转既有 takeover 流程；不在本卡执行资源注册。
- email identity/callback 绑定异常时，转 `auth-sso-token-edge-cases` 或 `business-logic-state-machines`。
- 认证配置与实际投递结果齐全时，交给 `triage-validation`。

## 可晋升经验

- 某种 DNS/邮件记录与应用身份绑定组合在多个目标重复形成可验证影响。
- 某类认证配置误差反复造成误判，能明确写出停止条件和替代检查。
