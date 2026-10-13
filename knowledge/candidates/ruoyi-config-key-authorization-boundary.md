---
id: ruoyi-config-key-authorization-boundary
type: technique-card
related_skills:
  - src-hunting
  - triage-validation
trigger_tags:
  - ruoyi
  - config-key
  - secret-disclosure
  - anonymous-config
risk: high
maturity: draft
load_priority: low
deep_refs:
  - knowledge/cards/information-disclosure-source-config.md
  - knowledge/cards/auth-access.md
  - knowledge/cards/auth-sso-token-edge-cases.md
source_refs: []
---

# RuoYi 系配置键读取与未授权边界

候选状态：独立方法草稿，尚未完成目标复现、整链盲答或晋升审核。重点是配置键的
授权与敏感值分类，不把一个公开 RSA 公钥接口自动外推成密钥泄露。

## Quick Recall

- 登录页脚本调用 `rsa.publicKey` 和存在按 `configKey` 取值的接口，是辨型信号。
- `rsa.publicKey` 适合作为公开基线；`rsa.privateKey`、初始密码、微信凭证和其他
  `*.secret` 必须逐键、逐部署验证，不能以键名存在替代值存在。
- 未登录请求返回结构或“配置不存在”只说明路由行为。Candidate 需要证明无会话也
  能得到非公开、可用的敏感配置，或有明确的权限绕过差异。
- 供应商多部署可用于验证修复范围，但每个部署的来源、配置和授权结果独立记录。

## 触发信号与适用条件

前端 `login.js`/`ry-ui.js` 读取公钥，Network 中出现
`/system/config/getConfig` 或语义相同的 `configKey` 查询口，且当前范围允许匿名
读取检查。先固定一个公开键和一个不存在键作为控制；不猜测未观察到的密钥命名空间，
不把真实凭据写入工作材料。

## 最小验证

1. 在无痕/无会话上下文保存公开键、未知键和一个明确受保护键的 baseline；同时记录
   `Scope/Auth`、响应类型、是否由网关或应用返回。若只有登录态可读，匿名假设不成立。
2. 只对已观察的键做单变量请求：`rsa.publicKey` 作公开对照，随后核对
   `rsa.privateKey`、`sys.user.initPassword`、`wx.appid`/`wx.appsecret` 或产品代码中
   明确出现的 `*.secret`。返回空值、掩码、示例占位符和真实值必须分开记录。
3. 对敏感配置只保留键名、长度/类型、不可逆指纹和脱敏片段。私钥、初始密码和应用
   凭证不写入候选、日志或报告原文；需要证明可用性时使用项目提供的测试凭据或受控
   验证回执，不把值交给外部服务。
4. 区分“配置泄露”和“可利用影响”：密钥值非空并不自动证明登录、解密或 API
   接管。若范围包含本地测试验证，使用自有账号/测试公众号和最小只读 endpoint；
   失败、白名单拒绝、占位值和需登录分别保留原因。
5. 若产品存在多部署，复现同一键和同一鉴权条件，绑定部署版本/配置差异；一处成功
   不代表所有厂商部署都暴露。

## 证据要求

保存匿名请求、公开/未知/敏感键的原始响应引用、目标部署、会话状态、敏感值的
脱敏指纹和可用性验证回执。`40164` 等上游服务错误只有在测试凭据由本地受控验证
得到时才说明凭证格式被接受；不能仅凭一个错误码宣称接管。

## 常见误判与停止条件

- 非空 `rsa.privateKey` 不等于每个部署都有私钥；示例 `appsecret`、默认初始密码或
  掩码值不等于可用凭据。
- 需要登录、只返回公钥、接口返回统一空对象或网关错误时，关闭相应匿名分支，保留
  配置键线索，不继续枚举真实账号或密钥。
- 无自有测试凭据、无法安全清理、或下一步会触发真实用户/公众号副作用时，停止在
  泄露证据层。

## 下一步与来源

准入后优先并入 `information-disclosure-source-config`，影响验证再引用
`auth-sso-token-edge-cases`；不创建 RuoYi 专属 registry。直接来源为 v2.3
`skills/specialized/src-hunt-lane/references/kill-chains/ruoyi-getconfig-unauth.md`，
SHA-256 `e7eb006e9c8f4185cc6e6727803cdc6c0098b38e8c03e65c3664db206c94eff3`，第 1–54 行；
对应新增 shortlist 行为同一源 `shortlist.md` 第 96 行（SHA-256
`ac77785a8533d1153d66c83dd63cad8f690da5ed1c05169fd9e854d15a7c9ddd`）。

