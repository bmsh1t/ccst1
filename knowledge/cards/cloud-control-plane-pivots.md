---
id: cloud-control-plane-pivots
type: workflow-card
related_skills:
  - bug-bounty
  - triage-validation
trigger_tags:
  - cloud-control-plane
  - cloud-metadata
  - iam
  - rbac
  - service-account
  - artifact-deploy
risk: high
maturity: draft
load_priority: low
deep_refs: []
---

# 云控制面身份与部署连接器

## Quick Recall

- 触发：已证明的服务端 URL fetch、metadata/临时身份、CI/CD OIDC、Kubernetes service account、IAM/RBAC 或部署 artifact。
- 用 `入口 -> 身份 -> 权限 -> 控制面动作 -> 影响` 建模；每一跳都需要独立证据，不能把凭证出现当成越权。
- 默认只读检查身份、策略和单个测试资源；不枚举内网、不读取真实 secrets、不创建/修改/删除云资源。
- SSRF/DNS callback、环境变量、日志或配置泄露只算入口信号，必须证明身份归属和最小控制面影响。

## 能力定位

本卡连接 `ssrf-internal-impact`、`information-disclosure-source-config`、`cicd-trust-boundaries` 的后续判断，帮助 AI 区分“拿到身份”和“控制面影响”。它不是云提权清单，也不替代红线和授权门。

## 触发信号

- 响应/日志/配置出现临时云身份、service account、role ARN、OIDC subject、metadata endpoint 或控制面 API 名称。
- CI/CD runner、容器、函数或 web service 可见云环境变量、workload identity 或部署凭证。
- IAM/RBAC policy、trust relationship、artifact/deploy manifest 出现宽主体、通配资源或跨环境绑定。
- SSRF/内部读取已证明服务端身份，但尚未确认该身份的权限和资源边界。

## 思路分支

- 身份归属：凭证来自哪个 workload/tenant/environment，生命周期、audience 和 owner 是否可验证。
- 权限边界：只读/写入/委派/模拟权限分别对应什么资源，策略条件是否绑定资源、分支、namespace 或环境。
- 控制面动作：优先找低风险 `get/describe/list` 或测试资源的 dry-run；不要从权限名称直接推导可执行影响。
- 部署连接器：artifact、镜像、函数、role、namespace 和环境变量是否把一个低信任输入带入高信任部署链。
- 影响链：仅在同一身份、同一资源和同一操作都有证据时，才进入 Candidate/报告门。

## 技巧家族 / Payload 家族

- 身份对照：记录匿名、服务身份、普通 workload 和目标环境的 caller identity/租户差异。
- 策略对照：使用策略文档、模拟结果或测试资源状态差异，区分 allow/deny、条件和资源范围。
- 连接器对照：把 metadata/CI/artifact 作为 source，把 IAM/RBAC/control-plane 操作作为 sink，逐跳保留引用。
- 云服务差异只作为路线提示；不要把 provider 名称或权限名变成固定攻击字典。

## 补充 Checklist

- 是否确认凭证/身份属于授权测试环境，而不是第三方或生产租户？
- 是否保存 caller identity、租户/账号、资源 ARN/namespace 和策略版本？
- 是否把“可读取身份”“可读取配置”“可执行控制面动作”分开验证？
- 是否有 dry-run、测试资源、最小权限和回滚路径？
- 是否记录 SSRF/CI/source 到云身份的每一跳证据？

## 最小验证

- 先用现有入口证明服务端或 runner 身份，再做一个无副作用的 caller identity/describe 检查。
- 对单个自有测试资源做最小权限对照；记录 allow/deny、资源边界和实际状态。
- 如果只能证明 metadata/DNS/环境变量存在，保持 Signal，继续找归属和权限证据，不扩大访问范围。
- 任何 create/update/delete、secret read、跨租户访问和持久化动作默认 blocked，除非明确授权并有回滚。

## 常见误判 / 死路

- metadata 可达、IAM policy 宽或 OIDC 开启不等于已经越权；缺 caller/资源/动作证据时不能报告。
- 云错误页、凭证格式和 provider 指纹只能帮助路由，不能证明权限。
- 只读 `describe` 结果不等于能修改资源；不要把潜在路径写成已验证影响。
- 第三方 webhook/CDN/registry 只属于链上下文，除非所有权和授权边界已确认。

## 关联 Skills

- `bug-bounty`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 身份、权限和单个资源动作齐全时，交给 `triage-validation`。
- 入口是 URL fetch/SSRF 时回到 `ssrf-internal-impact`；入口是 workflow/OIDC 时回到 `cicd-trust-boundaries`。

## 可晋升经验

- 某种 workload/CI/SSRF 到控制面身份的连接器在多个目标重复出现，并有逐跳证据。
