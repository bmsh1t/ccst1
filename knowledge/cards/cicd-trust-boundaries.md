---
id: cicd-trust-boundaries
type: workflow-card
related_skills:
  - cicd-security
  - bug-bounty
trigger_tags:
  - ci-cd
  - github-actions
  - gitlab-ci
  - jenkins
  - runner
  - oidc
  - workflow-trigger
  - dependency-confusion
  - public-registry
  - sbom
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# CI/CD 触发器到部署链的信任边界

## Quick Recall

- 触发：公开仓库 workflow、PR/comment 触发器、self-hosted runner、artifact/cache、部署 job 或 OIDC 云角色。
- 把链路拆成 `untrusted input -> workflow context -> runner -> secret/OIDC -> artifact/deploy`，每一跳都要有证据。
- 只做配置和数据流审查、测试分支或 dry-run；不执行未知 workflow，不读取真实 secrets，不修改生产部署。
- `pull_request_target`、宽权限 token、未固定 action、可控 artifact/cache 只是 Lead，必须证明下游信任边界被跨越。
- dependency confusion 使用三段式证据门：public registry miss + 构建实际依赖 + public fallback；404 单独只算 Lead。

## 能力定位

本卡补充 `skills/cicd-security` 的跨层连接器，帮助 AI 选择审查顺序和证据门；执行动作、脚本分析和红线仍由 Skill 与 `rules/red-lines.md` 管理。

## 触发信号

- workflow 使用 `pull_request_target`、issue/comment 输入、可控 branch/title/body、`self-hosted` runner 或宽 `permissions`。
- workflow checkout 未信任的 PR 内容，或 shell/script/template 读取了 `${{ }}`、artifact 名称、缓存键和环境变量。
- 出现 `id-token: write`、云 role trust、发布包/镜像、release/deploy job、共享 artifact/cache。
- Jenkins/GitLab/其他 CI 的 job 参数、变量、runner 标签和下游部署上下文相互传递。
- JS/source、manifest/lockfile、构建日志、SPDX/CycloneDX SBOM 或 Docker/GHCR image layer 暴露内部包名和精确版本。

## 思路分支

- 触发上下文：谁能触发、谁能修改输入、workflow 使用 base 还是 fork 权限，审批条件是否实际生效。
- 执行上下文：runner 是否共享工作区/缓存，checkout 的 ref、脚本解释器和 action 版本是否固定。
- 凭证上下文：secrets、短期 OIDC token、环境保护和云 trust policy 是否绑定 repo/branch/environment。
- 产物上下文：artifact、cache、镜像、包和 release 是否被更高权限 job 或部署链消费。
- 连接器：只沿已证实的数据流检查 secret 暴露、云身份越权、包发布或部署影响，不泛化为“能执行命令”。
- dependency confusion：分别证明目标构建消费该包、resolver 会回落 public registry、public namespace 状态；三者不得互相代替。

## 技巧家族 / Payload 家族

- 配置差异：比较 trusted PR、fork PR、comment、手工 dispatch 和定时触发的权限/环境差异。
- 数据流形态：标记 PR title/body、branch、label、artifact/cache key、环境变量到 shell/模板/部署参数的单向流。
- 版本/权限形态：检查 action/镜像是否固定、token permissions 是否最小、OIDC subject/audience 是否绑定具体环境。
- 证据形态：优先使用静态配置、测试分支日志和无敏感 dummy secret，避免直接触发高权限 job。
- 依赖形态：从 JS/source、lockfile、build log、SBOM、公共镜像层交叉确认 package/version；再检查 scope、source priority、lock 和 fallback。

## 补充 Checklist

- 触发者、输入来源、权限上下文、runner 类型、checkout ref 是否逐项记录？
- secrets/OIDC 是否在不可信输入之后才可达，或通过 artifact/cache 间接到达？
- action、镜像、依赖和 runner 是否固定到可信版本和边界？
- artifact/cache/package 是否被 release/deploy/job 以更高权限消费？
- registry 404 之外，是否有“实际依赖”和“public fallback”两份独立证据？
- Docker/GHCR layer、SPDX/CycloneDX 和 OSV/CVE 映射是否绑定同一精确 package/version，而不是名字相似？
- 是否有测试环境、审阅批准、清理和停止条件？

## 最小验证

- 只读解析 workflow 图，输出 `source -> sink`、权限和环境边界。
- 在训练仓库使用无害 marker 或 dummy secret，验证输入是否进入日志/构建产物，而非读取真实 secret。
- 对 OIDC 只检查 trust policy 与 subject/audience 绑定；不换取或使用真实云权限。
- dependency confusion 先输出三列表：`dependency evidence`、`resolver fallback evidence`、`public namespace state`；
  只有三列都成立时才创建 Candidate，隔离 fixture 可用于验证 re-resolution 和版本选择。
- 任何需要执行未知 workflow、改生产配置或发布包的路径都降级为 blocked，并记录证据缺口。

## 常见误判 / 死路

- 存在 CI 文件或 `id-token: write` 不等于可利用；需要证明不可信输入能到达高权限上下文。
- action 未 pin 是供应链风险信号，但没有受控影响证据时不要包装成直接 finding。
- 普通 runner 命令执行不等于云越权；必须分别证明 token、trust policy 和控制面动作。
- 日志中出现 masked secret 不代表泄露；不要为脱敏字段继续猜测真实值。
- public registry 404、内部风格包名或 SBOM 单独出现都不等于 dependency confusion；缺构建消费或 public fallback 时保持 Lead/Informational。

## 关联 Skills

- `cicd-security`
- `bug-bounty`

## 晋升到 Skill / Queue 的条件

- 配置图和一条最小可复现数据流明确后，交给 `cicd-security` 的专项审查队列。
- 若 OIDC/runner 已产生云身份线索，转 `cloud-control-plane-pivots`；若 artifact/cache 影响包发布，转供应链相关流程。
- dependency confusion 只有在实际依赖、public fallback 和 public namespace 三项证据齐全后进入验证队列。

## 可晋升经验

- 某类触发器、runner、OIDC 或 artifact 组合在多个目标重复形成跨层信任错误，并有配置/日志证据。
