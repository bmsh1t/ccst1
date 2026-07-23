---
id: public-package-artifact-intelligence
type: technique-card
related_skills:
  - web2-recon
  - cicd-security
trigger_tags:
  - package-registry
  - package-history
  - published-artifact
  - container-image
  - historical-release
risk: low
maturity: draft
load_priority: low
deep_refs: []
---

# 公开包与历史发布物情报

## Quick Recall

- 只在官方源码/文档、lockfile/SBOM、JS、镜像引用或已有 namespace 信号指向公开包时启用。
- 先证明 namespace、包或镜像与目标的归属；名字相似、组织名近似或第三方依赖都不够。
- 历史发布物只产生 Candidate 线索，不代表目标部署了对应版本，也不能直接触发 CVE 适用性或 Finding。
- 归档只解压并静态审查；不安装包、不执行 lifecycle script、不运行镜像、不发布或接管 namespace。

## 能力定位

本卡为 `web2-recon` 提供一个按信号加载、时间有界的公开生态情报分支。它复用现有 Source Hunt、Intel、Target Memory 和证据流程，不拥有新的资产图、置信度或 finding 生命周期。

## 触发信号

- 官方仓库、文档、前端资源、lockfile、SBOM 或构建记录给出明确 package/image namespace。
- npm、PyPI、RubyGems、NuGet、Maven、Packagist、crates.io、Docker Hub 或 GHCR 存在可归属的发布记录。
- 当前版本看似干净，但首版、上一个 major、迁移前后版本或旧镜像层可能保留配置、内部地址或误发布文件。

## 思路分支

- 归属确认：官方链接、同组织 publisher、仓库 metadata、签名或文档引用能否形成至少一条直接归属证据。
- 历史差异：有界选择首版、上一个 major、迁移前后版本和最新版，比较新增、删除及打包边界变化。
- 静态线索：检查配置模板、source map、内部 host、CI 文件、manifest、调试文件和 secret pattern；真实 secret 值只进入现有 triage。
- 容器线索：记录 registry、repository、tag、digest、发布时间和选取的 layer，不把 tag 当不可变标识。
- 后续路由：已解压目录交给 Source Hunt；只有真实目标直接观测到精确组件/版本后，才交给 `/intel` 判断适用性。

## 技巧家族

- Provenance：保存生态、包名/镜像名、版本或 tag、发布时间、来源 URL、digest/SHA-256 和扫描范围。
- Bounded history：按发布边界抽取少量代表版本，不默认枚举或下载全部历史版本。
- Archive diff：仅比较文件清单、路径、manifest、配置和静态文本，优先关注历史中被删除的敏感材料。
- Existing scanner reuse：对本地已解压目录运行 `python3 tools/source_hunt.py --target TARGET --repo-path PATH`，复用现有证据输出。

## 补充 Checklist

- 是否有直接目标归属证据，而不是名称相似或普通第三方依赖？
- 是否记录来源 URL、版本、发布时间、digest/hash 和实际扫描范围？
- 是否使用代表版本并说明选择理由，而不是无界下载全部历史？
- 是否保持纯静态审查，未安装、执行、运行或发布任何产物？
- 是否把包线索保持为 Candidate，并在 `/intel` 前确认目标真实部署版本？
- dependency confusion 是否仍具备实际依赖、public fallback 和 namespace 状态三项独立证据？

## 最小验证

- 用官方来源或目标直接引用确认 package/image namespace 归属。
- 对每个选中产物记录 immutable hash、版本、来源、扫描时间和扫描范围，再做解压后的只读静态检查。
- 将命中保存为证据路径、最小脱敏片段、为何值得补证据以及下一步；不要把真实凭据写入知识卡或普通日志。
- 公开历史版本只进入 Lead/Candidate。只有目标侧直接版本证据和稳定影响链齐全后，才进入现有验证流程。

## 常见误判 / 停止条件

- 同名包、相似组织名、第三方依赖或社区镜像不证明目标归属。
- registry 中存在旧版本不证明生产环境仍部署该版本，也不证明对应 CVE 可利用。
- secret pattern、内部域名或配置键名只是静态线索；缺少有效性、可达性或影响时保持 Lead。
- 达到预设代表版本范围、来源无法确认、只有重复低信号文件或需要执行未知代码时停止，并记录证据缺口。
- public namespace 空缺不单独构成 dependency confusion；继续使用现有三证据门。

## 关联 Skills

- `web2-recon`
- `cicd-security`
- `/source-hunt`
- `/intel`

## 晋升到 Skill / Queue 的条件

- 归属、产物 provenance、immutable hash 和静态命中都可复核后，将线索写入现有 Target Memory/证据路径并进入对应补证据队列。
- 只有真实目标直接观测到精确组件/版本时才转 `/intel`；只有真实 secret、公开敏感文件或供应链边界得到最小影响证明时才进入验证队列。

## 可晋升经验

- 某类发布边界、历史版本选择或 archive diff 在多个目标稳定发现可复核高价值线索，并保留来源与验证结果。
