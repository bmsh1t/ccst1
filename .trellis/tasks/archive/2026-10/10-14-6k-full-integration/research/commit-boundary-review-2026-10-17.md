# Git 交付边界复核（2026-10-17）

> 历史检查点：下文为提交边界初审；批准后的最终交付见 [B7](b7-git-acceptance-2026-10-17.md)。

## 状态

用户选择下一步 1：仅提交本任务变更，再归档；不部署个人 runtime。
C 本地 B6/A1–A9 的既有验收仍成立，但不能将它等同于一个自包含、可从 Git 新建 checkout
直接运行的交付版本。提交前静态复核发现以下边界，尚未执行 git add/commit/archive。
HEAD 仍为 `99a653b14ece0f925a625c8645a690aaa8a7a218`，index 与 B1 基线相同、无暂存差异。

## 1. 混合改动与未提交前置依赖

以下本任务修改的 tracked 文件在 B1 前已经有 WIP：
`docs/tool-index.md`、`rules/campaign.md`、`skills/runtime-protocol.md`、
`tools/context_pack.py`、`tools/hot_method.py`、`tools/validation_runner.py`、
`knowledge/clown-hot-method-manifest.json`。整文件暂存会纳入旧改动，路径白名单不足以隔离。
其中 context_pack 的 B1→当前增量可直接应用到 index；其他多个文件的增量与旧改动交织，
不能用标准 patch 强行套到 HEAD 或未验证地合成另一份实现。

确切跨文件依赖：当前 `tools/validation_runner.py:50,66` 导入
`validate_cleanup_confirmation`，`:490–492` 向 `record_execution` 传 `finding_id`。
定义位于原 WIP 的 `tools/target_store.py:648,1953–1955`；HEAD 中缺该函数且
`record_execution` 不接受该参数。故整文件提交 runner、排除 Store WIP 会形成缺依赖版本。
Store 属原有改动，不因本次依赖就自动获得提交授权。

方法树目前155个文件全部未跟踪：56活动文件、74 blobs、6 transaction/decision/receipt、
19 witness。任务前已存在55个活动文件；只暂存 candidate-files 清单会漏掉49个未改动的
原方法文件和C生成的历史材料。完整接入必须明确纳入这些既有6k字节，不能称全为本轮新增。

明确不自动纳入的原 WIP：runtime-autopilot/validation-evidence 两份spec、CLAUDE.md、
capabilities.yaml、knowledge/index.md、rules/context-loading.md、rules/hunting.md、
autopilot_bootstrap/capability_profile/report_generator/target_store/validate、guihua.md、
两张 hypothesis-reframe/surface-unknown-probes 卡及 operational_metrics/surface_advisory。
这些当前字节均仍等于 B1；其中必要依赖也必须先划定和审核，不能直接全收。

## 2. 本地恢复身份不等于可移植版本读取

`tools/hot_method.py:733–739` 的 `_validate_revision` 调用 `_load_transaction`；后者在
`:675–676` 绑定已存目录身份，在 `:829–838` 的 `_verify_witness` 核对 dev/ino 及blob分离。
Git 不保留 inode/dev 或硬链接身份。因此把全部history字节提交也不证明新checkout可读。
原设计明确禁止移植F见证到C，此限制没有被B6消除。本次只做静态核对，没有伪报fresh
checkout行为已验证；若要交付可移植版本，须明确区分终态版本读取与checkout本地恢复身份，
经设计审阅及针对性验证，不可直接删掉身份守卫、伪造见证或降级hash检查。

## 3. 归档和日志提交范围

默认archive辅助函数会暂存整个 `.trellis/tasks/archive/`，日志自动提交会包含当前开发者
全部journal文件；不能保证仅收本次增量。应使用现有 `--no-commit`，然后对白名单内容手动
暂存并检查index。新spec与task目录被 `.gitignore` 忽略，确需入Git时仅对已审具体文件 `-f`。
部分暂存不能用 `git commit -- <path>`，因为那会取该路径完整工作树内容。

本任务一直在共享分支直接完成，branch/base_branch相同；归档须显式
`--skip-branch-validation`，不伪造PR/分支元数据。归档还会清除指向本任务的session指针。
新spec到本任务research的三条链接不会自动重写，应与归档一并改为archive路径。

## 决策门

先确认必要旧改动的提交授权和可移植Git交付范围，再给出一次性的具体分批/文件计划。
范围未确认前不暂存混合文件、不提交缺依赖版本、不提前归档，也不修改本地恢复协议。
本记录晚于B6补充包；原包仍是已验证的B6时点材料，不声称包含本次Git交付复核。

## 后续批准与完成

用户已回复“同意”；必要前置闭包和终态读取分层按 [B7计划](git-delivery-plan-2026-10-17.md)
实施并验证，见 [真实验收](b7-git-acceptance-2026-10-17.md)。当前仍未实际提交/归档；
下一门是一次性确认具体分批清单，不再重复询问已批准的功能范围。
