# 待确认的一次性分批提交计划

状态：用户已回复“确认”。前两批按精确白名单提交，原任务已归档；日志按第四批单独提交。
用户已批准功能范围。本清单是 workflow 3.4 要求的唯一具体分批确认；确认后按顺序执行，不 push。

## 1. `fix: bind cleanup verification to report publication`

必要既有 cleanup WIP 独立成批（6 文件，222 additions / 10 deletions），不是本轮新写的 Store 功能：

- `.trellis/spec/backend/contracts/validation-evidence.md`
- `docs/tool-index.md`
- `tools/report_generator.py`
- `tools/target_store.py`
- `tools/validate.py`
- `tools/validation_runner.py`

`validation_runner.py` 用 B1 前置 blob，tool-index 仅新增 cleanup record-evidence 一行；
validation-evidence 仅其既有 34 行 cleanup 合同。其余前置代码也都逐字匹配 B1 before。

## 2. `feat: integrate versioned 6k methods and native observations`

178 个精确路径（23 个代码/入口/规范路径，加 155 个方法/历史文件）：

- `.trellis/spec/backend/contracts/hot-method-native-observation.md`
- `.trellis/spec/backend/contracts/recon-surface.md`
- `.trellis/spec/backend/index.md`
- `CLAUDE.md`
- `commands/autopilot.md`
- `commands/context-pack.md`
- `commands/hunt.md`
- `docs/evidence-runners.md`
- `docs/tool-index.md`
- `knowledge/clown-hot-method-manifest.json`
- `rules/campaign.md`
- `rules/retrospective.md`
- `skills/mobile-pentest/SKILL.md`
- `skills/runtime-protocol.md`
- `skills/src-hunting/SKILL.md`
- `tools/artifact_io.py`
- `tools/browser_evidence.py`
- `tools/browser_mcp_import.py`
- `tools/context_pack.py`
- `tools/contracts.py`
- `tools/hot_method.py`
- `tools/structured_findings.py`
- `tools/validation_runner.py`
- `knowledge/methods/clown/`：清单内 56 活动文件、99 blobs/transactions/decisions/receipts/witnesses；不含其他方法目录。

完整 178 路径、mode、blob、SHA256 见 [机器白名单](b7-commit-boundary.json)，不是对上述目录执行宽泛 git add。
包含原先 55 份未跟踪活动方法和旧内置/未排名基础；本次成为 56 份。campaign 的既有衔接及
runtime-protocol 的已验收 125 行整体重写一并纳入，含压缩重述，不把每行宣称为新增或代码依赖。

**只取部分改动**：CLAUDE 的四处必要接线、context_pack 的 B1→本任务增量、tool-index 的
observation/browser说明。精确暂存预览 blob，C 原完整工作树保持不变；不能 whole-file add，
也不能 `git commit -- <path>` 覆盖部分暂存。真实 C reader 已与预览 byte-for-byte 一致。

## 3. `chore(task): archive 6k full integration`

- 原任务归档到 `.trellis/tasks/archive/2026-10/10-14-6k-full-integration/`。
- 只纳入机器白名单内 PRD/design/implement、两份 JSONL、task.json 与 research 工件/回执。
- 本地 `b6-inputs/**` 随目录移动保留，但不加入 Git（原件/日志已有自己的保管位置）。
- 修正 hot-method spec 的三条研究链接、任务内越级 spec 链接及 JSONL 当前任务路径。
- archive 使用 `--no-commit --skip-branch-validation`，不伪造 PR/分支，不暂存整个 archive 根。

## 4. `chore: record 6k integration journal`

- `.trellis/workspace/Codex/journal-1.md`：仅本次新增记录。
- `.trellis/workspace/Codex/index.md`：仅对应 journal 索引增量。
- `add_session.py --no-commit` 后精确暂存；不包含其他开发者或旧日志改动。

## 明确不提交

- `.trellis/spec/backend/contracts/runtime-autopilot.md`
- `knowledge/capabilities.yaml`
- `knowledge/index.md`
- `rules/context-loading.md`
- `rules/hunting.md`
- `tools/autopilot_bootstrap.py`
- `tools/capability_profile.py`
- `guihua.md`
- `knowledge/cards/hypothesis-reframe.md`
- `knowledge/cards/surface-unknown-probes.md`
- `tools/operational_metrics.py`
- `tools/surface_advisory.py`
- CLAUDE 的其余旧重写、context_pack/tool-index 的 advisory/metrics/degraded 剩余 hunk。
- 其他 task/journal、目标状态、个人 runtime、模型、临时验收 fixture 和恢复包。

以上路径及剩余 hunk 保留在工作树，不回滚或删除。每批先核对 HEAD/index 和精确 blob；
出现新用户改动则停止重审。完成后核对提交树、归档链接和未提交 WIP；不做个人 runtime 同步。

本清单已获确认，无需再次确认；下节记录已完成步骤。

## 已确认提交与归档

用户回复“确认”，随后“继续”；按原四批清单执行，不 push、不 amend。
- `a4a22e2d0b81d2c232be3518bdba89e652b19635`：cleanup前置，6路径；树与验收候选一致。
- `ba183ca88e1bf311e59f3b41348c318f96047e3f`：6k集成，178路径；树与验收候选一致。
- 原任务以 `--no-commit --skip-branch-validation` 归档；只暂存29项任务工件与spec链接修正。
- b6-inputs全部74文件仅在本地随目录移动保留，内容/身份不变，不纳入Git；其他WIP保持原样。
- 日志仅追加本次记录及对应索引，使用 `add_session.py --no-commit`；四批最终hash另保存在D7收尾回执。
