# 安装器与 Runtime Doctor 文件筛选一致性

## Goal

本地开发补丁不能被安装为运行命令/Agent；安装结果与只读 Doctor 的文件归属规则一致。

## Confirmed Facts

- `runtime_doctor._is_runtime_markdown_source()`（`tools/runtime_doctor.py:95-98`）对名称
  lowercase 后排除 `.patch.md`；compare 与 sync 都通过 `_repo_files()` 使用同一规则。
- `install.sh:74-85` 的 commands 复制不排除补丁；`:91-98` 的 agents 仅排除小写后缀。
- 父任务临时复现中，复制循环生成 commands 的 local.patch.md/local.PATCH.md 和 agents
  的 local.PATCH.md，随后 compare_kind 都报告 EXTRA；未运行完整安装器或个人 runtime。

## Requirements

- R1：两个现有 Markdown 复制循环按 Doctor 的既有语义排除开发补丁，包括大小写后缀。
- R2：保留 disabled command 不重新启用、完整 Skill 资源、外部 Skill 和用户文件的归属；
  不因修复运行 sync/prune 或更改现有 cp fallback 的 additive 行为。
- R3：只做本地 shell 筛选和临时 parity 回归，不增加库存服务、过滤配置或依赖。

## Acceptance Criteria

- [x] AC1（R1）：临时 checkout 同时含两个 kind 的小写/大小写补丁与普通 md，复制后普通文件
  字节相同、补丁不复制，Doctor 无此类 EXTRA；repo 中补丁原文仍在。
- [x] AC2（R2）：既有 disabled/嵌套资源/外部 Skill/升级重放测试仍有效；无用户状态修改。
- [x] AC3（R3）：对应 focused 测试通过，记录 rsync 分支是否可用；没有个人 runtime 安装或部署。

## Technical Notes and Execution

这是独立轻量修复，PRD-only 即可。获批且 Scanner 子任务完成后，从实际当前已提交 HEAD
创建 `fix/installer-runtime-file-selection`，更新 base_branch 并 start 本子任务。
用户本次 `go` 已确认推进；Scanner 已提交 `e755065` 并归档于 `45fdf1e`，本子任务从 `45fdf1e`
启动，base_branch 为 `fix/scanner-summary-input-contract`。
仅改 `install.sh` 两个现有循环；沿既有 shell case 写法逐字母匹配 patch 的大小写，
不增加外部命令依赖或提高 Bash 版本要求，不创建通用同步器。
`tools/runtime_doctor.py` 的语义不变，它是比较基准。

在 `tests/test_install_script.py` 的临时 checkout 验证和 Doctor 的 parity；按需要把
`tests/test_runtime_doctor.py` 现有 patch 测试参数化为 commands/agents 和三种后缀大小写形式。
复用既有升级/重放测试：加入小写、全大写、混合大小写 patch 与普通/近似名称 Markdown，
每轮安装检查源字节不变和补丁未安装；Doctor 测试覆盖两个 kind 的旧 runtime 补丁仅在显式 prune 时删除。
更新 runtime-autopilot 现有契约后审查 diff，并提出独立提交计划。

```bash
python3 -m pytest -q tests/test_install_script.py tests/test_runtime_doctor.py
```

测试仅运行临时 HOME/PATH 的隔离 fixture；缺少 rsync 时如实报告 skip，不安装依赖。
无数据迁移，可独立回滚产品提交。父任务统一汇总，不再叠加全仓测试。

## Verification

上述命令已实际执行：**31 passed in 7.25s**，无 skip；rsync 与 cp 两条升级/重放路径均通过。
实现、规范更新和定向验收已完成，已提交 `8227cd2`，进入收尾归档；完整结果及审查见 verification.md。

## Out of Scope

个人 runtime、实际部署、自动 sync/prune、外部 Skill 删除、Scanner 代码、旧暂存日志。
不新增 owner/依赖，不改 bash 工具链要求，不自动提交或 push。
