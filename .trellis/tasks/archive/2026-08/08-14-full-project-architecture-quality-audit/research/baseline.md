# 审核基线

日期：2026-08-14

## Git 身份

- 分支：`main`
- HEAD：`c2aca248d121fb63fceb94cac1e004877447145c`
- HEAD subject：`feat: explain knowledge card recall`
- 与 `ccst1/main`：ahead 1，behind 0
- index：无 staged changes
- 主审核对象：当前工作树
- 归因对照：以上 HEAD 提交态

## 工作树摘要

### Tracked dirty（20 项，74 insertions / 569 deletions）

Runtime/命令/文档：

- `commands/hunt.md`
- `docs/tool-index.md`
- `requirements.txt`
- `rules/red-lines.md`
- `shenhe.md`（删除，486 行）

Knowledge/vendor：

- `knowledge/cards/insecure-deserialization.md`
- `knowledge/cards/sqli-hidden-surfaces.md`
- `tools/vendor/badsecrets_telerik/SOURCE.md`

State/tooling：

- `tools/action_queue.py`
- `tools/checkpoint.py`
- `tools/context_pack.py`
- `tools/vuln_scanner.sh`

Tests：

- `tests/test_action_queue.py`
- `tests/test_checkpoint.py`
- `tests/test_context_pack.py`
- `tests/test_fresh_code.py`
- `tests/test_red_lines_docs.py`
- `tests/test_selective_knowledge_distillation.py`
- `tests/test_skill_boundaries.py`
- `tests/test_vuln_scanner_script.py`

### Untracked（7 项）

- `DEEP_MODE_AUTOPILOT_SUMMARY.md`
- `guihua.md`
- `jyou.md`
- `zyou.md`
- `tests/test_aspnet_viewstate_knownkey.py`
- `tools/aspnet_viewstate_knownkey.py`
- `wordlists/onelistforallmicro.txt`

这些改动属于用户现有工作树，审核不暂存、不回滚、不把其存在本身判为 finding。报告中的问题
逐项标注 `HEAD`、`WORKTREE` 或 `BOTH`。

## 审核期间漂移规则

审核结束前重新运行同组 status/name/stat 命令。若路径、行号或内容发生变化：

1. 保留本文件作为起始快照；
2. 追加结束快照和漂移路径；
3. 重新读取受影响证据；
4. 不把并发修改归因于起始基线。

## 安全边界

本次基线只记录路径、计数和 commit 元数据，不读取 `.env`、`.private/`、真实目标 artifact 或
凭据内容。后续测试仅使用 synthetic fixture、`tmp_path`、localhost 或 `/tmp` 导出副本。

## 结束快照

审核报告完成后重新取样：

- HEAD 仍为 `c2aca248d121fb63fceb94cac1e004877447145c`；
- index 仍为空；
- tracked dirty 仍为相同 20 项，diff stat 仍为 74 insertions / 569 deletions；
- untracked 仍为相同 7 项；
- 未发现审核期间工作树漂移，所有 `HEAD` / `WORKTREE` 归因和行号继续有效；
- 审核只新增/更新当前 Trellis 任务下的规划、研究和验收产物，未改动生产代码。
