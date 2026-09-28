# 第四批：Scanner 摘要与部署规则契约核查

## Goal

让摘要损坏和未完成工作保持可见，并让安装器与 Runtime Doctor 对运行文件有一致解释。
架构与能力优先，其次效率与维护成本；只修复本地已复现的契约缺口。

## Confirmed Facts

- 基线 `7c3556d` 包含第三批修复 `916524c`；仍在本地任务分支，未合并或 push。
- F1：Scanner reader 把错误的 lane 容器当 missing，把小数计数截成整数，非有限数与坏
  UTF-8 分别抛 OverflowError/UnicodeDecodeError。reader/gate 各有一份计数转换。
  出处：`tools/autopilot_state_read.py:204-265`、`tools/autopilot_gate.py:161-222`。
- F2：Doctor 排除大小写不敏感的 `.patch.md`，安装器 commands 不排除、agents 仅排除小写。
  临时复制循环产生 Doctor 所报 EXTRA。出处：`tools/runtime_doctor.py:95-122`、`install.sh:70-101`。
- 复现命令及完整结果见 `research/findings.md`；没有证明真实目标误闭合，也未运行真实扫描或完整安装器。
- 用户 `go` 已批准本轮建任务/规划与原最终实施方案；最新 `go` 追加批准两处同源消费者编码边界，全程不用子代理。
- 两处追加边界已实现；第二次验收为 64 passed/1 failed。新发现 Finding claim 枚举未排除
  Scanner 专属 summary，最新 `go` 已批准追加一条文件归属规则，详情见 Scanner 子任务 verification.md。
- Scanner 最终定向验收为 **67 passed, 225 deselected in 1.67s**，包括原 UTF-8 整链失败用例；
  Scanner 实现/规范完成待提交，安装筛选仍未实施。

## Requirements and Task Map

| 要求 | 可独立验收的子任务 | 结果 |
|---|---|---|
| R1：保留摘要健康、剩余输入和恢复入口，不把损坏变成成功空结果 | `09-28-scanner-summary-input-contract` | reader/gate 共用 Scanner 计数校验；损坏保持 partial/可复核 |
| R2：部署与只读检查的文件归属一致 | `09-28-installer-runtime-file-selection` | 两类 Markdown 复制循环遵循现有 Doctor 排除规则 |
| R3：不为修复扩大状态或维护面 | 两个子任务共同遵守 | 无新 owner/依赖/框架；保留原文件、禁用状态及完整材料 |

父任务只管理研究、需求和最终合并审查，不直接承接产品实现。

## Acceptance Criteria

- [x] AC1（R1）：错误容器、非整数/非有限/布尔计数和坏编码不可成为 valid/missing；已存在
  的合法整数、整数文本、空 lane 集合和缺少旧版可选字段保持兼容；真实剩余工作与原文引用可见。
- [ ] AC2（R2）：临时副本中安装筛选与 Doctor 一致；开发补丁不复制，禁用命令不恢复启用，
  外部 Skill/用户设置/Store 不被影响。
- [ ] AC3（R3）：每个子任务仅执行对应 focused 回归，产品 diff 不跨出批准边界；原始材料与
  两份旧暂存日志字节/暂存补丁不变，不复用第三批测试结果冒充本批验证。

## Out of Scope

- 实际扫描、个人 runtime 安装/同步/prune、部署、数据迁移、自动提交、合并或 push。
- 新状态源、通用摘要/快照/部署管理器、hash/schema 变更或整个 scanner 重写。
- Recon phase 计数、其他 JSON reader、未复现问题和旧暂存日志；不得顺手扩大修复。
- 临时 fixture 内的复制循环/后续隔离测试不属于个人 runtime 部署。
