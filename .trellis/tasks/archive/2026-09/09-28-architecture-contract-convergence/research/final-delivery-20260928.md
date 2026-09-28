# 架构契约收敛验收（2026-09-28）

基线：main@846670c9c30dccf111612e0f03c17516dc67fd4a。
代码提交：038e2a72ae4dfde3fb828bdb67159371fc57c086。
原始 R1–R10/M1–M8 的工程交付保持有效；本轮依据 requirement gap map 完成剩余结构收敛。

## 交付

- 五组 tools 静态循环依赖消除；最终 129 个模块无环，包含函数内 import 和直接执行 fallback。
- wire vocabulary、decision schema、敏感观察文本校验归 contracts；证据路径准入归 target_paths。
- Scope 匹配/列表解析归 scope_context；Browser readiness 归 browser_evidence；Resume 查询归
  resume_read，CLI 保留渲染与 Checkpoint 编排。已有实际消费者的 Resume 公共导出保留。
- 36 个模块的 40 处普通文件发布实现归 artifact_io；共享同目录独立临时文件、UTF-8、
  0600、flush/fsync、replace 和清理。各 owner 保留锁、准入、格式和多文件提交顺序。
- JSON ASCII/排序、OAST indent=1/无末尾换行、流式 inventory 和 Recon URL hash 不变。
- 明确的行为改善：param_discovery 和两处 migration 激活 receipt 不再用固定临时文件；
  它们和 distill_digest 补文件 fsync；js_reader 自动创建缺失父目录；清理覆盖中断。
- 保留 Scope CAS/目录 fsync、migration backfill receipt 的目录耐久性、Store fence、
  Action/Validate/Report 排他不可变发布、Case/Surface 多文件顺序、spray 可配置权限。
  通用 writer 不宣称目录 fsync、跨文件事务或读改写锁。
- CI core 纳入依赖图和发布失败恢复检查。Scope/持久化/质量规范、架构文档和仓内
  Python、Shell 内嵌 Python、隔离测试样本同步到新 owner。

## 验证

| 检查 | 实际结果 |
|---|---|
| `python3 -m pytest -q tests --disable-warnings --maxfail=5`（最终） | **2554 passed** |
| 最新发布迁移定向检查（依赖/Guard/scanner/Recon/intel/知识/OAST/migration） | 125 passed |
| 门禁扫描、隔离 spray、Store/Resume 消费与依赖图修复复验 | 153 passed |
| `bash tests/test_recon_denoising_integration.sh` | 通过 |
| `bash -n tools/recon_engine.sh tools/vuln_scanner.sh` | 通过 |
| Ruff `F821,F811` | 通过；新增未用导入已移除 |
| `git diff --check`、质量指南长度/专题链接约束、task context validation | 通过 |
| 迁移前后 AST 比对 | 14 个迁移函数（除重命名/去除 Scope 反向 import）和 5 个共享声明保持一致 |
| journal 字节及原暂存补丁 SHA256 | 与任务基线一致 |

中间回归发现 Resume 渲染漏保留 shlex，已修复。首次全量 2551 passed / 3 failed：
共享校验迁移后门禁扫描未包含 contracts、隔离 spray 未复制 scope_context、Store 测试
仍引用旧 Resume 私有位置。三处均同步到新 owner；门禁总数下限保持 15（Queue 12 +
contracts 3），其余行为断言未减弱。最终全量已覆盖这些修复。

## 维护与能力边界

可核实的维护收益是：无静态循环、共享契约与发布机制只有一个实现、责任所在与测试位置
一致；未新增第三方依赖、领域 owner、ORM、运行时服务或路由框架。
领域 schema、生命周期、证据强度、Scope 和真实目标状态不因这次模块移动而更改。
新的 Python 导入位置写入架构/Scope 规范，旧 target_paths 的 Scope 导出不再保留。

本轮未测量整体维护工时或宣称模型收益；已接受的固定 48 阶段在线评估不重开。
没有操作真实目标、个人 runtime、审计原件、远端、部署或创建 PR。
原用户暂存 journal 不纳入提交；本次会话记录保存在本任务报告，避免覆盖既有日志。
