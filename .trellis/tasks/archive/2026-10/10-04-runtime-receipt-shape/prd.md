# F09：安装清单结构错误边界

## 目标

损坏结构的安装清单通过既有启动错误边界返回可消费、有界的诊断，不让未处理的
AttributeError 中断 bootstrap，也不将坏清单当成空安装或自动修复它。

## 已确认背景

- 基线 `d2e451f`；F07/F08 已完成工作、归档和 journal 提交。用户要求继续现有 F09，
  不创建重复任务；随后以“go”批准最终实现计划，任务已激活。
- 来源 `/tmp/ccst-audit-2026-10-02/AUDIT.md:86-91`，F09/P2：合法 JSON 根数组或记录 null
  越过结构化错误边界。2026-10-06 源码研究后，13 个预期失败用例复现该缺口；
  修复后的定向回归 22 项通过，命令及证据见 `research/f09-runtime-receipt-shape.md`。
- `tools/runtime_doctor.py:159-168` 在 skills 比较中读取 `.ccst-installed.json`，直接调用
  根对象的 `.items()` 和记录的 `.get()`。唯一 writer `sync_runtime()` 已在 `:343-352`
  校验结构；本批缺口是只读消费侧，不是安装写入流程。
- `tools/autopilot_bootstrap.py:852-864` 已将 `OSError/ValueError` 转成 `stop_runtime_error`；
  `:906-922` 的 CLI 正常输出 JSON 后返回 0，停止语义来自 `action`，不是新增非零退出码。

## 要求

- R1：在现有 runtime receipt 只读入口消费时，根必须是对象，每个记录必须是对象。
  非对象根/记录抛 `ValueError` 并指出安装清单结构错误；不依赖捕获 AttributeError，
  不跳过坏记录，不以空对象兜底。
- R2：保留 bootstrap 既有 `stop_runtime_error`、`error.type/reason` 与单行 JSON 契约。
  reason 去换行且不超过 500 字符；错误后不进入 capability 探测或 target-state 获取。
- R3：保留读取兼容面：缺失清单、空对象、合法记录、额外字段、缺少 hash 的对象记录，以及
  被既有 kind 筛选忽略的对象记录不因本批新增字段要求而失败。commands-only/agents-only
  比较不新增 receipt 依赖；原有 skills 路径包含性检查不变。
- R4：只读比较和 bootstrap 失败不创建、删除、覆写安装内容或清单，不调用 sync。
  不改变 `sync_runtime()` 的写入校验、锁和发布顺序，不宣称显式 sync 的锁文件创建是零写入。

## 验收条件

- [x] AC1 / R1：真实 `compare_runtime()` 对根数组/null/字符串/数字/布尔值，以及记录的相同
  非对象类型均抛 `ValueError`，不是 AttributeError 或成功空比较结果。
- [x] AC2 / R2：真实 receipt reader → bootstrap `main(["--json", "--", ...])` 对根数组、
  根 null、记录 null 返回单行可解析 JSON，action 为 `stop_runtime_error`，type 为 `ValueError`，
  reason 有界、无 traceback，返回码仍为 0；现有错误边界覆盖长 reason 的截断。
- [x] AC3 / R3：合法清单比较结果不变；缺失/空清单不被补建或改写；既有宽松对象记录读取和
  commands/agents 选择保持兼容，不顺带增加 hash/kind/额外字段校验。
- [x] AC4 / R2,R4：坏清单处理前后的临时 repo/runtime 文件集合、字节和 mtime 保持不变；
  明确断言 capability、target-state 和 sync 入口没有被调用。
- [x] AC5 / R1-R4：隔离临时目录的定向回归通过；runtime owner 契约同步上述错误与兼容边界，
  不依赖真实 HOME、网络或安装操作。

## 范围与兼容边界

产品改动仅 `tools/runtime_doctor.py` 的 receipt 只读分支；测试在
`tests/test_runtime_doctor.py`、`tests/test_autopilot_bootstrap.py`，规范同步
`.trellis/spec/backend/contracts/runtime-autopilot.md` 的既有安装 ownership 章节。

不修改 bootstrap 产品代码或扩大其异常捕获。`runtime_doctor` 独立 CLI 仍采用原有错误出口，
本批不把它改为结构化错误协议。安装 receipt 不等于 `commands/autopilot.md` 内嵌 critical manifest。

## 顺序与批准边界

这是单一 owner 内的轻量修复，采用 PRD-only 规划；研究记录和两份真实 jsonl 上下文补齐证据。
实现、定向验证、独立复核与 spec 更新已完成。用户在原会话以“ok”批准四文件提交，恢复后
再次要求继续；工作提交为 `538975e`，任务于 2026-10-07 归档。历史质量检查包括相关测试
89 项、Ruff、py_compile 与 diff check；收尾时重新运行定向测试 22 项及 diff check，均通过。
journal 单独记录并引用工作提交；不推送、不自动开展 F10。

## 范围外

其他审计项、新 schema/version/helper 框架、通用 receipt reader/writer 重构、hash 格式收紧、
未知字段或重复 JSON 键策略、路径策略统一、自动迁移/修复、doctor CLI 错误协议重构、
真实目标操作、全局安装/同步和未经确认的数据迁移。
