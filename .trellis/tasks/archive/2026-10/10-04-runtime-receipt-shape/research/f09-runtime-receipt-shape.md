# F09 只读研究（2026-10-06）

基线 `d2e451f`；两项独立只读探索完成，主线程已点验目标 owner、bootstrap 边界、fixture
和 runtime ownership 契约。研究阶段未跑测试、安装或同步，未读取真实用户清单。
以下源码行号为研究基线；实施及验证结果单独记录在末尾。

## 调用与数据契约

- `tools/runtime_doctor.py:126-173` `_runtime_files()` 是本批修改点；`:186-188` 的
  `compare_kind()` 经 `:248-256` 的 `compare_runtime()` 调用。只在 skills 分支读 receipt，
  根 `.items()` / 记录 `.get()` 前缺对象检查，非法 JSON 形状产生 AttributeError。
- `.ccst-installed.json` 是路径 → `{kind, sha256}` 的对象。唯一 writer 为
  `sync_runtime()`（`:321-444`），已有根/记录与更强字段、路径校验；不应为了修读取崩溃
  把 writer 的全部约束搬到 reader。reader 不消费 hash，并忽略非 skills 的对象记录。
- 最小修复是该分支两层 `isinstance(..., dict)` guard，抛现有 `ValueError`，无需新 helper
  或异常类型。缺失 receipt/空对象的语义、kind 选择及现有 skill containment 检查保持不变。
- `tools/autopilot_bootstrap.py:852-864` 已捕获 OSError/ValueError，reason 使用
  `" ".join(str(exc).split())[:500]`；`:870` 后才做 capability，`:877` 后才读 target state。
  在此之前已有参数/CTF/scope 读取，不能写成“所有读取前失败”。`:906-922` JSON CLI 返回 0。
- doctor CLI `:495-542` 不捕获上述错误；安装入口 `install.sh:43-44` 用 `--sync --prune`。
  sync 已在内容发布前拒绝坏结构，但此前可能创建 runtime 目录和锁文件；本批不改变写路径。

## 测试落点与陷阱

- `tests/test_runtime_doctor.py:24-55` 提供 `_repo_fixture`、`_runtime_fixture` 和合法 receipt
  producer；`:76-109` 固定精确比较结果；`:68-73,322-334` 覆盖无 receipt 的外部 skills 忽略。
  用相同 fixture 参数化非对象根/记录，并补缺失/空对象、宽松对象记录与非 skills 比较的兼容断言。
- `tests/test_autopilot_bootstrap.py:298-316` 只有 mock OSError；新增三个真实坏 receipt 场景
  必须保留真实 `compare_runtime`。`:628-648` 提供单行 JSON CLI 调法。
- 显式设置临时 `REPO_ROOT`、`CCST_RUNTIME_ROOT`、HOME/cwd，防止落到真实 `~/.claude`。
  在放好坏 receipt 后快照文件路径、bytes、mtime；不比较读取会改变的 atime。
- capability 入口的 AssertionError 哨兵会被产品里的 `except Exception` 吞掉，因此仅抛异常
  不能证明没调用。使用 Mock 的 `assert_not_called()` 或显式调用记录，同样检查 state/sync。
- 现有错误用例可增加长 ValueError 文本，证明 500 字符截断；无需让新 owner 文案带原始清单内容。

## 定向检查命令

新增用例名称带 `receipt`，复用现有 pytest 与 fixture；实际执行结果见下方记录。

```bash
python3 -m pytest -q tests/test_runtime_doctor.py tests/test_autopilot_bootstrap.py \
  -k 'receipt or runtime_read_error or compare_runtime_reports_diff_missing_and_extra or compare_runtime_ignores_unrelated_external_skills'
git -c safe.directory="$PWD" diff --check
```

只需 owner 回归和真实 bootstrap 消费链，不执行全仓测试、构建、installer 或真实网络验证。
规范落在 `.trellis/spec/backend/contracts/runtime-autopilot.md:1222-1260` 的既有七节契约；
错误层原则见 `.trellis/spec/backend/error-handling.md:10-11,33-34`。

## 实施与验证记录（2026-10-06）

- 用户“go”批准最终计划后激活既有任务。主线程只在 `_runtime_files()` 增加根/记录对象
  检查，抛既有 ValueError 文案；没有改 bootstrap 产品代码、sync、路径规则或字段要求。
- 在修改产品代码前运行：

  ```bash
  python3 -m pytest -q tests/test_runtime_doctor.py tests/test_autopilot_bootstrap.py \
    -k 'receipt_shape' --tb=short
  ```

  **13 failed、76 deselected，1.25 秒**，均为预期 AttributeError：10 个 owner 类型场景，
  3 个真实 bootstrap JSON 入口场景。已核对 traceback 来自 receipt 的 `.items()` / `.get()`。
- 修复后运行上方定向检查命令：**22 passed，exit 0**；随后 `git diff --check` 通过。
  未执行全仓测试、构建、lint、typecheck、安装、同步或网络验证，未读取真实用户安装清单。
- 新的一次性只读探子复核完整四文件 diff、PRD 与相关规范，未发现阻塞问题；不重跑测试。
  主线程随后完整复查 diff，无额外 helper/依赖、异常兜底、隐藏行为变化或无关改动。
- 根因与防复发：合法 JSON 不代表根/记录可以调用对象方法；在实际 reader 的对象消费点
  校验形状，沿既有 ValueError 通道传播。真实 reader → CLI 回归防止 mock 只证明异常格式，
  `assert_not_called()` 防止 capability 的 broad catch 掩盖失败哨兵。七节 runtime 契约已同步。
- 最终质量检查由一次性 `trellis-check` 探子完成：未发现需要修复的具体问题；完整相关测试
  **89 passed**，`ruff check tools/runtime_doctor.py tests/test_runtime_doctor.py tests/test_autopilot_bootstrap.py`
  通过，三文件 `python3 -m py_compile` 通过，`git diff --check` 通过。检查未提交改动。

### 验收证据

| 条件 | 实际用例或检查 |
|---|---|
| AC1 | `test_compare_runtime_rejects_invalid_receipt_shapes` 的 10 个参数场景 |
| AC2 | `test_runtime_receipt_shape_error_is_structured_without_writes` 的 3 个真实 CLI 场景；`test_runtime_read_error_is_structured_before_target_state` 的换行与 500 字符边界 |
| AC3 | `test_compare_runtime_preserves_receipt_read_compatibility`、`test_compare_runtime_does_not_read_receipt_for_other_kinds`，以及既有精确 counts / 外部 skills 回归 |
| AC4 | owner 与 bootstrap 用例比较所有临时路径、文件 bytes/mtime；CLI 用例显式断言 capability/state/sync 未调用 |
| AC5 | 22 项定向回归、相关完整测试 89 项、Ruff、py_compile、`git diff --check`、临时 HOME/runtime 隔离及契约 diff 复核 |

## 恢复与收尾（2026-10-07）

- 从会话 `01a10ef4-1876-7b32-8c2e-6c967d8b96c1` 恢复，核实用户最终“ok”已批准提交；
  原会话随后因资源错误结束，没有执行提交或归档。
- 重新运行上方定向检查：**22 passed，exit 0**，`git diff --check` 通过；不重复完整相关测试。
  历史 89 项、Ruff 和 py_compile 结果已通过原始执行日志核实；py_compile 是编译检查，
  不是完整静态类型检查。
- 四文件工作提交为 `538975e`；通过 `task.py archive --skip-branch-validation --no-commit`
  归档真实在 `main` 完成的任务，再显式提交准确归档目录。journal 另行记录并引用工作提交；
  不推送、不启动 F10。
