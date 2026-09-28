# Scanner 子任务：验收与范围补充

状态：最终定向验收已通过，规范已同步，工作提交 e755065 已完成；用户确认归档。本轮只实施 Scanner，安装器未修改。
分支：`fix/scanner-summary-input-contract`；基线：`7c3556d`。无子代理、提交或部署。

## 已实现

- `_scanner_lane_accounting()` 位于现有 reader，reader/gate 复用；保留无效标志和有效计数，拒绝有损转换。
- reader 区分缺字段与错误容器，坏编码保持 partial；新增真实原文、直接 gate、真实 Store 恢复路径回归。
- 原两文件实现后，已按用户追加批准修复 Coverage/Surface 的 UnicodeError 边界；安装器未修改。

## 实跑结果

```bash
python3 -m pytest -q tests/test_autopilot_state_tool.py tests/test_scanner_pass.py -k 'scanner or residual_global_review'
```

退出码 1：**60 passed, 1 failed, 225 deselected in 1.54s**。完整输出在 `research/first-check.log`。
没有重复运行同一失败检查，也未删掉失败测试或缩小它的断言。

失败：`test_scanner_summary_damage_preserves_store_work_and_closure_diagnostics[坏 UTF-8]`。
真实调用链为 `build_autopilot_state -> resume -> runtime_state -> read_matrix -> _xss_policy_skip`，
先于 Scanner reader 读取同一 summary，因 UnicodeDecodeError 中断。
出错位置：`tools/coverage_matrix.py:1513-1520`。

随后用临时文件分别直接调用 `_xss_policy_skip()` 和
`surface_projection.scanner_manual_review_paths()`；两者均复现 UnicodeDecodeError，退出码 0
（脚本断言这两个现存缺陷）。第二处位于 `tools/surface_projection.py:45-54`。
临时原文为 `b"\xff\xfe"`，两个读取前后字节相同，未使用实际 target 或个人 runtime。

## 最小范围修订（用户最新 go 已批准）

增加两个现有同源消费者的坏编码边界：

- `tools/coverage_matrix.py::_xss_policy_skip`
- `tools/surface_projection.py::scanner_manual_review_paths`

仅在已有坏 JSON/OSError 分支中同时处理 UnicodeError；不改覆盖授权、XSS 策略、
Surface 路径归属或通用 JSON reader，不新建 parser/owner。Scanner reader 仍负责公开 partial
诊断；另两个可选投影不从无法解码的源猜出 skip 或 manual-review 条目。

补充两个消费者的定向断言和既有 XSS policy 兼容用例，再重跑有针对性的单条命令。
产品范围从 2 个文件增至 4 个。首次验收后已停止扩大修改并请求确认；用户最新 `go` 已批准，
保留原失败集成测试，继续实施这两处边界并执行更新后的 focused 验收。

## 第二次验收：两处边界已修复，整链仍未通过

```bash
python3 -m pytest -q tests/test_autopilot_state_tool.py tests/test_scanner_pass.py tests/test_coverage_matrix.py::test_default_xss_skip_is_visible_without_closing_coverage -k 'scanner or residual_global_review or default_xss_skip'
```

退出码 1：**64 passed, 1 failed, 225 deselected in 2.02s**。
完整输出在 `research/second-check.log`。新增辅助消费者的合法输入/坏 JSON/坏 UTF-8 回归均通过，
既有 XSS skip 不闭合覆盖的兼容用例通过；原真实 Store 集成测试保持原样，坏 UTF-8 变体仍失败。

当前失败链：`build_autopilot_state -> _load_autopilot_control_facts -> list_root_finding_claims
-> _load_json_value -> UnicodeDecodeError`，位于 `tools/finding_index.py:744,803`。
Coverage 原阻断已解除，后续 root `*.json` glob 又读到同一 summary。

## 新发现的归属缺口（用户最新 go 已批准）

`finding_index.ROOT_CLAIM_EXCLUDED_FILES`（149–168 行）已明确排除机器摘要/索引，却缺少 Scanner
专属 `summary.json`。`list_root_finding_claims` 在解码前检查该集合；`_root_claim_from_json` 也复用
同一分类函数。故最小根因修复是把 `summary.json` 加入既有排除集，不是让通用 JSON reader
吞掉更多错误。后者还影响 `load_legacy_finding_index`，超出本任务且会隐藏别的损坏材料。

已批准追加 `tools/finding_index.py` 的一条排除项；在当前 Scanner 测试中断言坏编码/伪 claim
形状的 summary 均不进入 Finding claim，同时独立 `claim.json` 及完整原文继续可见，Store 不变。
产品边界由 4 文件增至 5 文件；继续保持原失败整链回归，不缩小验收或修改通用 parser。

已用 fast-context 检索及精确调用点核对同源消费者；未发现另一个直接解析该 summary 的主链 reader。
这不是整链通过的证据，仍须在获批修复后运行同一 focused 检查。
第二次验收后已停止重跑并回到范围规划；最新 `go` 批准该归属修复，继续实施。提交与安装子任务仍未开始。

## 最终验收：67 passed

第三轮仅补 `ROOT_CLAIM_EXCLUDED_FILES` 的 `summary.json`，没有改变通用 `_load_json_value`。
新增两项参数化断言：坏 UTF-8 与伪 claim 形状 summary 均被排除，独立 claim 的 payload、候选状态、
原始字节和 Store binding 保持不变。原失败的真实 Store 集成测试未改。

```bash
python3 -m pytest -q tests/test_autopilot_state_tool.py tests/test_scanner_pass.py tests/test_coverage_matrix.py::test_default_xss_skip_is_visible_without_closing_coverage -k 'scanner or residual_global_review or default_xss_skip'
```

退出码 0：**67 passed, 225 deselected in 1.67s**；完整输出见 `research/final-check.log`。
这包括坏 UTF-8→bounded state→Closure 的真实 Store 链路、直接 gate、可选消费者与合法 XSS skip。
通过后不再叠加全仓、构建或重复测试；没有真实扫描、安装、部署、提交或 push。

## Bug Analysis: 同源摘要不等于同一消费边界

### 1. Root Cause Category
- **B/C/D/E**：跨层输入契约、重复计数解释、整链覆盖缺口与“JSON 文本一定可解码”的隐式假设。

### 2. Why Fixes Failed
1. reader/gate 单点修复没有覆盖先执行的 Coverage 解码；只测 reader 无法证明状态恢复。
2. 同源显式 reader 修复后，root `*.json` 的隐式枚举仍把 Scanner 产物当 claim 输入。

### 3. Prevention Mechanisms
| Priority | Mechanism | Specific Action | Status |
|---|---|---|---|
| P0 | 归属 | 复用现有非 claim 文件排除集，不放宽历史 reader 的错误处理 | DONE |
| P0 | 回归 | 保留原真实 Store 整链测试，并验证独立 claim 和 raw 不变 | DONE |
| P1 | 契约 | Recon/Surface 现有七段场景补充计数、编码与文件归属 | DONE |

### 4. Systematic Expansion
- 同源显式读取与 glob 枚举都纳入本次核对；Recon 和其他 JSON reader 无已批准复现，不扩修。
- 计数只收敛到现有 Scanner reader 的一个纯函数；没有新 owner、parser 框架、依赖或额外 I/O。
- 下次从真实入口追踪读取顺序，搜索已知路径之外的文件枚举；不要用局部通过替代整链通过。

### 5. Knowledge Capture
- [x] `.trellis/spec/backend/contracts/recon-surface.md` 已同步相关签名、错误矩阵和回归断言。
- [x] 无适用的模板副本；此处只修改项目契约，不改 Trellis 框架。

## 完整差异审查与提交计划

- 已检查五个产品文件、回归和规范的完整 diff：无新增状态 owner、依赖、schema/hash、额外读取，
  无通用吞错、重复计数规则、源写入或无关产品变更。归属排除不是调用方异常补偿。
- `git diff --check` 通过；未额外执行 lint/typecheck/build/full suite，定向行为回归已提供所需证据。
- `sha256sum -c /tmp/fact-contract-baseline.vmDsm7/worktree.sha256` 两项均 OK；
  两份日志的 `git diff --cached --binary` 与 `staged-before.patch` 经 `cmp` 一致。
- 拟一个工作提交：`fix: preserve scanner summary input integrity`。包括五个产品文件、
  `tests/test_autopilot_state_tool.py`、`.trellis/spec/backend/contracts/recon-surface.md`，以及本轮
  父任务/Scanner/安装筛选三个任务目录的规划、研究与验收记录；安装筛选只有规划，无实现。
- 明确排除 `.trellis/workspace/Codex/index.md` 和 `.trellis/workspace/Codex/journal-1.md`。
  获批后仅按上述精确路径 `git add -f` 必要的任务记录，再 `git commit --only`，不吞入旧暂存日志。
- 当前未提交；归档与后续安装器实现另按既定任务顺序处理，不合并、不 push、不部署。
- 用户随后回复“提交”，已确认上述清单。暂存检查仅在 pytest 原始 `second-check.log` 中发现
  框架生成的行尾空格；保留该日志原字节，不当作源码格式错误。其余暂存内容单独通过空白检查。

## 交付与归档

工作提交：`e755065 fix: preserve scanner summary input integrity`。用户后续 `go` 已确认归档并推进安装器子任务。两份旧暂存日志不纳入归档提交，保留其内容和暂存补丁；本次不调用会修改它们的 add_session.py。
