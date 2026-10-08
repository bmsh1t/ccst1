# F06–F11 集中验收证据与命令候选

调研基线：`a31535d`。本轮仅静态读代码、git 历史、配置、日志，以及查询 Python/已安装 distribution 元数据；**未执行 pytest、collect-only、产品 CLI、网络、真实模型、安装或 runtime 同步**。fast-context 工具元数据明确其搜索会调用远端 AI，因此本轮遵守离线边界，改用本地检索；未读取真实目标目录或 `.env`。

## 1. 工作提交与现有可执行断言

| 项目 | 工作提交 | 现有入口与主要覆盖 |
| --- | --- | --- |
| F06 | `b63ad6a98c17c14305612ed387028d91a0de5fd9` | `tests/test_finding_index.py:1320` `test_hunt_report_count_uses_current_index_not_stale_files`：10 种子进程执行/协议/count 场景；`:1347` 无 finding 不启动子进程。`tests/test_hunt_initialization.py:191` single failure 真入口退出 2；`:205` batch 继续且保留成功结果；`:223` 全零成功；`:235` missing/empty/file/files-only；`:268`、`:302` 非报告分支保持分发/错误码；`:314` 不吞未知异常。 |
| F07/F08 | `fd02dc84cf829d418192354f72088c19ba20ed0b` | `tests/test_finding_index.py:1055` `test_report_attachment_publication_selects_only_current_draft`：只复制所选正文资产、忽略其他草稿/FIFO/坏链接；`:1095` copy 损坏同时使 report/index/current delivery 失效但保留历史；`:1148` registration/index 部分失败与健康重试；`:1183` 已登记重试不得补回/重发 copy；`:1370` selected source 损坏。`tests/test_target_store.py:535,557` 引用协议/畸形路径；`:563` direct registration 文件拒绝；`:590` 无附件兼容；`:607` precommit 文件漂移；`:632` hash 不进入写事务；`:660` delivery commit 复查正文事件；`:685` direct replay 不绕过撤回正文；`:491,705,721,745` registration/delivery/currentness 基线。 |
| F09 | `538975e1b5f2fe57f5bd332bff39a7e0abcb4395` | `tests/test_runtime_doctor.py:78` `test_compare_runtime_rejects_invalid_receipt_shapes`：root/record × null/list/string/number/bool；`:100` missing/empty/宽松字段兼容；`:117` 非 skills 不读 receipt；`:129` 正常 diff/missing/extra。`tests/test_autopilot_bootstrap.py:303` reader 错误在 state 前结构化；`:325` **真实 compare_runtime → bootstrap.main** receipt 错误返回 `stop_runtime_error`，无需 probe/state/sync，bytes/mtime 不变。 |
| F10 | `6245fb06e59a6aeeef60b5ad138305eee58f46dc` | `tests/test_disclosed_pattern_dedup.py:175` `test_failed_refresh_preserves_success_snapshot`：无/有 cache × total/client_missing/partial_report/partial_empty/fallback；`:218` 完整成功空结果替换旧 cache；`:243` 健康 cache 时间；`:265` no-MCP 不读 cache；`:281` 非有限 TTL；`:294` 坏 owner response 与独立成功；`:325` 坏 cache 诊断且保全；`:362,386` **真实 provider parser → owner/cache** 坏 envelope/兼容 response；`:404` cache/Markdown 原子发布失败。 |
| F11 | `3c83280` | `tests/test_target_memory_cli.py:357` `test_documented_guidance_reads_current_store_without_mutation`：真实三文档提取 11 个读取命令，current/empty/missing，selected Finding 精确关联且忽略旧投影；`:423` `test_documented_memory_writes_preserve_conditions_and_reject_incomplete_negative`：lead/next/dead-end/handoff/note 真实 CLI 持久化条件/引用，无证据 note 可用，negative 缺 conditions/reopen-when/operation-ref 拒绝且不写，actions 保持 0。 |

报告链额外已有集成桥，不需新脚本：`tests/test_validate_target_mode.py:591` `test_machine_report_replay_preserves_body_and_isolated_root` 从合成 runner evidence/decision 经 validate → Store report/runtime summary，核对当次 `summary_path`、重复执行 body/inode/mtime 不变；`:645` recovery 拒绝改变/缺失正文，`:668` 禁止跨 Finding 复用已登记路径，`:683` 原子 publication 失败可恢复。这同时连到 F01–F05 的证据/Store 边界与 F11 的当前 summary 指导。

## 2. 历史通过不是本轮通过

来源均为 `.trellis/workspace/Codex/journal-1.md`：

| 位置 | 当时命令/结果与限制 |
| --- | --- |
| `:690` | F06：`python3 -m pytest -q tests/test_finding_index.py tests/test_hunt_initialization.py -k 'hunt_report or report_only or non_report'` → **27 passed**，2026-10-06。 |
| `:727–728` | F07/F08：finding_index + target_store + validate_target_mode，`-k 'attachment or screenshot or attach_images or report or delivery_event or finding_authorization'` → **130 passed，在两处最后修复之前**；修复后 finding_index + target_store，`-k 'report_attachment_registered_retry or report_attachment_direct_replay or report_attachment_retry or report_registration or explicit_report_retry_does_not_repair or report_attachment_damage_invalidates'` → **13 passed**。不可把 130 说成最终完整重跑。 |
| `:764–765` | F09：runtime_doctor + autopilot_bootstrap，`-k 'receipt or runtime_read_error or compare_runtime_reports_diff_missing_and_extra or compare_runtime_ignores_unrelated_external_skills'` → **22 passed**；更早两文件 **89 passed**/Ruff/py_compile 仅历史，不是本轮。 |
| `:802–803` | F10：完整 test_disclosed_pattern_dedup **80 passed，在最后 coverage_status 修正之前**；最后修正后 `-k 'bad_cache or healthy_cache or failed_refresh'` → **30 passed**。日志明确没有完整 83 项重跑，因此集中验收适合一次跑该文件。 |
| `:840` | F11：`python3 -m pytest -q tests/test_target_memory_cli.py` → **18 passed**。 |

## 3. 建议合并成三个离线命令组（待主计划批准，不在调研中执行）

以下是可复用选择器；主代理应与 F01–F05 合并去重，而不是照抄每一条历史命令再追加：

```bash
# A: F06 + F07/F08 + validate/report bridge, one pass over shared files.
python3 -m pytest -q \
  tests/test_finding_index.py tests/test_hunt_initialization.py \
  tests/test_target_store.py tests/test_validate_target_mode.py \
  -k 'report or attachment or screenshot or attach_images or delivery_event or finding_authorization or non_report'

# B: F09 exact reader/consumer boundary, excluding unrelated runtime sync coverage.
python3 -m pytest -q \
  tests/test_runtime_doctor.py tests/test_autopilot_bootstrap.py \
  -k 'receipt or runtime_read_error or compare_runtime_reports_diff_missing_and_extra or compare_runtime_ignores_unrelated_external_skills'

# C: F10 final whole-file coverage + F11 documented-CLI/store chain.
python3 -m pytest -q \
  tests/test_disclosed_pattern_dedup.py tests/test_target_memory_cli.py
```

- 若 F01–F05 的主组已包含完整 `test_target_store.py` / `test_validate_target_mode.py` / `test_finding_index.py`，从 A 删除该文件；记录一次结果覆盖多个 F 编号。若仅部分选择器重叠，在主组取选择器并集，不重复跑相同 nodes。
- C 对 F10 有价值是最后修改后未有整文件当前证据；F11 整文件只历史 18 项，保留真实进程重启/错误输入及文档新节点，比另建 smoke harness 更直接。
- 无需再执行每个修复的旧 targeted 小组；集中组成功即覆盖它们。异常只在本组/归因范围定位，不自动触发全 suite/build/lint/无关修复。
- 预计节点数不是通过数量：本轮没有 collection，最终确切 collected/deselected/pass/fail/skip 与时长由实际获批命令记录。

## 4. 静态隔离证据与边界

- F06 CLI harness `tests/test_hunt_initialization.py:140–184` 在 tmp root/cwd/HOME，最小 env，`runtime_exec.run_argv_command` 完全 mock，`subprocess.Popen` 和 `socket.socket.connect` 明确 fail-fast；内部 `timeout=15`。count 测试 `tests/test_finding_index.py:1322–1330` 全部 tmp paths + mock runner。
- F07/F08 report fixture `tests/test_finding_index.py:318–329` 为 tmp Store；`:1035–1091` mock `REPORTS_DIR` 到 tmp，截图为本地固定 bytes，不启动浏览器/模型。direct Store 测试使用 `tmp_path`。报告 CLI `:1021–1032` 从 tmp findings 推导 repo root，真实子进程只发布本地正文（timeout 30）。
- F09 fixtures `tests/test_runtime_doctor.py:28–73` 手写临时 commands/agents/skills/receipt；bootstrap `tests/test_autopilot_bootstrap.py:325–359` 临时 repo/runtime/home + HOME/CCST_RUNTIME_ROOT/chdir，capability/state/sync 设置为一调用即失败。这里的 receipt 不是全局安装清单。
- F10 `_old_cache` `tests/test_disclosed_pattern_dedup.py:163–170` 仅 tmp cache；`:192–194,307–309,333–334` provider mock；所谓 real-provider 节点 `:340–346` 只加载本地模块，`:370–372,388–390` 替换 `_graphql_request`，不运行 live GraphQL。import 仅建 SSL context，provider 网络入口 `mcp/hackerone-mcp/server.py:65` 的 urlopen 不在所选测试路径执行。
- F11 `tests/test_target_memory_cli.py:299–320` 只提取 target_memory/target_store/experience_recall 命令，用 `sys.executable -B`、`--repo-root tmp`、timeout 20；`:335–353` 录制 synthetic response bytes，不实际请求 URL；`:416–420,463–473` 检查 no-write/no-actions。**不是执行文档里的 validate/scanner 命令，也不是激活 Autopilot。**
- 以上为所选路径静态证据，不是 OS 级网络隔离证明。`tests/conftest.py` 只有路径/fixture，无全仓 autouse 网络阻断；不要将任意扩大后的测试集自动视为同样离线。

## 5. 环境、CI 与 timeout/logging

- 根 `conftest.py:1–2` 仅忽略 `archive/*`，`tests/conftest.py:8–14` 注入 repo/tools import 路径；根无 pyproject/pytest.ini/tox.ini/setup.cfg。显式文件列表优于裸 `pytest`。
- `.github/workflows/ci.yml:18–63` core-contracts 自带精选列表，包含 finding_index/runtime_doctor/target_memory_cli/validate_target_mode；**不包含** hunt_initialization/target_store/autopilot_bootstrap/disclosed_pattern_dedup。单跑 core CI 列表不能声称 F06–F11 全覆盖。
- CI core timeout 15 分钟 `:20`；full suite `:69–88` 仅 main push/schedule/手动触发且 timeout 30 分钟，是发布/周期预算，不是当前集中离线验收必须复制的层次。
- CI Python 3.13、锁文件安装 `:25–31`。当前只查元数据：`/usr/bin/python3` **3.13.5**；pytest **9.0.2**、requests **2.32.5**、PyYAML **6.0.2**、certifi **2025.11.12**；`pytest-timeout` **未安装**。锁为 pytest **9.1.1** (`requirements-ci.lock:733`)、requests **2.34.2** (`:812`)、PyYAML **6.0.3** (`:737`)。这是版本偏差记录，不是阻塞或暗示本轮应联网安装；若未来 import/collection 因依赖失败，报告环境缺口，不全局 pip 修复。
- Linux/POSIX 必需：目标 Store/runtime 用 `fcntl`，附件测试有 `os.mkfifo`、symlink、inode 断言；当前 Linux 适用。无需安装 Playwright browsers、执行 installer、加载凭据。
- `/usr/bin/timeout` 已定位；不用不存在的 pytest-timeout/`--timeout`。每组先给约 **60 秒**预算，`timeout --signal=TERM --kill-after=5s 60s`；超时 124 与强杀 137 单列，不当成断言失败，不原样盲重跑。可用 pytest 内置 `-o faulthandler_timeout=45` 获取慢点栈，`--durations=10` 记录实际耗时，无新 harness。
- 每组创建独立 `/tmp/ccst-acceptance.XXXXXX`；env `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1`，pytest `-p no:cacheprovider --basetemp="$RUN/tmp" --junitxml="$RUN/junit.xml"`，stdout/stderr 重定向 `"$RUN/pytest.log"`，紧接保存 `$?` 再 cat。不要裸 `| tee` 丢退出码，也不要复用 basetemp（pytest 会清理它）。日志包含基线、完整命令/选择器、解释器版本、exit/status/count/skip reason/耗时即可；保留超时的不完整日志，JUnit 可能尚未生成。禁用插件不是网络沙箱。

本轮产出只有此研究文件，未修改产品、测试、任务状态或全局 runtime。
