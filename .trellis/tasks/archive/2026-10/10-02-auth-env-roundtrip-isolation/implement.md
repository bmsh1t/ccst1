# 认证环境导出与重载隔离：执行计划

## 开始门禁

- [x] 已确认 owner、实际调用者和已有兼容性测试，完成 PRD 收敛。
- [x] 已具备 PRD、设计、执行计划与真实 spec/research context。
- [x] `task.py validate` 通过（implement 6 项、check 5 项 context）。
- [x] 用户在最终计划后回复 `go`；已运行 `task.py start`，状态为 `in_progress`。

## 实施顺序

1. 重新确认工作区基线；保留 `.trellis/spec/backend/contracts/runtime-autopilot.md`、`agents/recon-ranker.md`、`tests/test_recon_ranker_contract.py` 的 R17 改动。读取 before-dev 和相关规范，主代理亲自阅读待修改代码。
2. 在 `AuthSession.export_to_env()` 完成八键清理再应用 overlay，更新其 docstring；不修改解析/来源优先级和消费者。
3. 新增一个 focused regression 文件 `tests/test_auth_session.py`：覆盖原始四类凭据、旧/坏环境、空会话、空 mapping、未绑定会话、显式 Origin、scheme/port、幂等与原对象不变；验证初次原始环境/文件/CLI 来源与冲突拒绝仍保持。通过临时子进程 source 真实 `_auth_helper.sh`，断言 URL 级参数和 session ID，而非只检查生成字符串。
4. 更新 `.trellis/spec/backend/quality-guidelines.md` 现有认证条款，记录“初次来源读取”与“已选会话导出替换”的边界，不新增专题文档。
5. 执行下列单批定向验证，随后审阅整个任务 diff。确认没有重复清理逻辑、隐式 fallback、凭据日志、无关变更或仅断言实现细节的测试。

## 验证命令

```bash
python3 -m pytest -q tests/test_auth_session.py \
  tests/test_validation_runner.py::test_cli_auth_file_builds_session_and_raw_header_keeps_precedence \
  tests/test_validation_runner.py::test_redirect_handler_rejects_off_target_redirect \
  tests/test_validation_runner.py::test_cross_origin_redirect_replays_only_explicitly_authorized_session_headers
```

新测试使用合成凭据、受控环境和临时目录；Shell 检查不发请求。既有跨 Origin 重定向回归只使用其自建 loopback HTTP server，不访问真实目标或外部网络。预计单批在 60 秒内完成；不默认全量测试、build、安装依赖或全局 runtime 校验。环境无法创建 loopback listener 导致 skip 时如实记录，不把 skip 当通过。

## 实施与核验结果（2026-10-02）

- 已完成 `tools/auth_session.py` 的 owner 修复、新增 `tests/test_auth_session.py`，并更新质量规范；未修改消费者或初次来源选择。
- 上述定向 pytest 命令：**37 passed**（34 个新增参数化用例、3 个既有兼容回归）；无 skip。
- `git diff --check`、新文件 `git diff --no-index --check /dev/null tests/test_auth_session.py` 均无错误；质量规范的行数、专题标题及六项契约链接检查通过。
- 只读代理 `/root/auth_env_regression_review` 完成本任务全差异独立核验，无阻断发现；主代理随后亲自检查完整 diff 并运行验证。
- R17 三个文件的 SHA-256 与实施前一致；无真实目标或外部网络访问，无新依赖、全局 runtime 修改或自动提交。
- 用户确认后已提交 `4646762`（`fix: isolate auth session environment exports`），仅包含 owner、测试及质量规范三个文件；R17 仍未提交，未推送。任务尚未归档。

既有审核的 F01 复现结果保存在 `/tmp/ccst-audit-2026-10-02/results.json`；长期回归证据现由仓库内测试承载。

## 停止与提交

不因无关失败扩大修复范围；没有新证据不重跑同一失败命令。若发现需要改变来源选择或 Scope 契约，回到规划重新确认。成功后列明本任务改动及排除的 R17 文件，取得提交批次批准再提交，不推送、不提前归档。

## 集中验收与归档（2026-10-08）

基线 `a31535d` 的 `A-auth` 组一次通过 **37 项**，无失败/错误/跳过；主线程逐项核对原始 AC。
本任务已归档，保留上述原工作提交；完整证据见 `../10-04-stabilization-acceptance/acceptance.md`。
