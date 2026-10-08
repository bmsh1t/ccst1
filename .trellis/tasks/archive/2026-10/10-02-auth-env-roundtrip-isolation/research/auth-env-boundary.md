# Auth 环境替换边界

## 已确认事实

- `tools/auth_session.py:185-210`：`from_env()` 先读取导出 headers，再读原始 header/cookie/bearer/api-key；旧原始值能覆盖已选会话。
- `tools/auth_session.py:380-404`：overlay 省略无值字段；导出非空 overlay 只做 update，空会话只删除四个派生字段。这是旧认证和授权范围泄漏的共同根因。
- `tools/hunt.py:132-143`：`_runtime_child_env()` 复制进程环境，处理平台凭据后调用选定 AuthSession 的 `export_to_env()`。Recon/scanner 使用该入口（约 `:810,883`）。
- `tools/hunt.py:1456-1457`：选定且绑定的会话导出到 `os.environ`，与子环境出口共用 owner。
- `tools/_auth_helper.sh:19-45,87-100`：Shell 参数读取派生 headers/session/target，URL 允许检查再用 Python `from_env()`；污染环境能造成两条消费路径不一致。
- Shell 的 `bb_auth_bind_target()` 已在 target mismatch 时清理原始凭据；不要再在各调用者重复添加补丁。
- 只读调用者检索（`/root/auth_env_consumers`）未发现生产代码手动合并 `env_overlay()`；其生产调用者为 `export_to_env()`。

## 兼容性与排除项

初次来源消费者包括 `validation_runner.py:1466`、`param_discovery.py:793` 和 `target_case_state.py:530-538`；不改变这些入口。`cf_solver.py:383-385` 独立写 `auth.env`，不是本次 export/reload 契约的调用者。

`tests/test_validation_runner.py:657` 的已有回归覆盖 auth file 构造 session 与请求级显式 header 优先级（mock 请求）；`:524` 覆盖跨目标重定向拒绝；`:574` 的 loopback 回归覆盖只重放显式授权 session headers。本轮仅阅读这些测试，尚未执行。新增文件聚焦 export/reload 及真实 Shell 参数构造，不复制整套 runner 测试。

## 复现证据

`/tmp/ccst-audit-2026-10-02/results.json` 的 `auth_roundtrip` 记录：旧外部 Origin 导出前拒绝、重载后允许；显式凭据被重载改变；空会话导出后凭据复活。此次规划读取了已有结果，未重新执行审核或产品测试。临时结果不作为长期唯一证明，实施时以仓库内 regression 固化。

## 适用规范

- `.trellis/spec/backend/quality-guidelines.md`：认证来源隔离、owner 修复和 focused tests。
- `.trellis/spec/backend/error-handling.md`：边界输入错误不可静默吞掉。
- `.trellis/spec/backend/scope-context.md`：凭据不得因关系或环境残留自动跨资产转移。
- `.trellis/spec/backend/logging-guidelines.md`：凭据不进入通用日志或公开材料。
