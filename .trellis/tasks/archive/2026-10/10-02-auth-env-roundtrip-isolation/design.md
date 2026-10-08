# 认证环境导出与重载隔离：设计

## Owner 与数据流

沿用 `AuthSession`，不新增状态 owner。初次 CLI/文件/环境输入选择 → 会话绑定 → `export_to_env()` → Python `from_env()` 或 Shell helper。`hunt.py` 的父环境导出与 `_runtime_child_env()` 共用这一出口；调用关系见 `research/auth-env-boundary.md`。

## 最小修改

只修改 `tools/auth_session.py::AuthSession.export_to_env()` 的替换语义：

1. 先调用现有 `env_overlay()`，生成当前会话的导出内容。
2. 无条件从目标 mapping 删除八个既有认证键：`ENV_HEADERS`、`ENV_SESSION_ID`、`ENV_TARGET`、`ENV_ORIGINS`、`ENV_HEADER_IN`、`ENV_COOKIE`、`ENV_BEARER`、`ENV_API_KEY`，缺失键忽略。
3. 写入 overlay；空 overlay 同样执行，结果就是清空认证。

复用既有常量，不做前缀批量删除，不新增 registry、协议标记、配置或依赖。显式传入空字典仍修改该字典，只有 `env is None` 才使用 `os.environ`。先计算再删除保留现有的序列化失败前不修改环境的顺序；不增加异常吞噬或自定义 mapping 事务层。

## 行为契约

| 当前会话 | 导出并重载后的行为 |
|---|---|
| 有凭据且绑定目标 | headers、session ID、scheme/port 绑定及显式 Origin 保留；旧原始输入和旧 Origin 清除 |
| 有凭据、未绑定目标且无显式 Origin | 保留当前凭据，不继承旧绑定；URL 认证仍按既有规则拒绝 |
| 无凭据，包括仍带目标元数据的空会话 | 八个认证键均不存在，重载匿名，不复活旧凭据 |
| 已污染或空环境 | 结果只由当前会话决定，无关环境值和原会话不变，重复导出幂等 |

## 兼容与边界

`from_env()` 仍接受原始认证输入；初次来源优先级、`--auth-from-env`、文件解析和显式请求 header 优先级不变。移除原始环境键发生在选定会话导出之后，不改变选定之前的合并规则。`env_overlay()` 仍是纯导出片段，完整替换由 `export_to_env()` 负责。

不修改 Scope、Origin 匹配、重定向、调用者或 Shell helper。Scope 对象不是本次环境协议的新字段。`cf_solver.py` 独立生成 `auth.env`，任意 shell sourcing 不属于本修复覆盖面。

在 `tests/test_auth_session.py` 用公开接口回归污染环境往返，并用实际 Bash helper 验证新目标可携带当前凭据、旧 Origin 不可携带凭据。补充现有质量规范的认证条款，不修改 R17 已脏的 runtime 契约。

## 发布与回退

无需数据迁移或 runtime 同步。修改仅对后续调用导出生效，不修补已经启动的子进程。若需回退，撤销本任务的 owner、测试和规范改动，不恢复整个工作区；回退会重新暴露旧环境污染问题。
