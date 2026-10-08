# 认证环境导出与重载隔离

## 目标

保证一次已选定的 AuthSession 导出到子进程环境后，不继承其他会话的目标、Origin 或原始凭据；匿名会话保持匿名，Python 与 Shell 重载同一份导出认证上下文。

## 背景与证据

2026-10-02 项目审核 F01（P1）已离线复现：`tools/auth_session.py:380-404` 对非空会话仅 update overlay，未清除旧 `BBHUNT_AUTH_ORIGINS`；`from_env()` 在 `:185-210` 又读取原始 header/cookie/bearer/api-key 输入。结果是旧 Origin 被重新允许、旧 bearer 覆盖显式新凭据、空会话导出后旧凭据复活。实际消费者包括 `tools/hunt.py:132-143,1456-1457`；Shell URL 检查通过 `tools/_auth_helper.sh:87-100` 重载同一环境。

用户在审核建议后回复 `go`，本任务仅承接优先修复 F01；其余审核发现和未提交 R17 独立保留。

## 需求

- R1：导出必须以当前会话为认证来源，替换目标环境中既有认证上下文和原始认证输入，不能部分叠加旧会话。
- R2：非空会话导出后重载保留本次 headers、session ID、目标绑定和显式 Origin；本次未允许的旧 Origin 不因环境残留变成允许。
- R3：空会话导出后重载为空；有凭据但无目标绑定的会话不能继承旧目标或旧 Origin。
- R4：不改变初次 CLI/文件/环境来源选择与显式 `--auth-from-env` 的既有契约；不修改 URL 匹配、Scope、重定向和请求执行边界。
- R5：不清除无关环境变量、不修改原会话、不打印凭据、不增加依赖、配置或新的认证框架；所有实际导出调用者遵循同一 owner 契约。

## 验收标准

- AC1 / R1-R2：环境含旧导出值、旧 Origin 和原始 header/cookie/bearer/api-key（包括无效旧值）时，新会话导出并重载仅含当前选定凭据与允许范围。
- AC2 / R2：显式新 Origin 和带 scheme/port 的目标绑定往返保留；旧 Origin 的 `headers_for_url()` 结果为空；session ID 与当前会话一致。
- AC3 / R3：空会话、有凭据但未绑定目标的会话均不会复活旧凭据或旧绑定；目标环境从空字典开始同样正常。
- AC4 / R4-R5：无关环境值和 AuthSession 本身不变；重复导出幂等；通过实际 Python/Shell 重载入口验证，而非只测试构造出的 overlay。
- AC5 / R4：已有来源选择、目标不匹配和认证重定向测试不退化；测试只使用临时目录、synthetic credentials 和本地子进程，不访问目标网络。

## 范围外

不修本轮其余审核发现，不提交或混改 R17；不重建 AuthSession，不改变初始来源优先级，不新增环境协议版本或配置，不修改真实认证材料/Store、安装依赖、同步全局 runtime 或运行真实模型/目标实验。
