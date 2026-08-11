# scripts 目录说明

`scripts/` 只保留少量仍被文档或测试引用的通用包装脚本。

当前保留：

- `full_hunt.sh`：旧式全流程 shell wrapper，仍有 auth 兼容测试保护
- `dork_runner.py`：通用 dork 辅助脚本

`full_hunt.sh` 与主 Recon 入口一致：Amass 默认关闭；需要时设置
`BBHUNT_ENABLE_AMASS=1`，quick 模式仍会跳过。

历史 round / campaign / 目标硬编码脚本已经归档到：

```text
archive/campaign-scripts/20260624T120400Z/
```

这些归档脚本不是 Claude CLI 主流程。默认使用：

```text
/autopilot -> /surface -> /hunt -> /validate -> /checkpoint or /report
```
