# scripts 目录说明

当前没有受支持的运行时入口保留在 `scripts/`。旧式全流程入口和 dork
辅助脚本已经移出主代码路径；统一使用 `tools/hunt.py`、
`tools/recon_engine.sh` 及对应的 Claude 命令。

历史 round / campaign / 目标硬编码脚本归档在：

```text
archive/campaign-scripts/20260624T120400Z/
```

这些归档脚本不是 Claude CLI 主流程。默认使用：

```text
/autopilot -> /surface -> /hunt -> /validate -> /checkpoint or /report
```
