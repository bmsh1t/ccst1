# scripts 目录说明

当前没有受支持的运行时入口保留在 `scripts/`。旧式全流程入口和 dork
辅助脚本已经移出主代码路径；统一使用 `tools/hunt.py`、
`tools/recon_engine.sh` 及对应的 Claude 命令。

历史 round / campaign / 目标硬编码脚本归档在：

```text
archive/campaign-scripts/20260624T120400Z/
```

这些归档脚本不是 Claude CLI 主流程。当前入口按需要选择：

- 自动继续调查：[自动执行合同](../commands/autopilot.md#shared-automation)。新空目标
  默认 Recon；已有可用材料可直接调查，独立工作可并行，报告发布后继续选择下一问题。
- 手动调查：[入口说明](../README.md#how-it-works) 与 [工具索引](../docs/tool-index.md)。
  `/recon`、`/hunt`、`/validate`、`/report` 按当前证据使用。
- 显式有界、可调度调用：[`/autopilot-round`](../commands/autopilot-round.md)。
