# Autopilot 只负责自动化

2026-10-22，基线 `1c6fb2f981d69378cd1d8ece646f09bc64413b11`，checkout `ccst3/ccst`。
用户认可：参照上游的简单职责分工，Autopilot 负责自动推进，6k 负责调查；主入口约 4–6 KiB，
删去重复解释，同时核对连带读取总量。任务记录选项未回复，本轮直接完成，不创建或归档任务。

## 改动边界

- `commands/autopilot.md`：恢复、继续、执行写回、刷新四步循环，加简短的调用条件与结束规则。
  不重写业务理解、实验选择、知识方法、浏览器或报告细则。
- `skills/runtime-protocol.md#native-skill-loading`：集中原生 Skill 调用、完整正文复用、
  压缩后恢复与等待/清理例外。删除协议回指 Autopilot 的加载关系。
- `commands/checkpoint.md#global-review`：复核范围归现有提交命令；快照参数、失败恢复不变。
- `commands/autopilot-round.md`、`docs/architecture-contract.md`：仅更新上述两个责任引用。
- `.trellis/spec/backend/contracts/runtime-autopilot.md`：更新自动化入口契约与验收口径。

Round prepare/claim/heartbeat/correction/settle/cron 仍在 Round；普通模式仅处理已有 Round 的恢复。
Bootstrap 动态行、manifest、frontmatter、公共锚点、argv、证据与恢复义务保留。
没有新增 controller、状态层或必须加载的长手册；没有修改 Python 运行时、6k 方法或常驻规则。

## 验收与体量

```bash
python3 -B .trellis/workspace/Codex/research/10-22-autopilot-automation/check_automation.py
```

约 0.43 秒，结果见 [result.json](result.json)。复用之前 research 的纯 Markdown helper、
源码白名单与引用匹配式，不执行历史验收。检查真实纯参数解析器、manifest reader 和 lane
提取函数；验证全部示例、Round 默认、Auth/context、固定入口行、共享章节、42 个引用，
以及所有已跟踪原规则/src-hunter 材料与基线的原始字节一致。

| 静态读取集合 | 原字节 | 当前字节 |
| --- | ---: | ---: |
| 主入口 | 14,326 | 6,242 |
| 主入口 + Round + runtime-protocol + Checkpoint 全文 | 36,713 | 29,684 |
| 启动选定章节 + src-hunter + 短表 | 80,726 | 73,132 |
| 上述启动 + Action 执行所需合同 | 99,808 | 92,214 |
| 上述执行 + 耗尽检查/复盘/晋升合同 | 131,937 | 124,251 |
| CLAUDE 及其 13 个直接 imports（另列） | 140,852 | 140,852 |

主入口减少约 56.4%；相关四份全文合计减少约 19.1%。每个集合的具体文件/章节和字节在
result 中列出，按同一行为比较前后并复用已读章节。常驻另列，不能与重复来源简单叠加。
网络代理、具体漏洞方法、浏览器/其他 lane、委派和工具输出依选择展开，未计入这些选定集合；
变化文件集合已包含所有正文增量，避免把迁移后的增量隐藏起来。

首次自查将 CRLF 经过 `read_text()` 转换后与 Git 原始文本比较，误报一个方法变化。
核对原件字节完全一致后，改用 `read_bytes().decode()` 保留换行；产品材料未动。

## 限制

这些是明确列出的静态读取集合，不是宿主实际注入追踪，也不是 token、费用、时延或挖掘深度。
未读取、修改或运行项目 `tests/`，旧精确文案/形状断言尚未复核；未访问真实目标、调用
Claude/付费模型、联网、安装依赖或同步个人 runtime。6k 常驻体量的调整留待另项。

两位独立只读复核分别检查组合语义与接口/统计，均未发现实质问题：普通入口仅恢复已有
Round，Skill 加载无反向循环，claim/写回/heartbeat/刷新、报告后继续和结束清理保持；
新增的共享正文已纳入读取集合，没有借迁移隐藏新增成本。主线程最终审阅全部差异并运行
`git diff --check`，未扩大项目测试范围。

两处既有 Python 改动 `tools/autopilot_state.py`、`tools/surface_projection.py` 经原哈希保护，
未纳入本轮。
