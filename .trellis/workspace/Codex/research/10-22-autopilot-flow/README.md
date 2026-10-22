# Autopilot 调查流程整理验收

2026-10-22，基线 `d9d215a70b2dbafe5844a1e50d79290b81825a51`，分支
`refactor/10-11-capability-architecture`，实现 checkout 为 `ccst3/ccst`。
用户认为二开 Autopilot 不如上游清晰，同意恢复调查主线；本轮范围为 Claude CLI 文档。

## 改动

- `commands/autopilot.md` 增加用途、参数与四个示例，先呈现五步调查流程：恢复工作；
  理解业务并选择问题；执行、登记与刷新；证据成熟后验证发布；继续、转向或有理由地结束。
  启动恢复、Skill 加载、执行规则、动作后刷新和结束细节在后面的对应章节展开。
- 正常流程解释 lane，避免未解释的 A/B/C；Q7 的内部交付条件移到执行规则。
  已确认发现及时保存、发布后继续调查，保持原有含义。
- 修正原入口笼统禁止失败重试与现有 lane 合同的冲突：保留浏览器一次瞬时故障重试，
  登记失败只重试登记。没有扩大 Action claim 重试或未知效果请求重放。
- `.trellis/spec/backend/contracts/runtime-autopilot.md` 将旧的 11 KiB 合计预算替换为
  可读流程与接口保留契约；调查方法仍由 src-hunter 及其现有模块提供。

主命令由 10,176 增至 14,326 字节（增加 4,150，约 40.8%）；完整 Shared Automation
为 11,628 字节。本轮优先解释清楚流程，不能据此宣称 token、费用、时延或调查深度改善。

## 保留的接口和规则

frontmatter、精确 Bootstrap 执行行和 critical manifest 保持原文。Round 仍读取完整
Shared Automation H2；`shared-automation`、`investigation-skill`、`state-consumption-loop`
锚点保留。调查方法、Round、runtime-protocol、lane 实现不在本轮修改范围。

保留 Scope/Auth/context、执行前 claim、报告身份绑定、登记/resolve 后写 terminal heartbeat
再刷新、未知效果恢复、全局审阅与 Closure、预算结束清理和一次性 Memory recommendations。
没有增加独立控制器、默认专家委派或自动外部提交。

## 验证

```bash
python3 -B .trellis/workspace/Codex/research/10-22-autopilot-flow/check_flow_contracts.py
```

最终运行约 0.27 秒，结果见 [result.json](result.json)。纯 Markdown helper 复用同级
`10-22-autopilot-docs/check_document_contracts.py`，不运行那一轮验收。

- 临时源码副本验证 frontmatter、Bootstrap、manifest、完整共享章节和入站锚点；
  21 个唯一 checkout 引用及 5 个内部链接有效。
- 比较 Round、runtime-protocol、lane 文档、CLAUDE 导入声明及 src-hunter Markdown 与基线；
  没有比较 CLAUDE 引入的全部规则正文，不将这项检查称为完整 6k 验证。
- 使用真实 manifest reader 和从源码提取的 lane reader，验证完整 lane section 提取；
  controller command 引用仍按原设计不内联。
- 真实纯参数解析器接受四个示例、默认 paranoid、quick/deep 组合、1–32 的 lane 上限、
  Round 默认 normal/deep/16 和 auth/context 参数；拒绝无效上限与冲突模式。
- 两位只读探子分别复核语义保留与可读性，未发现阻断；主线程落实三条小修后重新运行
  上述定点检查。提交前审阅 diff 并通过 `git diff --check`。

## 限制与状态

未读取、修改或运行项目 `tests/`，旧的精确文案/字数断言未复核。未访问真实目标、
同步宿主 runtime、联网、安装依赖或调用 Claude/付费模型；静态验收不证明实际调用效果。

任务创建的可选确认未收到回复，本轮未新建任务或修改旧任务状态。已有的
`tools/autopilot_state.py`、`tools/surface_projection.py` 改动与本轮开始时的哈希一致，
不纳入本轮提交。不归档旧任务，不 push。
