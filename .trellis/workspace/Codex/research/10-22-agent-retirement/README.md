# 五个 agent 退役验收

2026-10-22，checkout `ccst3/ccst`，分支 `refactor/10-11-capability-architecture`，
基线 `1a8a95d0589463f0a3aebff037034bbc2b5e0953`。用户授权先清理五个重复入口。

删除 `recon-agent`、`recon-ranker`、`chain-builder`、`web3-auditor`、`token-auditor`。
保留 `autopilot`、`validator`、`report-writer`、`disclosed-researcher`、`credential-hunter`。
原有 37 个 commands、完整方法模块、6k 知识正文和通用子代理委派能力保留。

README、Autopilot、campaign 与现行规范改用 commands/modules 和通用委派。
原 Ranker 独有的只读边界移入 src-hunter 的共享 handoff：只审现有目标证据，
不发目标请求、不采集/刷新、不初始化/导入/修复 Store；unknown 与 owner 建议交回父会话。
Skill description 未改。Bootstrap 的兼容字段 `enrichment_hints` 保留为空，
不再透传历史 Ranker 提示。安装器和持久化 owner 无改动。

## 验收

```bash
python3 -B .trellis/workspace/Codex/research/10-22-agent-retirement/check_agent_retirement.py
```

[脚本](check_agent_retirement.py) 在临时目录复制基线与当前 tracked 源码，
不复制项目 tests 或目标数据。真实 `runtime_doctor` 从临时源码导入；
所有 source/runtime 根显式指向临时目录。[结果](result.json)：passed，约 1.05 秒。

- 五个剩余 agents、除 Autopilot 外的 commands 和除主 Skill 外的全部 Skill 资源
  与基线逐字节一致。主 Skill 只新增共享只读段落，frontmatter 与原正文保留；
  CLAUDE 与除 campaign 接线外的 rules 不变，critical manifest 相同且有效。
- 实际 compact 函数通过 AST 提取，覆盖空提示、历史 Ranker 与缓存工具提示；
  除 `enrichment_hints` 外与基线输出一致，保持 owner、Surface 原 URL/续页、
  记忆绑定和真实 lane 正文。仅 next_step 文案使用 stub，不验收状态获取过程。
- 用现有 sync owner 安装旧版 10 个 agents，再做普通同步：旧五副本仍受管，
  removed 为空。随后 prune 精确移除旧五副本；剩余 5 agents、37 commands、
  62 Skill 资源及回执内容匹配当前源码。未受管 extra 的 bytes/mtime 保留。
- 修改旧 recon-agent，并让另一个 command 有待同步变化：整批 rejected，
  copied/removed 为空，所有 runtime payload、receipt bytes/mtime 原样保留。
- 活动引用检索与 `git diff --check` 通过。一次性 default 只读探子独立复核
  验收断言和其他安装/配置接线，没有发现阻断问题；未重复运行验收。

## 实际安装与限制

本轮只清理源码，真实宿主 runtime 未同步。已安装的旧副本需使用现有
`runtime_doctor.py --sync --prune --kind commands,agents,skills`，并显式指定
要更新的 `--repo-root` 与 `--runtime-root`。只有 receipt-owned 且未修改的
旧文件可删除；修改过的旧文件会拒绝整批同步，用户自有文件保留。

未读取/运行项目 tests，未接触真实目标、正式知识审核或个人 runtime；
无网络、安装依赖、付费模型验收、push 或旧任务归档。临时文件同步与静态正文保全
不证明宿主缓存、实际模型调查能力、压缩后恢复或模型成本改善。
任务创建问题未收到答复，本轮没有创建任务或变更旧任务状态。
