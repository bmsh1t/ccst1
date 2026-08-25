# Skills 层

Skills 是按需加载的执行契约。Claude Code CLI 主会话根据当前目标、阶段和证据保留路线选择权，Skill 提供所选路径的输入、观察、检查和写回协议。

## 四层顺序

```text
目标层 -> Skills 层 -> 知识库层 -> 检查层 -> 执行与写回
```

含义：

- 目标层：确认当前目标、阶段、假设和已有线索
- Skills 层：为主会话选定的路径提供工作流和工具契约
- 知识库层：按当前证据按需读取，用于回忆、联想、扩散和变形思路
- 检查层：执行前过滤红线，结束前审计覆盖基线
- 写回：把 lead、next、dead-end、handoff 和可复用经验沉淀回对应层

## 共享协议

完整协议见：

```text
skills/runtime-protocol.md
```

当前主要决策/执行 Skill 复用该协议：

- `bug-bounty`
- `bb-methodology`
- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`

## 设计原则

- Skill 是执行契约，不是主流程控制器，也不是知识库。
- Claude 主会话选择路径并决定取舍；Skill 指定该路径的输入、工具和收敛条件，知识库只提供候选思路。
- 知识库只在当前 Skill 需要回忆、联想、扩散或变形思路时加载。
- 红线优先级高于所有 Skill。
- 覆盖基线用于防止过早收工，不要求无脑全测。
- 结果必须写回目标层，否则下次上下文无法续接。
