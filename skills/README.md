# Skills 层

Skills 层负责流程控制：根据当前目标、阶段和证据，选择执行路径、调用知识库、执行检查层规则，并把结果写回目标层。

## 四层顺序

```text
目标层 -> Skills 层 -> 知识库层 -> 检查层 -> 执行与写回
```

含义：

- 目标层：确认当前目标、阶段、假设和已有线索
- Skills 层：决定怎么做、用哪个工作流和工具
- 知识库层：由当前 Skill 按需调用，用于补充思路和案例
- 检查层：执行前过滤红线，结束前审计覆盖基线
- 写回：把 lead、next、dead-end、handoff 和可复用经验沉淀回对应层

## 核心协议

完整协议见：

```text
skills/runtime-protocol.md
```

核心 Skills 必须遵守该协议：

- `bug-bounty`
- `bb-methodology`
- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`

## 设计原则

- Skill 是主流程控制器，不是知识库。
- 知识库只在当前 Skill 需要发散思路时加载。
- 红线优先级高于所有 Skill。
- 覆盖基线用于防止过早收工，不要求无脑全测。
- 结果必须写回目标层，否则下次上下文无法续接。
