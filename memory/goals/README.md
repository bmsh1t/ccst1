# 目标记忆层

这个目录保存 Claude CLI 的目标记忆。

它刻意和下面这些目录分开：

- `hunt-memory/`：持久化 hunt profile、journal 和已学习模式
- `findings/`：结构化漏洞证据和验证状态
- `state/`：运行时/session 面包屑
- `knowledge/`：可复用思路材料和知识卡片
- `rules/`：红线、验证 gate 和报告 gate

## 文件

```text
memory/goals/
  active.json
  targets/
    <target>.json
  sessions/
    <timestamp>-<target>.md
```

## 职责

目标记忆保存：

- 活跃目标
- 当前模式和阶段
- 当前假设
- 活跃线索
- 下一步动作
- 已证伪或低价值方向
- 目标特定的有效模式
- 会话交接摘要

目标记忆不保存：

- payload 集合
- 全局方法论
- 红线规则
- 大体积扫描日志
- 最终报告证据

## 生命周期

1. 使用 `python3 tools/target_memory.py set <target>` 设置或切换目标。
2. 在 hunt 过程中追加线索和下一步。
3. 当某个方向被证伪时记录 dead end，避免下次重复浪费时间。
4. 在上下文过长前写 handoff。
5. 对可复用经验做提升：不要只留在目标文件里，应沉淀到知识库层。
