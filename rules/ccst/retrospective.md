# 复盘与沉淀规则

复盘用于把一次 hunt、验证或目标切换中的经验沉淀回四层体系。它不是报告，也不是漏洞验证。
它的增强目标是把“总结”变成“分流决策”：每条经验必须落到目标层、知识库、Skill、Rules、`/remember` 或 `none`。

## 目的

重要会话结束时交代什么有效、什么无效、漏了什么、哪些线索与方法值得保留，以及 Skill/Rules 的缺口。

## 沉淀分流

| 内容类型 | 写入位置 |
|---|---|
| 只属于当前目标的线索 | 目标层 `lead`，见[写回合同](#写入目标层) |
| 当前目标下一步 | 目标层 `next`，见[写回合同](#写入目标层) |
| 当前目标无效方向 | 目标层 `dead-end`，见[写回合同](#写入目标层) |
| 会话交接摘要 | 目标层 `handoff`，见[写回合同](#写入目标层) |
| 多目标可复用思路 | `knowledge/cards/*.md` |
| 知识晋升判断 | `knowledge/promotion-rules.md` |
| Skill 执行顺序或判断方式问题 | `skills/*/SKILL.md` 或 `skills/runtime-protocol.md` |
| 红线、覆盖、上下文加载、验证标准问题 | `rules/*.md` |
| 已验证发现或成功模式 | `/remember` |

## 自动证据读取

读取步骤与 `RETROSPECTIVE DECISION` 模板见
[复盘命令](../../commands/retrospect.md#自动收集)及其[输出格式](../../commands/retrospect.md#输出格式)。

- Checkpoint 是只读快照；空的 `target_write_back` 列表和展示的 handoff 不是待执行写入。
  复用有效视图，只展开缺失的 owner/原件，不默认预拉全部状态、日志、响应或历史。
- 目标选择指针不代替 Store。缺库/缺 Finding ID 显式失败，合法空库可为空，旧 JSON 不作当前事实回退。
- 按选定 Finding 的 assessment/evidence/delivery/report 关系展开；validation summary 核对
  target/Finding，不能用全局 `findings/last-validate.json` 绑定另一发现。
- 有界 `find-gaps` 不是全部覆盖；按需展开，不为复盘固定执行 rebuild。

## 判断标准

### 写入目标层

当前目标的 Lead/Signal、条件反证、下一步和交接写入目标层；是否保存仍按下述唯一时机。

目标层写回时机唯一由
[`skills/runtime-protocol.md#cognitive-write-timing`](../../skills/runtime-protocol.md#cognitive-write-timing)
规定：有影响后续判断的稳定结论、反证、条件变化、路径决定，或暂停/换目标/compaction
需要续接时，保存必要增量及真实引用，不等用户另说“记住”。本规则只帮助分流内容，
不新增逐观察复盘或固定写回频率；执行事实和真实回执仍即时交给原 owner。
明确只读/预览时只展示建议，不写目标层或 campaign 工作文件。
完整命令示例、条件/重开要求、凭据引用、交接与失败恢复统一见
[`commands/target.md#交接与证据`](../../commands/target.md#交接与证据)。
先按 Shared Memory Continuity 核对当前事实与相关反证，再决定本次需要保留的增量。

### 写入知识库

多目标可复用的思路、高/低价值形态及其触发、验证和停止条件可形成候选；单站结论不当通用方法。
原生方法维护遵守 `rules/hunt-iter.md` 的准入、来源和主控审核；共享知识卡按
`knowledge/promotion-rules.md` 及现有发布审核处理，默认只输出候选，不自动发布。
候选指明目标卡、证据形态、价值、下一动作、停止条件与验证要求；完整模板见复盘命令。

### 修改 Skill

选择/顺序导致漏测，或知识调用、输出、写回不完整时，指出 `target skill`、证据、
缺陷类型（route / ordering / output / write-back / context-load）和 `proposed change`。
默认只提建议，不自动修改。

### 修改 Rules

红线、覆盖、加载、验证或报告标准存在缺口/冲突时，指出 `target rule`、触发证据、
为何属于规则问题及 `proposed change`。默认只提建议；用户明确授权的工程修复按授权执行。

### `/remember`

只有已验证发现、稳定成功模式或经过 `/validate` 的结论进入 `/remember`。
Lead、Signal、未验证假设、目标专属线索不进入 `/remember`。

## 禁止事项

- 不把未验证漏洞结论写成知识库事实。
- 不把目标专属敏感信息写入知识库。
- 不把真实凭证、cookie、token、个人数据或客户数据写入知识库。
- 不用复盘替代 `/validate`。
- 不自动删除或覆盖已有经验；修正通过原 owner 保留历史与依据。
- 不用“这次没发现”结束复盘，必须说明覆盖和剩余项。
- 不把目标层 dead end 直接晋升为全局规则，除非多个目标重复出现且有停止条件。
