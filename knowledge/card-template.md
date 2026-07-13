# 知识卡模板 v2

复制本模板创建新的知识卡。文件名使用小写短横线，例如 `oauth-sso.md`。

知识库是经验压缩库，不只是联想种子。知识卡可以沉淀思路、技巧家族、
payload 家族、WAF/解析绕过、补充 checklist、最小验证、误判/死路和可复用
经验，但不能接管 Skill 的流程决策。

新卡优先使用 v2 结构：front matter metadata + Quick Recall + 正文结构 +
深度附录引用。旧卡可以逐步迁移，不需要一次性重写。

```md
---
id: short-card-id
type: technique-card
related_skills:
  - web2-vuln-classes
trigger_tags:
  - example-tag
risk: low
maturity: draft
load_priority: medium
deep_refs:
  - knowledge/payloads/example.md
source_refs: []
---

# 知识卡标题

## Quick Recall

- 10-20 行内说清本卡最重要的触发信号、核心思路、最小验证和停止条件。
- Quick Recall 用于 context-pack / Skill 快速回忆；不要放大段 payload。

## 能力定位

- 本卡解决什么问题，给哪个 Skill 补充什么能力。
- 说明它是供料层：提供思路、知识、技巧和补漏点，不替代 Skill 指挥。

## 触发信号

- URL、参数、响应、源码、JS、浏览器状态、错误信息、版本、组件、业务流程等具体证据。
- 哪些信号说明应该读取本卡。

## 思路分支

- 从哪些角度展开攻击面或验证路径。
- 如何从当前证据横向扩展、纵向深入、链到更高影响。

## 技巧家族 / Payload 家族

- 可复用的技巧类别、payload 形态、编码/解析差异、WAF 绕过思路、协议/框架特性等。
- 示例必须是启发式候选，不是固定字典或穷尽清单。
- 大型 payload、绕过矩阵、工具参数和长案例放到 `knowledge/payloads/` 或其他深度附录，本节只写路由和代表形态。

## 补充 Checklist

- 当前 Skill 容易漏掉的输入面、边界、角色、状态、组件、二阶链路或证据点。
- Checklist 只用于防漏，不决定固定执行顺序。

## 最小验证

- 低风险、可复现、单变量、可记录证据的验证方式。
- 需要哪些 baseline、对照组、角色/对象/状态差异或可达性证据。

## 常见误判 / 死路

- 哪些信号容易误判。
- 什么情况下应该降级为 Signal、dead-end、blocked 或转其他 Skill。

## 关联 Skills

- `skill-name`

## 晋升到 Skill / Queue 的条件

- 什么时候只是知识启发。
- 什么时候应交给当前 Skill 决策。
- 什么时候应写入 `tools/action_queue.py` 成为可执行 action。

## 可晋升经验

- 哪些目标层经验可以沉淀回本卡。
```

## Metadata 字段

| 字段 | 含义 |
|---|---|
| `id` | 与文件名一致的稳定 ID |
| `type` | `technique-card` / `payload-pack` / `checklist-card` / `dead-end-card` / `product-card` / `workflow-card` |
| `related_skills` | 推荐读取本卡的 Skills |
| `trigger_tags` | context-pack / Skill 路由可使用的证据标签 |
| `risk` | `low` / `medium` / `high`，指验证动作风险，不是漏洞严重性 |
| `maturity` | `draft` / `tested` / `proven` |
| `load_priority` | `low` / `medium` / `high` |
| `deep_refs` | payload、playbook、长案例或项目内附录路径；不要指向本机绝对路径或未蒸馏原文 |
| `source_refs` | 结构化、按需查询的来源；v1 使用 `corpus-report` + `hackerone-disclosed-reports` + 字符串 ID |
| `updated` | 可选，最后人工维护日期 |

只有存在已经核对的本地案例指针时，才把空列表替换为对象列表：

```yaml
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "<non-zero-decimal-report-id>"
```

## 知识类型

- `technique-card`：技巧、手法、测试思路。
- `payload-pack`：payload 家族和变体，通常放在 `knowledge/payloads/`。
- `checklist-card`：补漏项和覆盖提醒。
- `dead-end-card`：误判、低价值方向和停止条件。
- `product-card`：特定组件、框架、产品或版本族经验。
- `workflow-card`：流程组织、验证顺序、复盘和协作经验。

## 编写规则

- 写思路、技巧家族、payload 家族和验证模型，不写无上下文的大段 payload dump。
- 写触发信号，不写空泛教程。
- 写补充 checklist，但不要把 checklist 写成固定流程或固定顺序。
- 写最小验证和停止/降级条件，避免知识库只会扩散不会收敛。
- 写常见误判，确保输出能回到验证 gate。
- 示例可以具体，例如参数名、header、payload 形态、绕过类别；但必须说明它们是候选形态，不是固定字典。
- front matter 和 Quick Recall 要保持短小，便于 context-pack 快速加载。
- 深度 payload / bypass / 长案例使用 `deep_refs` 按需加载，避免污染常规上下文。
- 外部材料必须先蒸馏成触发条件、证据门槛、停止条件或项目内 payload/playbook；
  不在知识卡里直接挂载本机绝对路径、整篇原文或一次性题解。
- `source_refs` 是 active 卡的唯一案例来源权威；不要再添加 `source_report_ids` Markdown footer。
- 没有真实来源时保持 `source_refs: []`，不得用示例数字、猜测 ID 或模型记忆填充来源。
- active 卡的正式生命周期由 `knowledge/governance/events.jsonl` 维护；`maturity` 只表示
  证据强度，不能代替 `reviewed/retired/superseded/restored` 状态。
- 不保存真实凭证、个人数据、客户数据或未经脱敏的响应正文。

## 提交前质量门

新增或修改 card、payload pack、playbook 后，在仓库根目录运行：

```bash
python3 tools/knowledge_audit.py
```

必须修复所有 `error`。没有 frontmatter 的旧 card 会暂时产生 `warning`，可按能力演进
逐张迁移；`--strict` 用于迁移阶段把 warning 也作为失败条件。不要为了通过审计添加
固定字数、代码块或与当前路由无关的工具映射。
