# 知识晋升规则

本文件定义哪些内容可以从目标记忆、hunt journal 或人工复盘中晋升到知识库层。

## 可以晋升

满足任一条件，可以考虑晋升：

- 同一模式在两个以上目标中重复出现
- 某个检查思路明显提高了有效 lead 命中率
- 某个方向被多次证明低价值，适合写入 dead end
- 某类技术栈、框架、产品形态有稳定攻击面特征
- 某个可复用经验或反例能帮助 Skills 层更好选择分支

## 晋升级别

- 普通通用知识：不新增 Skill。
- 实战发现的小缺口：补 `context_pack.py` 路由、知识卡、hypothesis seeds 和回归测试。
- 重复出现的高价值模式：优先升级成知识卡增强。
- 稀缺且可迁移的新打法：才进入 Skill 候选。
- 不好用、冗余、重复或过拟合单个 lab/目标的内容：直接丢弃。

## 能力落位规则

从靶场、真实授权测试、公开报告、CTF 非预期解或人工复盘里吸收新能力时，
先判断它应该进入哪一层，不要把经验、判断、路由、执行动作和结果记录混进同一个
Skill 或知识卡。

```text
经验进知识库
判断进 rubric
路由进 context_pack
下一步进 checkpoint
重复动作进工具
结果进 ledger
```

| 新内容类型 | 应落位置 | 示例 |
|---|---|---|
| 稀缺经验、技巧、bypass、反例、误判模式 | `knowledge/cards/` 或 `skills/security-arsenal/references/` | `q='` 无差异但闭合括号注释改变结果集；列表接口弱于详情接口 |
| 证据门槛、Candidate 判断、降级条件 | `tools/evidence_rubric.py` + `tests/test_evidence_rubric.py` | 匿名敏感配置泄露不需要无意义 actor diff；DNS-only SSRF 不能 candidate-ready |
| 触发词、上下文路由、知识卡选择 | `tools/context_pack.py` + `tests/test_context_pack.py` | `application-configuration` + unauth 路由到 auth-access；search/filter/sort 路由到 SQLi |
| 发现后的下一步动作、replay 草案、queue 优先级 | `tools/checkpoint.py` + `tests/test_checkpoint.py` | IDOR 缺 actor diff 时生成 A/B replay skeleton；已验证 finding 转 `/validate` |
| 稳定重复的 replay、diff、证据保存、格式转换 | `tools/` 下的执行器 + 对应测试 | baseline/variant 请求、响应 diff、MCP artifact 导入、validation runner |
| 目标专属结果、验证状态、actor matrix、raw evidence 指针 | `memory/evidence/`、`evidence/`、`findings/`、target memory | `tested_finding`、`dead_end`、raw request/response、ledger entry |
| 报告表达、CVSS 默认、提交门控 | `skills/report-writing/`、`tools/validate.py`、`rules/reporting.md` | 影响描述、保守 CVSS、预提交 checklist |

落位前必须问：

```text
1. 这是模型可能不知道的技巧/经验吗？
2. 这是判断标准或证据门槛吗？
3. 这是触发路由或上下文选择吗？
4. 这是可以稳定重复执行的动作吗？
5. 这是某个目标的验证结果或报告表达吗？
```

如果答案是“稳定重复执行的动作”，优先做工具，而不是把步骤写成长 Skill；
如果答案只是“技巧/经验/绕过思路”，优先写知识卡或按需 reference，不要让工具
默认执行。

工具化不是限制 AI，而是把重复、机械、易漂移的 replay / diff / 证据保存 /
ledger 写入交给稳定执行层。AI 的优势必须保留在：

- 从弱信号联想到高价值攻击面和替代入口。
- 选择当前最值得验证的假设，而不是顺序跑清单。
- 根据响应差异解释真实边界、误判来源和下一跳攻击链。
- 在知识卡、source/JS/browser、历史 ledger 和当前目标语义之间组合思路。
- 决定何时升级、降级、停止、换 lane 或写回可复用经验。
- 发现工具没有覆盖的新验证形态，并把稳定部分再晋升到工具层。

因此新增工具必须输出 AI 可继续推理的结构化证据，而不是只输出“通过/失败”。
最少应包含：baseline、variant、差异摘要、证据路径、风险/红线状态、下一步建议
和停止条件。不要把工具设计成固定扫描清单，也不要让工具结论替代 Claude 对上下文、
业务影响和链路可能性的判断。

## 不应晋升

以下内容不要进入知识库：

- 只属于单个目标的临时线索
- 未经验证的漏洞结论
- 真实 token、cookie、密钥、个人数据或客户数据
- 大段扫描输出、HTML、响应包
- 明确属于检查层的红线规则
- 会诱导无差别 payload spray 的内容

## 晋升格式

晋升时优先写成知识卡，而不是长文。

每条经验至少包含：

```text
Evidence pattern: 触发它的证据形态
Why it matters: 为什么值得测
Thought branches: 可以如何扩展思路
Technique / payload / bypass family: 可复用技巧或 payload/bypass 家族
Checklist gap: 容易漏掉的检查点
Next action: 最小验证动作
Stop condition: 何时停止
Validation requirement: 进入 Candidate 前需要什么证据
False positives / dead ends: 常见误判或死路
Promote to Skill / Queue when: 什么时候交给 Skill 或 action queue
```

## 从目标层晋升

目标层字段的处理建议：

| 目标层字段 | 晋升目标 |
|---|---|
| `active_leads` | 只有多个目标复现时才晋升为知识卡 |
| `dead_ends` | 可晋升到 `knowledge/cards/dead-ends.md` |
| `useful_patterns` | 可晋升到对应漏洞/攻击面知识卡 |
| `session_handoffs` | 不直接晋升，只作为复盘素材 |

## 复核要求

晋升前检查：

- 是否去除了目标专属敏感信息
- 是否能被其他目标复用
- 是否有明确停止条件
- 是否和 `rules/` 冲突
- 是否能帮助 Skills 层做更好的分支选择

正式卡晋升后的治理不写回 candidate lifecycle：

- `knowledge/candidates/lifecycle.jsonl` 只回答候选是否 pending/reviewed/promoted。
- `knowledge/governance/events.jsonl` 只回答正式卡是否 active、被替代/退休/恢复，以及
  maturity 是否有 reviewer、model profile 和可复跑证据。
- `tested` / `proven` 必须通过 `tools/knowledge_lifecycle.py review` 记录证据；没有证据的
  历史声明保守保持或降为 `draft`，不能用 `legacy` 绕过门禁。
