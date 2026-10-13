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
- 实战发现的小缺口：补知识卡、Skill 方法或判断规则；机械执行缺口才补工具与回归测试。
- 重复出现的高价值模式：优先升级成知识卡增强。
- 稀缺且可迁移的新打法：才进入 Skill 候选。
- 不好用、冗余、重复或过拟合单个 lab/目标的内容：直接丢弃。

## 能力落位规则

从靶场、真实授权测试、公开报告、CTF 非预期解或人工复盘里吸收新能力时，
先判断它应该进入哪一层，不要把经验、判断、路由、执行动作和结果记录混进同一个
Skill 或知识卡。

```text
经验进知识库
判断进 Skills / rules，由 AI 应用
知识发现进 Context Pack 目录，选择由 AI 完成
下一步由 AI 显式写入 Action Queue
重复动作进工具
结果经 Store observation / assessment 登记
```

| 新内容类型 | 应落位置 | 示例 |
|---|---|---|
| 稀缺项目经验、边界思路、反例、误判模式 | `knowledge/cards/` | 记录目标无关、可复用且能改变证据判断的边界差异 |
| 证据门槛、Candidate 判断、降级条件 | `skills/`、`rules/`、知识卡 | AI 根据原始证据判断边界与影响；工具校验提交材料与身份绑定 |
| 上下文路由、知识卡选择 | `skills/runtime-protocol.md`、`knowledge/capabilities.yaml` | Context Pack 提供目录和事实；AI 按信息缺口选择，不新增触发词自动选路 |
| 发现后的下一步动作、replay 草案、queue 优先级 | AI 判断 + `tools/action_queue.py` 显式 add/claim/resolve | AI 选择角色对照或待验证 Candidate，Checkpoint 只读展示已保存工作 |
| 稳定重复的 replay、diff、证据保存、格式转换 | `tools/` 下的执行器 + 对应测试 | baseline/variant 请求、响应 diff、MCP artifact 导入、validation runner |
| 目标专属结果、验证状态、actor matrix、raw evidence 指针 | TargetStore observation/assessment/Case 与外部 raw artifact | 保存执行、裁决和证据引用；target memory 只保存条件化经验与意图 |
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
Store 登记交给稳定执行层。AI 的优势必须保留在：

- 从弱信号联想到高价值攻击面和替代入口。
- 选择当前最值得验证的假设，而不是顺序跑清单。
- 根据响应差异解释真实边界、误判来源和下一跳攻击链。
- 在知识卡、source/JS/browser、历史 ledger 和当前目标语义之间组合思路。
- 决定何时升级、降级、停止、换 lane 或写回可复用经验。
- 发现工具没有覆盖的新验证形态，并把稳定部分再晋升到工具层。

因此新增工具必须输出 AI 可继续推理的结构化证据，而不是只输出“通过/失败”。
最少应包含：baseline、variant、差异摘要、证据路径、风险/红线状态、执行状态与错误；AI 负责下一步
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

晋升按完整判断单元组织；短摘要不能替代动作/状态依赖、成功证据、反例、停止与重开正文。

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

### 跨目标召回边界

只经显式内容审核、晋升和唯一 registry 登记的正文进入共享召回。未审草稿、候选索引、
他目标私有材料不能因为有 recall 标签或建立了索引就晋升。必要旧证据门迁移不算新增知识，
不因某个模型会答而删除；旧卡仍按证据、来源和适用条件复核。

## 审核回执

`knowledge/candidates/SLUG.review.json` 与草稿同目录，`knowledge_promote.py --id SLUG`
在任何 digest/正文/registry 写入前校验。字段：

- `schema_version: 1`、`card_id`、`candidate_sha256`（完整草稿字节 SHA-256）、`decision: accept`。
- 非空 `reviewer`、`reviewed_at`、`rationale`、`transferability`，注明人工判断与真实差分。
- `intake_kind`：`new-method`、`existing-contract-migration`、`existing-knowledge-review`。
- 后两者必须有 `existing_source`；只适用于有可核对旧正文的维护，不能拿新组合冒充迁移。
- 新增必须有 `three_questions` 对象：`model_seen`、`inferable_from_evidence`、`real_cost_delta`
  的整单元判断原文；`blind_answer` 对象包含 `verdict: incremental`、`model`、`configuration`、
  `criteria`、`increment`，以及 `question`、`allowed_material`、`response` 三个 `{file, sha256}`。
  文件相对 candidates，必须实际存在、哈希匹配且不是待评卡。原答/必要现场材料事先脱敏，
  不在审核目录复制私有响应。机器只能校验绑定，盲态、预登记、内容真值及许可仍由审核人负责。
- 无模型调用批准记未运行，保留草稿；不能制作虚构回执。答不稳不是 `incremental` 结论。
- 晋升正文 `maturity` 必须经证据复核为 `tested/proven`，不能仅因 audit 通过改 maturity。
- 保留回执及原答；registry 仍为唯一发布真源。内容改变会使旧哈希失效；失败不变成可召回知识。

可选域索引只能按需指向唯一完整正文；case-router 固定 `load: on-demand`。
索引创建不改变审核状态。方法撤回/替换后同步 registry 与内容绑定，使派生索引失效。


晋升以同一份候选字节快照完成审核绑定、解析和引用迁移；成功回执同时返回
`published_sha256` 与 `replaced_refs`，区分已审草稿和机械转写后的发布正文。
候选原文保留到 strict audit 和最终目录校验完成才删除。任一失败撤销本次登记、正文及
本次新建 digest；既有不同内容的 digest 拒绝覆盖。晋升进程在知识目录锁内串行执行。
回滚只清理仍与本次发布字节相同的文件；并发修改保留并报告 `recovery conflict`，
需要按诊断核对当前文件后再重试，不能用旧快照强行覆盖。此约束不承诺多文件崩溃事务。

### 发布字节审核与既有知识复审

晋升在 registry 的 `review_receipt` 绑定不可覆盖的
`knowledge/reviews/ID/PUBLISHED_SHA256-REVIEW_SHA256.json`。回执保留草稿/发布 hash、
机械引用转写映射、审核原文和原审核文件绑定。召回只通过 `knowledge_review.read_published_review`
读取：正文、审核原件/盲答依据变化或退役均使其不再可用；索引 source binding 也随之失效。
新增回执进入同次发布补偿范围；不会在 audit 失败后留下已审共享候选。

旧登记卡不能自动补审。对当前正文逐项复核后，将其完整字节 hash 作为 `candidate_sha256`，
用 `intake_kind: existing-knowledge-review` 保存新的审核文件，再显式执行：

```bash
python3 tools/knowledge_promote.py --id ID --review-existing \
  --review-file knowledge/candidates/ID.review.json --json
```

该操作不改正文/成熟度、不激活退役条目，也不免除内容真值与来源检查。同一正文再次复审应
使用新审核文件名，registry 切换到新回执，旧回执保留；原审核文件必须保留。
缺回执显示 `review-unverified`，不能以 registry、maturity 或文件目录替代审核。
