# 上下文加载规则

本规则用于解决 Claude CLI 上下文膨胀问题。默认只加载当前任务必要文件，不全量读取 Skills、知识库、日志或扫描结果。

## 核心原则

```text
先装配上下文，再执行任务。
```

加载顺序固定为：

```text
目标层 -> Skills 层 -> 知识库层 -> 检查层 -> 写回位置
```

## 默认必读

每轮复杂任务默认只需要这些入口：

```text
CLAUDE.md
memory/goals/active.json
skills/runtime-protocol.md
knowledge/index.md
rules/red-lines.md
rules/coverage-gate.md
```

如果 `memory/goals/active.json` 不存在，先根据用户当前目标建立或询问目标上下文。

## 按需读取

根据当前任务只选择必要文件：

| 场景 | 按需读取 |
|---|---|
| Web2 recon | `skills/web2-recon/SKILL.md`, `knowledge/cards/coverage-prompts.md` |
| API / IDOR | `skills/web2-vuln-classes/SKILL.md`, `knowledge/cards/api-idor.md` |
| 认证 / 角色 / 组织边界 | `knowledge/cards/auth-access.md` |
| URL fetch / webhook / import | `knowledge/cards/ssrf-url-fetch.md` |
| GraphQL / subscription | `knowledge/cards/graphql.md` |
| 上传 / 导入 / 转换 | `knowledge/cards/upload-parser.md` |
| Race / 并发状态差异 | `knowledge/cards/race-conditions.md` |
| 连续低价值方向 | `knowledge/cards/dead-ends.md` |
| 证据命中深度 Web 路由 | `rules/playbook-router.md` |
| Candidate 验证 | `skills/triage-validation/SKILL.md`, `rules/reporting.md` |

## 默认不加载

除非当前任务明确需要，不要默认读取：

- 全量 `skills/*/SKILL.md`
- 全量 `knowledge/cards/*`
- 全量 `skills/security-arsenal/SKILL.md`
- 全量 `skills/security-arsenal/REFERENCES.md`
- 全量 hunt journal / findings / recon 输出
- 大体积扫描结果
- 与当前目标、Skill、证据无关的历史会话

## 知识库加载限制

一次只加载 1-2 张知识卡。只有当当前证据继续扩展时，才加载更多。

知识卡必须服务于当前 Skill，不能反过来让知识库主导任务。

### 前沿模型上下文价值判据

对 Opus 4.8 等前沿模型，未经 A/B 证明有增量的方法论 prose 不应默认进入上下文。
已有 bug-bounty slim、web2-vuln live A/B、蒸馏知识卡 pilot 三层验证显示：
通用方法论文本容易触达模型天花板；稳定增量更可能来自按需技术细节、真实案例指针、
证据门、停止条件和可执行回归。

因此新增或加载知识资产时按以下优先级处理：

1. 优先加载当前证据直接需要的精确技术细节、证据门、停止条件和本地案例指针。
2. 蒸馏知识卡默认作为 router / recall 层：先根据触发信号定位模式，再按需查询源报告案例。
3. 长篇方法论、全量 Skill、全量知识卡和原始报告正文只在明确缺口或人工复核时读取。
4. 如果知识只是在复述模型已稳定掌握的方法论，应降级为索引、案例指针或回归测试，而不是默认上下文。

## 日志和扫描结果加载限制

读取扫描结果时优先读取摘要、索引或最近片段：

- `findings/<target>/findings.json`
- `validation-summary.json`
- target profile
- handoff
- surface summary

不要默认读取原始大日志、完整 HTML、完整响应包或所有 JSONL。

## 输出上下文包

执行前应输出：

```text
CONTEXT PACK
- Target:
- Phase:
- Selected skill:
- Must read:
- Knowledge cards:
- Required checks:
- Optional:
- Do not load:
- Write back:
```

## 写回位置

根据结果写回：

- 目标线索：`python3 tools/target_memory.py lead "..."`
- 下一步：`python3 tools/target_memory.py next "..."`
- 无效方向：`python3 tools/target_memory.py dead-end "..."`
- 会话交接：`python3 tools/target_memory.py handoff "..."`
- 可复用经验：按 `knowledge/promotion-rules.md` 晋升
- 验证后发现：`/remember`

能力增强必须按 `knowledge/promotion-rules.md` 的落位规则分层：
经验/技巧/bypass 进知识库，判断进 `evidence_rubric.py`，路由进 `context_pack.py`，
下一步进 `checkpoint.py`，重复执行动作进 `tools/`，结果进 Evidence Ledger。

## 禁止事项

- 不要为了“更全面”默认读取所有 Skill。
- 不要把知识库全量塞进上下文。
- 不要把扫描日志当作上下文包主体。
- 不要在没有目标层上下文时直接开始复杂任务。
- 不要用上下文包绕过红线和覆盖基线。
