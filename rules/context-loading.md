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

## 禁止事项

- 不要为了“更全面”默认读取所有 Skill。
- 不要把知识库全量塞进上下文。
- 不要把扫描日志当作上下文包主体。
- 不要在没有目标层上下文时直接开始复杂任务。
- 不要用上下文包绕过红线和覆盖基线。
