---
description: 使用知识库层为当前 Skill 补充思路、案例和停止条件。用法：/kb index | /kb suggest | /kb card <name> | /kb cases ... | /kb promote
---

# /kb

使用知识库层。

`/kb` 负责让 Claude 在当前目标和当前 Skill 的基础上，按需读取知识库卡片，
生成更好的假设、思路分支、技巧家族、payload/bypass 方向、补充 checklist、
下一步和停止条件。

## 用法

```text
/kb index
/kb suggest
/kb card api-idor
/kb card auth-access
/kb card ssrf-url-fetch
/kb card dead-ends
/kb cases status
/kb cases get <report-id> [--full]
/kb cases from-card <card-id> [--report-id <id>] [--full]
/kb cases search --class <weakness> [--limit N]
/kb promote
```

## 子命令语义

### `/kb index`

读取 `knowledge/index.md`，只输出可用知识卡、外部参考和加载建议。

### `/kb suggest`

基于当前目标记忆和当前任务，选择 1-2 张最相关知识卡。

建议读取顺序：

1. `memory/goals/active.json`
2. `knowledge/index.md`
3. 当前 Skill
4. 命中的知识卡
5. 必要时读取 `rules/playbook-router.md`

### `/kb card <name>`

读取指定知识卡，例如：

```text
knowledge/cards/api-idor.md
knowledge/cards/auth-access.md
knowledge/cards/ssrf-url-fetch.md
knowledge/cards/dead-ends.md
```

输出时必须包含：

```text
Evidence: 当前依据
Hypothesis: 安全假设
Technique family: 相关技巧 / payload / bypass 家族
Checklist gap: 需要补漏的点
Next action: 最小验证动作
Stop condition: 放弃条件
Related card: 使用的知识卡
```

### `/kb cases ...`

案例查询是显式、只读、按需的补充链路，不会被 `/kb index` 或 `/kb suggest` 自动调用，
也不会写入 finding、evidence ledger、target memory 或 action queue。底层命令使用仓库内
可选的 gitignored `distill/corpus/`；没有本地 corpus 时返回结构化 `unavailable`，普通
知识流程继续执行。

```bash
python3 tools/case_corpus.py status --json
python3 tools/case_corpus.py get <report-id> --json
python3 tools/case_corpus.py get <report-id> --full --json
python3 tools/case_corpus.py from-card <card-id> --json
python3 tools/case_corpus.py from-card <card-id> --report-id <id> --full --json
python3 tools/case_corpus.py search --class <weakness> --limit 20 --json
```

默认只返回一个案例摘要；完整 `vulnerability_information` 必须显式指定一个 report ID
和 `--full`。`from-card` 只接受卡片 frontmatter 的结构化 `source_refs`，并在结果中保留
`pointers` 与 `dangling_refs`，供 Claude 决定是否补证据或降级，不把解析结果当成漏洞结论。

本地 corpus 由用户显式构建，不自动下载或安装依赖：

```bash
python3 tools/case_corpus.py build --input distill/work/batch_000.jsonl
```

### `/kb promote`（经 /distill）

经验晋升走 `/distill <target>` 直线流程：机器出题 → AI 提三元组 → 草稿卡写入
`knowledge/candidates/` → 人工内容审核通过后运行
`python3 tools/knowledge_promote.py --id <slug>` 完成 promote（mv + registry
登记 + strict audit + Pack 目录可发现，失败原子回滚）、`rm` 即 reject
（git 即生命周期，不再有第二个状态机）。**裸 `mv` 不是 promote**——未登记的卡
Pack 不可见且过不了 strict audit。

晋升前必须读取：

```text
knowledge/promotion-rules.md
knowledge/card-template.md
```

不要晋升：

- 目标专属临时线索
- 未验证漏洞结论
- 敏感凭证或真实用户数据
- 大段扫描日志
- 红线规则

## 和其他命令的分工

| 命令 | 职责 |
|---|---|
| `/target` | 管当前目标、线索、下一步、handoff |
| `/kb` | 提供知识库思路、技巧、payload/bypass 家族、补漏 checklist 和可复用经验 |
| `/hunt` | 执行漏洞挖掘流程 |
| `/validate` | 验证 Candidate |
| `/remember` | 保存验证后的发现或成功模式 |

## 纪律

- 默认不要全量读取知识库。
- 知识库提供思路和战术知识，但不替代 Skill 的路线选择和验证。
- 具体 payload、WAF 绕过、SQLi 绕过、parser 差异等可以写入知识卡，但必须保留前置条件、误判边界和最小验证方式。
- 任何知识卡输出都必须回到目标层形成 lead、next action 或 dead end。
- 和 `rules/` 冲突时，以 `rules/` 为准。
