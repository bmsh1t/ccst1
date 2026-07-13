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
/kb lifecycle audit
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

### `/kb promote`

把目标记忆或复盘中的可复用经验晋升到知识库。候选状态由
`tools/knowledge_candidates.py` 的追加式 lifecycle log 维护，不能直接把 markdown
复制到 `knowledge/cards/`。

从带 evidence refs 的目标经验创建候选：

```bash
python3 tools/target_memory.py pattern "两角色只读差异可复用" \
  --kind validation-technique \
  --evidence-ref memory/evidence/example/ledger.jsonl#L3 \
  --target example.com
python3 tools/knowledge_candidates.py stage \
  --kind validation-technique \
  --title "两角色只读差异验证" \
  --summary "保留 baseline/variant 和响应差异，先确认权限边界再进入报告门。" \
  --source example.com <entry-id>
```

跨目标经验可重复 `--source TARGET ENTRY_ID`；每个来源都必须有可定位证据。
报告蒸馏候选由 `/distill --ingest` 自动登记到同一 pending 队列。

```bash
python3 tools/knowledge_candidates.py list
python3 tools/knowledge_candidates.py review <candidate-id> \
  --reviewer human --reason "已在两个目标复核，补齐停止条件"
python3 tools/knowledge_candidates.py promote <candidate-id> \
  --card-id <registered-card-id> \
  --reviewer human --reason "正式卡已注册并通过严格知识质量门"
python3 tools/knowledge_candidates.py reject <candidate-id> \
  --reviewer human --reason "只适用于单个目标，无法迁移"
python3 tools/knowledge_candidates.py supersede <candidate-id> \
  --replacement <new-candidate-or-card> \
  --reviewer human --reason "新卡覆盖范围更完整"
python3 tools/knowledge_candidates.py audit --strict
```

状态只能按 `pending -> reviewed -> promoted|rejected|superseded` 迁移；`promote`
会检查正式卡存在、registry 登记和 `knowledge_audit.py --strict`，不会覆盖同名卡。

候选晋升后，正式卡另有独立的治理日志，不复用 candidate 状态：

```bash
python3 tools/knowledge_lifecycle.py audit
python3 tools/knowledge_lifecycle.py review <card-id> \
  --maturity tested --reviewer human --reason "可复跑证据" \
  --model-profile claude-cli/profile --evidence-ref tests/fixtures/review.md#L1
python3 tools/knowledge_lifecycle.py retire <card-id> \
  --reviewer human --reason "被更完整卡替代"
python3 tools/knowledge_lifecycle.py supersede <old-card> \
  --replacement <active-card> --reviewer human --reason "范围合并"
```

`knowledge/governance/events.jsonl` 是 append-only 事实来源；`maturity` 与 active/retired/
superseded 生命周期分离。工具只检查 reviewer、model profile、证据引用和 replacement
完整性，不自动判断知识价值、合并对象或晋升 verdict。

晋升前必须读取：

```text
knowledge/promotion-rules.md
knowledge/card-template.md
```

新增或更新知识卡时，默认按 `knowledge/card-template.md` 的经验压缩库结构：

```text
能力定位
触发信号
思路分支
技巧家族 / Payload 家族
补充 Checklist
最小验证
常见误判 / 死路
关联 Skills
晋升到 Skill / Queue 的条件
可晋升经验
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
