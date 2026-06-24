---
description: 为当前目标装配最小上下文包，避免全量读取 Skills、知识库和日志。用法：/context-pack [target] [focus]
---

# /context-pack

装配当前目标的最小上下文包。

这个命令不执行测试、不扫描目标、不写目标记忆。它只读取本地目标记忆、
surface 排名、覆盖矩阵、findings 索引、Evidence Ledger，以及 browser/JS/source
的小型证据索引，决定 Claude 本轮应该读哪些文件、不要读哪些文件、结束后写回哪里。

## 必读规则

```text
rules/context-loading.md
```

## 用法

```text
/context-pack
/context-pack target.com
/context-pack target.com api-idor
/context-pack target.com graphql
/context-pack target.com sqli
/context-pack --target target.com --focus upload
/context-pack --target target.com --focus race
```

## 默认流程

先运行：

```bash
python3 tools/context_pack.py --target <target>
```

如果用户没有传 target，工具会读取 `memory/goals/active.json` 的当前目标。

工具会：

1. 读取目标层：`memory/goals/active.json` 和 `memory/goals/targets/<target>.json`。
2. 只读调用 surface 排名，提取 P1/P2、Workflow Leads 和 target memory 线索。
3. 读取覆盖矩阵 high-value gaps。
4. 读取 `findings/<target>/findings.json` 索引。
5. 读取小型 browser/JS/source 证据索引：
   - `recon/<target>/browser/xhr_endpoints.txt`
   - `recon/<target>/browser/api_endpoints.txt`
   - `recon/<target>/browser/browser_params.txt`
   - `findings/<target>/js_intel/hypotheses.json`
   - `findings/<target>/source_intel/hypotheses.jsonl`
6. 读取 Evidence Ledger 摘要：`memory/evidence/<target>/ledger.jsonl`。
7. 推荐一个主 Skill，再推荐 1-2 张知识卡。
8. 输出证据锚点、假设种子、Actor Matrix 缺口、相邻角度、矛盾点和写回建议。

如果工具输出的 `AI override` 认为另一个 Skill / 知识卡更匹配当前证据，Claude
可以改选，但必须说明原因并保留红线与覆盖检查。

## 输出格式

```text
CONTEXT PACK
- Target:
- Phase:
- Active goal:
- Current hypothesis:
- Selected skill:
- Why this skill:
- Must read:
- Knowledge cards:
- Required checks:
- Evidence anchors:
- Hypothesis seeds:
- Alternative angles:
- Unknowns:
- Actor matrix gaps:
- Contradictions:
- Do not load:
- Write-back:
- AI override:
```

## 示例：API IDOR

运行：

```bash
python3 tools/context_pack.py --target example.com --focus api-idor
```

```text
CONTEXT PACK
- Target: example.com
- Phase: hunt
- Active goal: Find high-value API authorization issues
- Current hypothesis: org_id may be user-controlled
- Selected skill: skills/web2-vuln-classes/SKILL.md
- Why this skill: 已有可测试的 Web/API surface 或漏洞类别信号。
- Must read:
  - memory/goals/active.json
  - memory/goals/targets/example.com.json
  - skills/runtime-protocol.md
  - skills/web2-vuln-classes/SKILL.md
  - knowledge/index.md
- Knowledge cards:
  - knowledge/cards/api-idor.md
  - knowledge/cards/auth-access.md
- Required checks:
  - rules/context-loading.md
  - rules/red-lines.md
  - rules/coverage-gate.md
- Evidence anchors:
  - P1/P2 https://api.example.com/api/org/123/users score=...
  - Browser XHR/API: https://app.example.com/api/admin/export?order_id=42
  - JS-reader endpoint: POST /api/accounts/42/export source=recon/example.com/js/admin.js auth=true
  - Source-intel hypothesis [idor]: /api/accounts/:id/export -> route contains account object id
  - Actor gap: /api/accounts/42/export x IDOR peer/other_object_same_org/id_swap expected=deny_or_no_data status=missing
  - Coverage gap: /api/org/123/users x IDOR weight=...
- Hypothesis seeds:
  - 对象/组织/租户 ID 是否只在前端约束，服务端是否重新绑定当前身份。
  - 浏览器观察到的 XHR/API 优先做登录态、角色、租户差异对比；遇到状态改变动作先按红线降级到只读或可回滚验证。
  - export/download/report 类接口是否可通过 ID 或筛选条件读取其他主体数据。
- Alternative angles:
  - 用 Playwright/浏览器复用登录态重放关键页面，只看 Network/Console 差异和只读响应变化。
  - 从 REST IDOR 横向扩展到导出、报表、批量查询、成员管理和 invite 流程。
- Unknowns:
  - No browser-observed XHR/API context loaded.
- Actor matrix gaps:
  - /api/accounts/42/export x IDOR: peer/other_object_same_org/id_swap expected=deny_or_no_data status=missing
- Contradictions:
  - None detected.
- Do not load:
  - full skills/* tree
  - full knowledge/cards/* tree
  - raw large recon logs, full JSONL, full HTML responses, or unrelated historical sessions
  - raw browser capture requests/console/storage unless validating one exact replay path
- Write-back:
  - python3 tools/target_memory.py lead "Evidence: ... Why it matters: ... Next action: ... Stop condition: ..." --target example.com
- AI override: Claude may choose another skill, knowledge card, or path if the evidence supports it...
```

## Skill / Focus 路由

| 输入 | 主 Skill | 知识卡 |
|---|---|---|
| recon 缺失 / `web2-recon` | `skills/web2-recon/SKILL.md` | `coverage-prompts`, 按 surface 追加 |
| `api-idor` | `skills/web2-vuln-classes/SKILL.md` | `api-idor`, `auth-access` |
| `auth` | `skills/web2-vuln-classes/SKILL.md` | `auth-access`, `api-idor` |
| `ssrf` / `url-fetch` | `skills/web2-vuln-classes/SKILL.md` | `ssrf-url-fetch` |
| `graphql` | `skills/web2-vuln-classes/SKILL.md` | `graphql` |
| `sqli` / `hidden-param` | `skills/web2-vuln-classes/SKILL.md` | `sqli-hidden-surfaces` |
| `upload` | `skills/web2-vuln-classes/SKILL.md` | `upload-parser` |
| `race` | `skills/web2-vuln-classes/SKILL.md` | `race-conditions`，并在 Required checks 保留 `rules/red-lines.md` |
| candidate / validation | `skills/triage-validation/SKILL.md` | 相关漏洞卡 + `dead-ends` |

## 纪律

- 一轮任务只选一个主 Skill。
- 一次最多选 1-2 张知识卡。
- 高风险动作必须加入 `rules/red-lines.md`。
- 结束前必须加入 `rules/coverage-gate.md`。
- 上下文包不是结论；它只是执行前的加载计划。
- browser 证据默认只读 `recon/<target>/browser/` 的 XHR/API/params/form/page-JS 小索引；
  不默认加载 `evidence/<target>/browser/...` 的原始 requests/console/storage。
- Actor Matrix 缺口不是结论；它只是提醒哪些角色/对象/replay 还没有结构化记录。
- 工具推荐不是强制路线；Claude 可以改选 Skill、知识卡或执行路径，但必须说明原因并写回。
