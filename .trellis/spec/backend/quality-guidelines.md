# 质量规范

> 本项目的实现、测试和审核约定。

---

## 总则

- 正确性和状态完整性优先于最小 diff；局部问题最小修复，结构性多写者/多 schema 问题在
  owner 边界根治。
- Claude 负责假设、价值判断、链路推理和升级/降级；工具负责稳定 replay、diff、raw
  evidence、schema 和幂等落盘。
- 新增第三方依赖前必须证明标准库和现有依赖不足，并取得确认。
- 新代码优先复用 `target_paths`、`finding_index`、`knowledge_registry` 等 owner API，不能
  在消费者中复制身份和解析逻辑。
- 修改行为必须有针对输入/输出的回归测试；不要测试私有实现细节或为覆盖率堆空测试。

---

## 禁止模式

- target-level `findings.json` 的直接多写者或 list/object 双 schema。
- 用 scanner-negative、coverage gap、regex 或 score 代替 AI 最终判断。
- 把 runtime v2 可派生状态重新持久化进 `session.json`。
- 同名 batch list 仅按 stem 共享磁盘状态。
- report ID 只按漏洞类型和当前循环序号生成并覆盖旧文件。
- broad exception 静默吞掉 canonical state 写入或参数错误。
- 测试依赖个人 `~/.claude`、真实目标数据或未跟踪 `.claude/settings.json`。

---

## Required Patterns

- Coverage changes must keep `rules/coverage-gate.md` as the completion owner.
  Before a feature/workflow is `tested`, its evidence identifies the exercised
  input surface, observed role/state/business behavior, and validation depth;
  residual lanes stay in the existing reason-bearing coverage states rather
  than creating `coverage_note`, `unruled_out`, or another schema owner.
- Security automation wording must be concrete. Avoid vague descriptions such as
  "security" or "hacking"; name the exact vulnerability class, trigger condition,
  input, output, stop condition, and evidence gate.
- High-impact validation actions must be scriptable and reproducible. The model may
  use a browser or MCP tools to observe pages and infer request shapes, but replay,
  state-changing checks, batch validation, and exploit verification must go through
  project scripts or explicit commands.
- Security automation must classify risk by concrete side effect, not by HTTP
  method alone. POST/PUT/PATCH/DELETE can be legitimate evidence paths when the
  observed request is read-only, preview/validate-only, or uses test-owned
  reversible resources. Broad scanner templates may still require opt-in, but
  that scanner guard must not become a global GET-only mindset.
- Raw request and response evidence must be preserved for validation. Summaries,
  knowledge cards, and hypothesis seeds should store reusable signals only, never
  target domains, credentials, one-time tokens, or lab-specific answers.
- 认证来源必须保持 target scope：显式 auth file/header/cookie/token 默认不合并进程内旧环境
  凭据，只有无显式来源或 `--auth-from-env` 时读取环境；两个非空 source target 冲突时必须在
  header/origin merge 前失败，显式 auth file 缺失、不可读、损坏或与 CLI target 冲突时必须在
  target I/O 前失败。Shell direct entry 遇到已绑定到其它 target 的 ambient session 仍清空认证并
  按 anonymous 继续，不能重绑旧凭据或把无目标内 URL 当成功。
- Public anonymous-exposure detection must not classify entire response prose as
  sensitive evidence. Weak markers such as `admin`, `password`, `oauth`, or
  `security question` only count when they come from structured key paths,
  assignment-style config fields, or strong secret-value shapes (for example
  JWTs, PEM private keys, or mnemonic seed phrases). Natural-language challenge,
  tutorial, help, or mitigation text must not auto-promote an authz finding.
- Discovery-stage scanners must not drop recon-discovered URLs just because they
  are outside the current live-host set. Third-party APIs, GitHub/Docker/CDN,
  webhook, OAuth/JWKS, and integration URLs can be chain context. Keep them in
  the discovery artifact stream and let surface/validation decide whether they
  are direct findings, chain leads, public metadata, or dead ends.
- Discovery-stage payload/probe denoising must be lossless for attack surface:
  raw probe URLs may be logged and kept out of automatic replay, but their
  endpoint path and parameter names must be preserved as inert surface shapes
  for ranking/coverage. Prefer extra false-positive leads over hiding a real
  endpoint behind historical XSS/SQLi/LFI/RCE probe noise.
- SPA/fallback/noise-filtered URL files are priority aids, not authoritative
  scope reducers. Coverage and surface discovery should merge filtered artifacts
  with raw recon artifacts where practical, then let ranking and validation
  downgrade noise instead of silently removing possible attack surface.
- Direct finding, validation, report, checkpoint, and ranked-surface queues must
  be target-owned. Use `url_belongs_to_target()` before promoting scanner or
  recon URLs into P1/P2, pending validation, or report follow-up. Off-target
  URLs discovered in recon/browser/JS stay useful as `external-chain-context`
  leads for integration review, hardcoded key review, OAuth/JWKS/webhook/CDN
  dependency analysis, or report-writing context; do not suggest direct live
  vulnerability validation against third-party hosts unless ownership/scope is
  established.
- POST/JSON active probes must reject off-target URLs, cross-scope redirects,
  and explicit non-POST rows before network I/O. Authentication must come from
  `AuthSession.headers_for_url()` and never enter argv, logs, public artifacts,
  or curl reproducers.
- Anonymous `200` API responses with substantial bodies should be preserved as
  manual-review discovery leads when they lack body-backed sensitive markers.
  Store them under `manual_review/open_200_api.txt`; only promote
  body-backed authz/config/secret/business-impact evidence into
  `auth_bypass/unauth_api_access.txt`.
- SQLi result-diff validation must separate "probe-shaped" from
  "finding-grade evidence". Quote-only or syntax-breaker probes that merely
  shrink search results, remove JSON fields, or change length are not findings
  by themselves; promotion requires a DB/parser error marker, boolean/union/
  NoSQL confirmation, result expansion, added fields, or a dedicated timing
  lane.
- POST-JSON WAF adaptation must stay baseline-relative and bounded. Only a new
  SQLi/XSS block signal may trigger an evidence-linked AI plan with a default of
  four class-specific semantic variants and a hard maximum of eight; every retry
  consumes the endpoint request budget. Without a plan, the static fallback stays
  capped at two variants. A plain `429`, failed baseline, or retry transport error
  is not a WAF block or application response. Preserve the block/bypass observations,
  and clear stale lane-local hit files on rerun.
- Budgeted active probes that span many endpoints must persist an
  input-fingerprint-bound cursor in the existing lane summary. A partial rerun
  resumes the untested endpoint tail, keeps prior evidence for the same snapshot,
  defers transport-failed endpoints without starving the tail, and resets only
  when the input fingerprint changes or the batch is complete; the request cap
  remains authoritative for each batch.

---

## AI 与工具边界

- 工具化必须增强 AI，而不是把 AI 降级成固定扫描器。
- AI 负责假设生成、攻击面取舍、跨证据组合、误判解释和升级/降级决策。
- 工具负责稳定 replay、diff、raw evidence、ledger 写入和格式一致性。
- 新增执行工具不能只输出 pass/fail；必须保留 baseline、variant、证据路径、停止条件和
  Claude 可继续推理的下一步建议。
- AI identity enrichment may propose a vulnerability family, semantic
  dimensions, aliases, and follow-up tests, but the candidate is untrusted
  until `tools/identity_contract.py` validates completeness, confidence,
  provenance, and conflicts. Persist candidates through the Evidence Ledger;
  do not create a second identity or lifecycle owner.
- A complete family-aware closure key is immutable. Later evidence that adds or
  corrects dimensions creates a linked replacement key and preserves the old
  evidence reference; it must not rewrite historical terminal state.

---

## Architecture Maintenance Contract

The authoritative five-plane and memory contract lives in
`docs/architecture-contract.md`. Apply these implementation checks when a
backend change crosses a layer:

- Identify the single durable owner and public mutation API before editing a
  consumer. Ordinary reasoning, routing, ROI, stop-condition, and knowledge
  changes stay in `skills/`, `knowledge/`, or `rules/` and do not change owner
  lifecycle state.
- Projection code may write only its own rebuildable artifact. It may request a
  durable mutation through the owner's API, but must not write another owner's
  file or reduce a second lifecycle truth.
- Treat `hunt-memory/targets/<target>.json` as a compatibility/read projection;
  new code must not add duplicate findings, tested endpoints, coverage, or
  lifecycle facts to it.
- Admit a new runner only when the existing HTTP/browser/MCP/subprocess/source
  or validation boundary cannot provide deterministic, reusable, budgeted,
  evidence-linked behavior. A protocol or vulnerability name alone is
  insufficient.
- Match validation to the changed boundary: content changes use focused
  governance/recall checks, execution changes use runner/evidence checks, and
  owner/schema changes add recovery and cross-owner checks. Run the full suite
  for shared-contract or release changes, not as a default for every edit.

---

## 专题契约

按改动 owner 读取对应分册，不要默认加载全部契约：

- [Runtime 与 Autopilot](./contracts/runtime-autopilot.md)：Claude CLI、启动、打包、长任务和
  子进程 argv 边界。
- [Recon 与 Surface](./contracts/recon-surface.md)：Recon 输入、scanner 语料、coverage、
  Surface 和知识路由。
- [Browser 与 JavaScript](./contracts/browser-js.md)：浏览器证据、增量发现和 JS 分析。
- [Validation 与 Evidence](./contracts/validation-evidence.md)：有界验证、证据门禁和 runner。
- [Lifecycle 与 State](./contracts/lifecycle-state.md)：身份、checkpoint、case、observation 和
  Action Queue 生命周期。
- [外部集成](./contracts/integrations.md)：OAST、solver、spray、EBurst 和动态 token adapter。

## Testing Requirements

<!-- What level of testing is expected -->

- New routing, seed, or knowledge-card behavior needs focused regression tests that
  prove the expected card selection and de-noising behavior.
- A security finding is not considered stable project capability unless the
  evidence path is reproducible and raw request/response artifacts can be traced.

---

## Code Review Checklist

- [ ] 入口、核心逻辑、异常路径和出口的数据流完整。
- [ ] 每个持久化对象只有一个 schema/identity/mutation owner。
- [ ] 重复执行、中断恢复、旧 schema 和损坏输入行为明确。
- [ ] CLI stdout/stderr 和退出码不会破坏机器解析。
- [ ] 目标路径通过 canonical target/storage key 隔离。
- [ ] 新行为有 focused test，跨层变更有真实 staging 或 localhost wiring 测试。
- [ ] 没有修改用户本地 runtime、目标 artifact 或无关未提交文件。
- [ ] 文档命令、实际 CLI 参数和测试一致。

---

## Knowledge Registry Quality Gate

The knowledge capability registry is a runtime input, not only documentation. Keep
`knowledge/capabilities.yaml` as the single source of truth for capability identity,
card paths, `kind`, `layer`, `load`, and purpose metadata. Consumers such as
`tools/context_pack.py` must use `tools/knowledge_registry.py`; do not add a second
string-based YAML parser or a hand-maintained card path table.

Run `python3 tools/knowledge_audit.py` after adding or changing knowledge cards,
payload packs, playbooks, or registry entries. The audit is read-only and checks:

- registry schema, unique IDs/files, kind-specific layer/load contracts, budgets, and
  active-document inventory;
- v2 frontmatter identity/type and type-specific signal, evidence, stop, and workflow
  sections;
- `deep_refs`, `related_cards`, Skill references, workflow routes, and Markdown links.

Identity, load, and reference failures are `error` and must make the default audit
fail. Missing v2 frontmatter on an existing card is a single `warning` for gradual
migration; `--strict` may be used when a migration campaign needs warnings to fail.
Do not add fixed word-count, code-block, MCP-map, or phrase-blacklist rules merely to
copy an external knowledge audit. The audit is an explicit governance/test command,
not an `/autopilot` startup preflight.

Required regressions include a passing audit for the current repository, legacy warning
compatibility, malformed/duplicate/orphan fixtures, frontmatter and reference failures,
CLI exit modes, and preservation of context-pack card selection and case-router budget.

## 大文件拆分纪律（2026-09-11 实测教训）

**Pattern: 纯搬动拆分的可行性由依赖深度决定，不由行数决定**

autopilot_state.py 拆分实测：loop_guard（依赖 8 符号）/state_read（依赖 20）/
gate（依赖 12）纯搬动成功；closure/decision 投影族（依赖 30+ 状态构建函数）
回退——搬它需要反向 import 会循环。

```
拆分前先跑依赖分析（AST 收集搬走函数引用的外部符号）：
  依赖 < 15 个 → 可纯搬动 + re-export
  依赖 15-30   → 逐个评估，可能要连带搬依赖
  依赖 > 30    → 不拆，或先做接口设计再拆（纯搬动会循环）
```

**re-export 模式**：原文件保留全量 `from tools.<new_module> import (...)`，
外部消费方零破坏。新增分桶测试不受影响（OWNER_SOURCES 不含被拆文件）。

**常见错误**：新模块漏 import（NameError 在运行时而非收集期暴露）——
搬完立刻 `python -c "import <module>"` + 全量 pytest。

**禁忌**：claim_templates ↔ action_queue 的 DEPTH_CONTRACT_VERSION 循环
import——常量在低层模块硬编码 + 一致性测试绑定（`tests/test_claim_templates.py`）。
