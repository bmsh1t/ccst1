# Tool Index — Claude CLI Quick Reference

> **Purpose**: When `/autopilot` `/hunt` `/recon` is running, Claude consults this table to discover which `tools/*` script fits the current evidence shape. The "When to use" column answers *"why would Claude choose this now?"*
>
> **Selection**: Native Skill/model reasoning selects methods and upstream tools. Retained project helpers provide concrete protocol, parsing, evidence or recovery value; file presence is not a reason to run a tool.
>
> **Path convention**: All paths are relative to repo root.

## 1. Recon (target → live attack surface)

| Tool | When to use | One-line function |
|---|---|---|
| `tools/recon_engine.sh` | New target / stale recon / primary-domain batch | Explicit bulk collection with raw sources, cursors and phase accounting; cached CI links only |
| `tools/cf_solver.py` | Confirmed Cloudflare challenge or expired clearance | Evidence-triggered 2Captcha+Playwright; stores clearance privately for recon |
| `tools/recon_adapter.py` | Reading recon output programmatically | Unified reader for `recon/<target>/`; streams and pages compact FFUF evidence without loading full artifacts |
| `tools/recon_candidates.py` | Cached candidate facts | Publishes candidate facts and full host inventory in name order; `--asset-cursor` resumes relation pages; never expands Scope |
| `tools/recon_host_verify.py` | Host pivot candidates were derived | One bounded read-only Host/SNI/default-vhost response comparison; appends observations without changing Scope or Queue |
| `tools/intel_engine.py` | Versioned component/service review | `/intel` owner — OSV/GHSA/NVD, KEV/EPSS, local signals, atomic `intel.json` |
| `tools/intel_artifact.py` | AI selects an omitted advisory group or filter | Read-only, bounded, cursor-paged query over the complete `intel.json`; never writes findings or Queue |
| `tools/technology_inventory.py` | Multiple consumers need reliable httpx/Nmap tech, version, service, or CPE data | Shared JSONL/text/Nmap parser and atomic component inventory owner |
| `tools/web_intel_artifact.py` | Official-source gap | Verified Web Intel recorder: TTL, source groups, atomic index |
| `tools/disclosure_search.py` / `disclosed-researcher` | Target or comparable disclosed-report pattern may transfer | Industry-aware cached metadata and independent full-report readings |
| `tools/scope_checker.py` | Verifying target classification | Deterministic host/URL classifier against active target set |
| `tools/scope_context.py` | Global Scope owner | Parses text lists/manifest v1, applies exclusions, classifies external context, and emits stable Scope hash |
| `tools/scope_source.py` | Inspect or explicitly update target Scope | `show` / `publish --manifest` / `publish --profile`; primary Scope lives in `state/<key>/scope.json`, replacement requires its current SHA256 |
| `tools/target_paths.py` | Computing per-target storage keys | Owns canonical target keys, including path-bound list keys |

Primary-domain list input (`targets.txt`) is handled by `tools/recon_engine.sh` as a batch dispatcher: each line writes its own `recon/<domain>/`; `recon/<list-key>/` is only the manifest/summary index. Obtain `list-key` from `tools/target_paths.py`'s `target_storage_key()`: sanitized stem + `--` + the first ten SHA256 characters of the canonical real path.

### `/recon` artifact map — read these before broad hunting

When `/recon` finishes, Claude should treat the files below as high-signal
handoff artifacts. They are not separate automation gates; they are quick reads
that help choose the next `/surface`, `/hunt`, `/intel`, `/cloud-recon`, or
manual review lane.

| Signal/tool | Primary artifact(s) | What Claude should do next |
|---|---|---|
| `waymore` historical URLs | `recon/<target>/urls/waymore.txt` | Merge mentally with `urls/all.txt`; prioritize old API/admin/export paths that no longer appear in current crawl |
| API doc grep (`swagger/openapi/redoc/postman/graphql`) | `recon/<target>/exposure/api_doc_candidates.txt` | Read first; API docs often reveal auth model, hidden operations, object IDs, and GraphQL/OIDC surface |
| `tools/openapi_semantics.py` | `api_specs/*`, `urls/api_endpoints.txt` | Review semantic auth boundaries; declarations remain leads, not findings |
| API leak consolidation | `recon/<target>/exposure/api_leak_candidates.txt` | Review before scanner breadth; imported Postman/OpenAPI candidates can drive exact endpoint probes |
| `porch-pirate` Postman search | `recon/<target>/exposure/api_leaks/postman_leaks.txt` | Look for workspace/collection URLs, environment names, tokens, and non-production API hosts |
| `postleaksNg` | `recon/<target>/exposure/api_leaks/postleaks_urls.txt`, `postleaksNg.log`, `postleaksNg/` | Extract collection/spec URLs; select `/secrets-hunt TARGET --filesystem recon/<target>/exposure/api_leaks/` when the evidence needs it |
| Osmedeus `SwaggerSpy` | `recon/<target>/exposure/api_leaks/swagger_leaks.txt` | Treat as API-spec discovery candidates; validate liveness and auth boundary before broad fuzzing |
| Verified secret pass | `recon/<target>/exposure/api_leak_trufflehog_verified.jsonl` | Evidence for attribution/usability and follow-up validation; choose the concrete action from the observed surface and apply `rules/ccst/red-lines.md` |
| `emailfinder` | `recon/<target>/exposure/identity_intel/emails.txt` | Seed tenant, reset-flow, invite, SSO, and username-format hypotheses |
| `LeakSearch` | `recon/<target>/exposure/identity_intel/leaksearch.txt`, `summary.md` | Attribute hits to the target and derive identity/credential hypotheses for the next evidence-backed action |
| `cloud_enum` | `recon/<target>/exposure/cloud/cloud_enum.txt`, `cloud_enum.log` | Treat as candidate cloud ownership evidence; pivot to `/cloud-recon` or minimal ownership checks |
| Generic asset relations | `recon/<target>/exposure/asset_relation_*` | Queue `scope-review`; keep external relations non-executable |
| Host pivot response comparison | `recon/<target>/exposure/host_collision_observations.jsonl`, `host_collision_summary.json` | Compare only target-owned controls; a difference remains a candidate and requires independent validation |
| Batch inventory | `recon/<list-key>/surface_inventory.txt`, `ai_handoff.md`, `batch_inventory.json` | Completed targets and source counts in completion order; select follow-up natively |

OpenAPI metadata probing defaults to 20 live origins. Set
`BBHUNT_OPENAPI_MAX_PLATFORM_HOSTS=0` for no host limit.

Runtime readers also surface these counters through `tools/runtime_state.py` and
`tools/autopilot_state.py`, so `/autopilot` and `/surface` can notice exposure,
identity, and cloud signals without re-enumerating everything.

## 2. Discovery (expand surface)

Context Pack includes `surface_advisory` over its existing bounded review window:
observed shape, unknown questions, existing-material inspection and stop conditions.
Question material comes from the registered `surface-unknown-probes` card. This is
not a live probe, Skill selector or Queue writer. `operational_metrics` reuses the
same verified Store snapshot; unavailable safety/replay/stop rates remain null.
Advisory JSON is capped at 16 items and text at 8. Text exposes its JSON expansion
command; `has_more_candidates` and the upstream `source_window` keep the two bounds
visible. Expand remaining URLs through the existing Surface index query and full
question/stop material through the recorded card, section and family.

| Tool | When to use | One-line function |
|---|---|---|
| `tools/param_discovery.py` (or `.sh`) | Live URLs exist, parameters thin | Target-scoped/auth-aware hidden parameter mining (arjun + x8) |
| `tools/dns_expand.py` | AI sees a DNS naming/scope gap after passive Recon | Bounded alterx/dnsgen + puredns expansion |
| `tools/source_hunt.py` | Need persistent source originals or a bounded clone | Acquisition and explicit source/workflow capture; analyses not_run |
| `tools/repo_source.py` | Need to clone target's public repo | Size-bounded GitHub repo acquisition |
| `tools/repo_workflows.py` | Repository acquisition needs retained CI originals | Bounded exact workflow snapshots and inventory; no parsing or ratings |
| `tools/repo_source_artifacts.py` | Resume source capture or historical analysis | Read source/workflow status without inventing zero findings |
| `tools/wordlist_engine.sh` | Selected sources need bulk offline mutation or website words | Optional word-pool recipe with local seeds, stage logs and compatibility paths |
| `tools/osint_employees.sh` | Public identity sources need collection and permutation | Optional OSINT preparation; observed/inferred materials and raw receipts stay separate |
| `tools/external_arsenal.sh` | Bootstrapping or diagnosing a box | Detect tools, install hints, and explicit `--versions` smoke |

## 3. Vuln & Bug-class testers

| Tool | When to use | One-line function |
|---|---|---|
| `tools/vuln_scanner.sh` | Recon done, want bounded breadth context | Bounded upstream Nuclei with per-run raw/log/exit/input receipts and residuals |
| `tools/validation_runner.py` (`record-evidence`) | Already-executed raw observations or final cleanup read-back | Registers evidence only; cleanup-only input binds exact mutation refs and never confirms a new finding |
| `tools/validation_runner.py` (`record-observation`) | Saved native/browser observations, with no Finding required | [No-verdict registration](evidence-runners.md#native-observation-registration); immutable full snapshots, original-attempt supplements and registration-only retries |
| `tools/sender_semantics.py` | Byte-exact/proxy/cache/smuggling work needs sender choice | `--list` / `--require ...`; sender capability matrix + raw HTTP/1 sender for low-level request semantics |
| `tools/aspnet_viewstate_knownkey.py` ⚠️ manual-only | Captured page contains `__VIEWSTATE` | Offline machineKey check; `--reveal-key` only for controlled validation |
| `tools/telerik_knownkey.py` ⚠️ manual-only | Captured Telerik `SerializedParameters` | Offline vendored Badsecrets default-key check; no HTTP or state write |
| `tools/eburst_lane.py` | Explicitly selected Exchange HTTPS interface check | Optional bounded upstream `-C` adapter; current Scope, raw bytes and exits, no credentials |

## 4. Browser / JS / Source intelligence

| Tool | When to use | One-line function |
|---|---|---|
| `tools/browser_evidence.py` | MCP browser evidence already imported | Compact linkage/readiness and baseline-checked original JSON/HAR step reading; never launches a browser or registers Store facts |
| `tools/browser_mcp_import.py` | Chrome DevTools/Playwright MCP artifacts ready | Normalize discovery materials and preserve one original-byte network baseline; discovery is not experiment completeness |
| `tools/browser_surface.py` | Browser evidence dumped | Extract XHR/API/GraphQL/realtime shapes from browser evidence |
| `tools/deep_js_packer.py` | Concrete webpack/chunk/source-map signal | Evidence-gated Packer bundle/page recovery into existing JS artifacts |
| `tools/surface.py` | Cached recon ready for review | Stream every exact target-owned URL into a neutral bounded review window; publish counts and complete expansion |
| `tools/surface_index.py` | Large URL corpus needs exact dedupe or long-tail paging | External-sort exact URL index with provenance union, lossless variants, shape/source/ownership cursor filters |
| `tools/surface_projection.py` | Bootstrap/context consumers need a fast URL-ordered review view | Manifest-bound bounded cache; only exact hits are consumable, stale/missing remains explicit refresh work |
| `tools/surface_finalizer.py` | Recon completed or derived surface needs recovery | Shared non-fatal recon post-processor for exact index, complete streaming review, inventory summary, and projection |
| `tools/finding_index.py` | Scanner review material or explicit historical inspection | Scanner-material index and historical readers; TargetStore owns Finding facts |
| `tools/structured_findings.py` | Reading single finding | Helpers to rank/load structured findings |

## 5. Auth & credentials

| Tool | When to use | One-line function |
|---|---|---|
| `tools/auth_session.py` | Carrying auth across recon/scan/replay | Auth-session helpers; produces `BBHUNT_*` headers |
| `tools/_auth_helper.sh` | Shell scripts sourcing auth env | Reads `BBHUNT_AUTH_HEADERS` into `BB_AUTH_ARGS=(-H ...)` |
| `tools/credential_store.py` | Loading `.env` secrets without leaking | Bounded credential loader |
| `tools/breach_checker.py` | Enrich prepared password candidates | HIBP counts in input order; failures stay unknown; SHA-1 prefixes only |
| `tools/spray_orchestrator.sh` ⚠️ controlled | Credential lane selected after AI shortlist | input-bound dry-run; request spec; unified audit/stop/resume; private evidence |

## 6. OAST / async (Blind vulnerabilities)

| Tool | When to use | One-line function |
|---|---|---|
| `tools/oast_listen.py` | Blind SSRF/XXE/RCE/SQLi suspected | **interactsh wrapper + OOB marker attribution** — start/markers/poll/stop; `markers` mints a unique `<label>-<uid>.<oast-host>` to embed in your payload, `poll` attributes callbacks back to the payload and class |

## 7. Hunt orchestration & state

| Tool | When to use | One-line function |
|---|---|---|
| `tools/hunt.py` | Explicit recon/scan pipeline (CLI) | Single targets default to recon + bounded scan; reports are explicit; lists run batch recon |
| `tools/autopilot_state.py` | Reading current autopilot state | Shared control facts plus compact read-only bootstrap/full diagnostic state; compact mode never ranks large surface bodies |
| `tools/capability_profile.py show / record-degraded / clear --runtime-root ROOT` | Persisting a confirmed tool/MCP outage across sessions, then explicitly acknowledging recovery | Runtime-global advisory marker; startup reads only and never treats it as target evidence |
| `tools/observation_inventory.py` | Large/resumed recon corpus | Owns neutral Recon `observations.json`; stat-bound summary and revision cursor are derived; never routes a Skill |
| `tools/action_queue.py` | AI selects explicit Action work | Thin Store adapter: list, claim explicit `--id`, resolve and summarize; AI chooses the action |
| `tools/target_case_state.py` | Multi-actor/object validation context | Actor/session/object/hypothesis registry and private auth refs; context memory only — no backlog, no route score |
| `tools/coverage_matrix.py` | Reviewing unresolved cells and endpoint kinds | Primary mark commands append Store reviews; `reviews [--history] [--id ID]` expands them; rebuilt cells still require execution evidence |
| `tools/target_store.py upgrade-schema --target TARGET --repo-root ROOT --backup ABSOLUTE_BACKUP` | Enabling current Store capabilities on an older schema | Explicit verified-backup upgrade to current schema v18; ordinary reads/init do not upgrade |
| `tools/target_store.py create-finding --target TARGET --finding-id ID --endpoint URL --method METHOD --family FAMILY --title T --claim C` | Persisting an unassessed Candidate claim before evidence registration | No execution evidence or verdict is invented; idempotency key defaults to create-finding:<finding-id>; same key with different content is refused |
| `tools/target_store.py dispose-finding --target TARGET --finding-id ID --status withdrawn --reason TEXT --command-id ID` | Correcting a mistaken unbound Candidate | Append withdrawal or explicit active/reopen with predecessor; optional replacement-id; rejects evidence/assessment/Action/Coverage bindings; preserves history |
| `tools/target_migration.py --backfill-coverage-source SOURCE --repo-root ROOT --target TARGET` | Recovering historical Coverage annotations after cutover | Manifest-bound historical import with source pointers; preserves newer reviews and grants no closure |
| `tools/resume.py` | Continuing previous target work | `/pickup` backend — summarize prior session+untested endpoints |
| `tools/experience_recall.py query --target TARGET --query QUESTION [--compact]` | 按问题读取经验/已审方法 | current 独立于 ranked recalled；完整经验在 record；health/pagination 明示缺失与余量 |
| `tools/experience_recall.py history --target TARGET [--compact]` | 原始 Store 历史翻页 | 完整经验在 experiences.items；--cursor 使用 Store 游标，--id 展开单条；不得混用 query 游标 |
| `tools/experience_recall.py index-build / index-status / index-prune` | 显式管理派生文本索引 | 目标 capture 按 Store audit/外部字节变化局部重采；`--shared` 不打开目标库、知识仍全量审核；`--full-rebuild` 重建；模型不隐式下载 |
| `tools/experience_recall.py context --target TARGET --id ID --version VERSION` | 展开精确历史更正/反证/依赖 | 独立 `--context-limit` / `--context-max-bytes` 和返回游标；完整原文用返回的 expand_command，不回填最新版本 |
| `tools/experience_recall.py relation-query --target TARGET --seeds @entities.json` | 精确实体多跳读取 | v4 包含 Case 显式关联、Action→operation→artifact 与实际 attempt/step 来源；路径仍为假设，旧格式需 --full-rebuild |
| `tools/experience_recall.py relation-build / relation-query / relation-status / relation-prune --shared` | 已审方法共享图 | 不打开目标 Store；query 的 seeds 为 knowledge-pattern 的 method_id/content_sha256/anchor；build 支持 --full-rebuild |
| `tools/target_memory.py knowledge-source --target TARGET --id ID --json` | 为经验绑定已审知识依据 | 返回完整正文与审核回执 hash；加 purpose=origin/basis 后传入保存的 --sources-json |
| `tools/target_memory.py history-source --target TARGET --id ID [--full] --json` | 绑定或展开本目标已导入历史原件 | 默认返回精确来源绑定，仅可加 purpose=origin；--full 返回原记录/选择器/归档元数据与可用性，历史仍 unverified |
| `tools/target_memory.py link --target TARGET --id NEW --to OLD --relation refutes --conditions CONDITIONS --reason REASON --command-id ID --expected-revision REVISION` | 显式条件化纠错 | 绑定两端精确版本；不同条件保留 conditional 连接，不整体作废旧条件下的经验；撤回不复活被挑战结论 |
| `tools/target_memory.py note ... --update-index text` | 显式保存后更新本目标索引 | 也可选 relations/all；--index-encoder 仅 text/all；失败保留保存回执，按返回命令只重建索引 |
| `tools/knowledge_promote.py --id ID --review-existing --review-file knowledge/candidates/ID.review.json` | 既有知识显式复审 | 绑定当前正文与审核原件；保留历史回执、不改成熟度或自动激活 |
| `tools/knowledge_promote.py --id ID --update-index all` | 晋升后显式更新共享文本/关系 | 先完成发布并解锁；更新失败返回 partial/退出 2，不撤销发布，不应重复晋升 |
| `tools/remember.py` | Recording target experience | `/remember` backend — primary writes Store experience plus journal; legacy PatternDB awaits retirement |
| `tools/target_migration.py --backfill-memory-source SOURCE --repo-root ROOT --target TARGET` | Old target memory is missing from an already active Store | Explicit, cutover-manifest-bound Experience backfill; inspect receipt mapping and quarantine before use; no re-promotion |
| `tools/target_migration.py --backfill-pattern-source SOURCE --repo-root ROOT --target TARGET` | Historical PatternDB rows for an active target need recall | Explicit, byte-pinned import plus permanent original archive; receipt maps target-owned file/line, including rotated logs. Exact-source retry may add a missing archive without new Store writes; no cross-target recall or promotion |
| `tools/validate.py` | Pre-report validation gate | 7-Question Gate + 4 gates — runs `/validate` |
| `tools/report_generator.py` | Publishing authored reports | `/report` backend — explicit body + current assessment/delivery binding; current index and pending drafts; unassessed manual notes |
| `tools/request_guard.py` | Logging request telemetry | Advisory audit/replay record + breaker telemetry |
| `tools/memory_gc.py` | Hunt-memory JSONL too big | Inspect/rotate audit/journal/pattern JSONL files |
| `tools/runtime_config.py` | Reading repo-local config | Shared loader for active `config.json` context/sections (`ctf_mode`, Resin, and optional solver settings) |
| `tools/runtime_doctor.py` | Checking repo↔runtime drift | `/sync-check` backend — compare commands/agents/skills |
| `tools/runtime_exec.py` | Subprocess execution | Shared shell-command runner with timeout/quoting |
| `tools/runtime_state.py` | Probing on-disk pipeline artifacts | Read autopilot/runtime state files |
| `tools/reset_target.sh` | Want clean re-run for one target | Wipe `recon/`/`findings/`/state for a single target |

召回的 `acquisition` 报告目标来源的 `mode`、`full_acquisition_reason`、
`experience_rows_read`、`owner_groups_read`、`reused_experiences` 和 `external_probes`，
与投影 `update.reused_sources/updated_sources` 分开。历史重采为 0 不等于没有 current 分页、
依赖元数据或原件字节读取。query/status 只读；旧 capture 缺失显式全采，坏代不会被查询修复。
构建期间来源变化（包括变坏后恢复原字节）拒绝发布并保留旧 CURRENT。

---

---

## Quick-pick by symptom

| Claude observes | First-pick tool |
|---|---|
| Concrete signal plus unresolved next verification question | smallest safe lookup/replay/diff/enrichment/probe, then checkpoint state |
| Need to remember user_a/user_b sessions, owned objects, private markers, or an open hypothesis | `target_case_state.py summary` (+ `add-actor`/`add-session`/`add-object`/`add-hypothesis`) |
| Observed object identifiers in cached artifacts | Native Read/Grep, then explicit Case object registration |
| Concrete CMS/plugin/theme/library version observed, or network product/CPE identified | `/intel` → `tools/intel_engine.py`; add `/scan-cves` only after AI selects a reachable advisory |
| 401/403 on interesting endpoint | AI-selected browser/curl/raw request; preserve observations for native registration |
| Anonymous `application-configuration` `200` | AI body review (config/oauth/security-answer content vs ordinary listing); preserve the observed request/response and comparison basis when promoting |
| Multiple session files in `.private/` | AI-selected multi-role comparison using the relevant sessions; retain per-role request/response evidence |
| Two account creds + numeric IDs | AI compares owner/peer object access and records the actual role, request and response |
| GraphQL endpoint discovered | AI-selected schema/operation inspection and authorization comparisons; native evidence registration |
| OAuth `/authorize` `/callback` discovered | AI-selected OAuth/OIDC flow review with per-step native request/response evidence |
| Payment / coupon / wallet / cart / checkout endpoint | high-value business-logic lane |
| Quota / OTP / payment / cart race signal | AI-selected workflow perturbation on the captured flow; preserve per-step raw evidence |
| Blind SSRF / RCE / XXE candidate | `oast_listen.py start` |
| Standard scans plateaued | AI-selected focused fuzz on remaining unexplored surface |
| Unicode / filter representation needs review | AI selects the exact representation and preserves raw evidence |
| Public/local source, uncertain reachability or guard | `skills/src-hunter/modules/whitebox-audit.md`; `source_hunt.py --source-file PATH`, native Read/Grep |
| Observed cloud binding or useful discovery gap | Native review; selected upstream cloud_enum/S3Scanner via `/cloud-recon` |
| Batch recon manifest exists | read `recon/<list-key>/batch_manifest.jsonl` using `target_paths.target_storage_key()`, then run `/surface` or `/hunt` on completed domains |
| Identity/cloud intel from recon has hits | review `exposure/identity_intel/summary.md` and `exposure/cloud/cloud_enum.txt`, then pivot to `/intel` or `/cloud-recon` |
| Passive DNS shows a naming dialect or evidence-backed hostname gap | AI-selected `dns_expand.py`; refresh `/surface` when new inputs require an updated view |
| Dangling DNS/service evidence | Native DNS/provider review; optional upstream dnsReaper/subjack via `/takeover` |
| Live URLs but no params | `param_discovery.py --target TARGET --from-recon` |
| Exchange/OWA/EWS/Autodiscover evidence | Native review or selected upstream interface tool; `/spray` for controlled credentials |
| Concrete webpack/chunk/source-map signal | `deep_js_packer.py`, then Claude native Read/Grep on recovered paths |
| JS bundles cached without recovery evidence | Claude native Read/Grep on exact selected paths |
| Recon done, want bounded breadth context | `vuln_scanner.sh` (candidate/residual summary; AI chooses validation) |
| Tech stack or identified network service needs CVE applicability | `/intel` → `intel_engine.py`; use `/scan-cves` for a selected reachable advisory |
| Dashboard / SPA target | Chrome DevTools/Playwright MCP → `browser_mcp_import.py` → `browser_surface.py` |
| Switching back to old target | `resume.py` |
| Want to remember a pattern | `remember.py` |
| Login surface + need credential prep | `/wordlist-gen`, `/osint-employees`, `/breach-check` |
| Credential breakthrough lane selected | `/spray` / `spray_orchestrator.sh` after prep + dry-run |

---

## Direct upstream execution

Native Read/Grep and the complete src-hunter Skill decide the current question,
selected input and interpretation. The commands `/scan-cves`, `/takeover`,
`/cloud-recon`, `/secrets-hunt`, `/wordlist-gen`, `/osint-employees` and `/token-scan`
remain method entry points; they do not require project wrappers or a fixed tool
chain. Mature upstream CLIs remain available directly through the native platform.

`wordlist_engine.sh`, `osint_employees.sh` and `eburst_lane.py` remain optional
helpers where source preparation, bulk operations or bounded execution save
repeated setup. Retaining a helper does not select it automatically. The first
two preserve material compatibility paths plus unique run logs; `ranked.txt`
remains a pool alias, and observed/inferred identity files are not confirmed users.
EBurst retains only the upstream interface-check mode and per-run binary output.

Before executing, read the selected version's local help and the exact template/input.
Recover current Scope/Auth and apply `rules/ccst/red-lines.md`. Native shell execution
uses platform permissions; artifact registration is not a network sandbox. Filter
initial inputs to the current target set, constrain redirect/recursive expansion and
credential replay, and preserve external associations as unverified context.

Use canonical target keys, not a method name as the target:

```bash
TARGET_KEY=$(python3 -c 'import sys; from tools.target_paths import target_storage_key; print(target_storage_key(sys.argv[1]))' "$TARGET")
umask 077
mkdir -p "findings/$TARGET_KEY/upstream"
RUN_DIR=$(mktemp -d "findings/$TARGET_KEY/upstream/run.XXXXXX")
```

Save selected inputs, original output, stdout/stderr, exit code, command arguments,
version and source/template/revision hashes in that unique run directory. Keep secret
values private and cite references in public summaries. Interpret exit status using
upstream semantics: findings-present can be a documented nonzero result, while
missing tools, transport failure and incomplete inputs remain separate. Empty output
never proves target safety. Do not suppress failures, install automatically or replace
a missing tool with local pattern verdicts.

Native review promotes a supported hypothesis through existing Candidate, observation,
assessment and report owners. A capture receipt, scanner result or list of inputs
creates no Finding, Action completion, Coverage closure or report automatically.

The retained integrated scanner is an optional bounded execution convenience:
`findings/<key>/nuclei_runs/<run-id>/` keeps exact inputs, raw JSONL, logs and receipts;
latest `summary.json` explicitly records status and unfinished origins. It does not
produce category×endpoint scanner-pass records. Historical raw artifacts and old
scanner-pass/secret/CI files remain unchanged for explicit review.

---

## Maintenance

When adding a new `tools/*` script:

1. Add a row to the appropriate category
2. If it covers a previously untooled attack class, add a "Quick-pick by symptom" entry
3. Keep description ≤ 80 characters
4. Don't list test fixtures, `__init__.py`, internal helpers

When retiring a wrapper, migrate active callers, prompts, installers and artifact readers before removal. Keep history in task notes rather than executable index rows.

---

## Related References

- `rules/ccst/hunting.md` — canonical hunt semantics + lane routing
- `rules/ccst/tool-ai-boundary.md` — AI judges, tools preserve evidence
- `commands/autopilot.md` — autonomous loop execution contract

## Execution Contract Lookup

Read only the owner needed for a selected action, not this entire table as a checklist.

| Question | Owner |
|---|---|
| Automatic continuation, checkpoint cadence and stopping? | `commands/autopilot.md#shared-automation`; capped or inherited Round mechanics in `commands/autopilot-round.md` |
| Which hypothesis to continue, rotate or stop? | `skills/src-hunter/SKILL.md` |
| Context and complete method reading? | `skills/runtime-protocol.md#shared-knowledge-recall` |
| Recover current target facts or recall a prior problem? | `skills/runtime-protocol.md#shared-memory-continuity`, `skills/runtime-protocol.md#problem-recall` |
| When to save accepted cognitive deltas? | `skills/runtime-protocol.md#cognitive-write-timing` |
| Target memory commands, handoff and corrections? | `commands/target.md#命令`, `commands/target.md#交接与证据`, `commands/target.md#版本来源与纠错` |
| Dependent session/process/socket continuity? | `skills/runtime-protocol.md#stateful-continuity` |
| Raw evidence versus AI judgment? | `rules/ccst/tool-ai-boundary.md` |
| Candidate validity and report readiness? | `skills/src-hunter/modules/triage-validation.md`, `commands/validate.md` |
| Side effects and stop controls? | `rules/ccst/red-lines.md` |
| Who accepts a write? | `skills/runtime-protocol.md#5-execution-and-write-back` |
| Capture originals, consume receipts or recover a failed registration? | `docs/evidence-runners.md#在执行时捕获原件` |
| Register observations without a Finding or evidence for an existing Finding? | `docs/evidence-runners.md#native-observation-registration`, `docs/evidence-runners.md#native-evidence-registration` |
| Claim/resolve or browser import and session close? | `docs/autopilot-lanes.md#state-and-queue`, `docs/autopilot-lanes.md#browser-source-and-js` |
| Existing executor for the chosen action? | Categories and symptom lookup in this index |
