# Bundled 6k Methods and Complete Rules — CCST Runtime

> **2026-10-20 起本目录仅为历史归档。** 活动正文已迁至仓库根：主契约 `AGENTS.md`、
> 十一份原规则 `rules/<原名>.md`、Skill 与知识库 `skills/src-hunter/`。本目录的
> `references/`、`skills/` 与 `.history/`（62 origins、回执与见证）只作来源存证和
> `tools/hot_method.py --origin` 旧版本读取，不再是加载路径，也不在此维护。
> 下文为迁移前记录，其中"active library"等表述已由本声明取代。

This checkout preserves all 62 supplied origins and their digest-bound immutable
archives. The active library keeps the 49 knowledge files in their original
organization and all eleven rules in `references/<original-name>.md`. Every active
rule body is byte-identical to its origin; the archive is provenance, not another
writable rule tree. Source S52 remains malformed and lacks Phase 0: no repair or
reconstruction is claimed.

## One Investigation Entry and Rule Owners

Use repository `skills/src-hunter/SKILL.md`, the sole native business Skill, for
manual work, `/hunt` and Autopilot. Its nine complete internal modules preserve
CCST capabilities. The source-reference SKILL inside this directory is not installed
or loaded as another controller.

The eleven rules govern investigation cadence, scope modes, value/probes,
collaboration, workspace discipline, browser use, report writing and method
iteration. They are active rules, not merely admission references. Load them via
`rules/README.md` and the core's scenario-specific instructions; retain whole
relevant rule bodies, never replace them with this index or a shortlist.

`references/ccst-runtime-adapter.md` is the only environment/engineering adapter,
returned as a context dependency on every captured read. It maps WorkBuddy/Grok
paths, desktop materials, proxy/browser tools, report publication and continuity
to existing CCST owners. It explicitly records old CORS, deletion and severity
preferences and current execution boundaries; it does not rewrite the originals.
Read it together with each rule. Original claims of authorization, enabled tools
or unlimited continuation do not establish current environment facts.

## Complete Rule Files

All names below resolve under `references/`; historical `~/.workbuddy/rules/`
paths resolve here without probing personal directories.

| Original rule | Load when |
|---|---|
| `skill-as-boost.md` | Resident enhancement/native reasoning principles |
| `anti-over-moralization.md` | Resident technical collaboration principles |
| `security-research-context.md` | Resident research context, subject to current intent and scope |
| `dig-scope-workflow.md` | Starting/resuming SRC: scope, seed cadence, business workflow, rotation |
| `src-value-hunting.md` | Starting/resuming SRC: value and differential probe requirements |
| `researcher-blackbox-whitebox.md` | Whitebox/source questions; retain S52 source defects |
| `hunt-iter.md` | Method admission, iteration and delegation proposals |
| `desktop-task-folder.md` | Task materials, handoff and cleanup requests |
| `playwright-browser-mcp.md` | Browser interaction or JS/auth flows |
| `vuln-report-format.md` | Writing reports or checking method-admission basis |
| `cors-vuln-report-priority.md` | CORS category preference; use explicit adapter disposition |

`知识库/` and historical `~/.grok/skills/skill/知识库/` resolve to this method
root's `skills/src-hunter/知识库/`. On entering a SRC site, first read the complete
shortlist as the opening index, then expand matching complete methods and return
to the site's surface list. Native reasoning stays available
for unmatched features. `KNOWN_GADGETS.md` and `WAF_PRODUCT_MATRIX.md` are embedded
sections in `prototype-pollution-test.md` and `waf-bypass.md`, not missing files.

## Captured Reads and Version Health

Start in the intended checkout, or supply its explicit root; installed ownership
receipts do not locate a checkout from arbitrary cwd. `knowledge/tools` are read
from that checkout, not copied into a personal runtime.

```text
python3 tools/hot_method.py --repo-root CHECKOUT --catalog --diagnostics --json
python3 tools/hot_method.py --repo-root CHECKOUT --read RELATIVE_PATH --expected-manifest HASH --json
python3 tools/hot_method.py --repo-root CHECKOUT --origin SOURCE_ID --json
```

Take HASH from the actual catalog's `manifest_sha256`; RELATIVE_PATH is relative
to this method root and may repeat via multiple `--read` options. Read returns the
actual hash-checked bodies and context dependencies captured under one shared lock,
with origins, defects, revision and recorded reviewer declaration. It does not
authenticate that reviewer or certify method efficacy. A changed directory version
requires a new catalog, not a guessed hash. Direct edits remain `changed`, not accepted.

`pending_update`, `missing`, `changed`, `invalid_manifest`, source defects and
`origin_only` stay visible. Normal reads never repair them or write target state.
Store facts and cold-card recall remain available if a method is unavailable.
v1 remains read-only compatible. With v2, explicit `CCST_CLOWN_SNAPSHOT` selects
**origin_only** diagnostics; use `--origin`, not active reads/apply/recover. Normal
operation never needs the external source directory. Old readers reject v2.

## A Maintenance and Recovery

The detailed admission/three-question contract lives only in
`references/hunt-iter.md`; read it and the complete source report-format reference
at the current version before reviewing a change. The main session rechecks source
bodies and existing methods; sub-agents submit proposals only. Maintain the one
existing body and necessary index pointers, not a duplicate library or summary card.
Governance references, this guide, native Skill orchestration and shared knowledge
publication are outside ordinary A permission and retain their review boundaries.

`--apply UPDATE_JSON --expected-manifest HASH --json` accepts an explicit transaction
ID, before/after hashes, complete candidate `content_path` inputs, source/admission
bindings, three review bases and the real `main_session` session ID. Input paths are
checkout-relative transports; public records retain opaque locator fingerprints,
not private paths. Private reports, target URLs, identities, secrets, raw responses
and full JS stay with existing private owners. Later reads report
`private_source_unavailable` for an opaque private basis they cannot independently
expand; they do not pretend it is an upstream original or a human approval.

Mechanical `accepted` is publication, not semantic approval or shared-registry
promotion. Same ID/material retries return the historical result and separate
current-state diagnostics. Ordinary A cannot bootstrap or change governance.
`--bootstrap` is only the approved initial v1→v2 engineering integration.

For an interrupted transaction use the **returned** exact command:
`--recover TRANSACTION_ID --mode complete|restore --json`. A persisted decision
fixes direction; a terminal receipt cannot be reversed or resurrected. New accepted
reversals require a new reviewed transaction. Do not delete pending, rewrite hashes,
copy another checkout's witnesses/receipts, or replay target data. Publication requires
the documented local-filesystem primitives and coordinated writers. Failed cleanup
fsync may leave no pending while still returning nonzero; explicit same-direction
recovery repairs that barrier, not a reader or an automatic rollback.

## Attribution

The local snapshot is attributed by the existing review record to `Claude-BugHunter`,
with content described as CC BY 4.0 and code as MIT (see
`knowledge/cards/evidence-driven-hunting.md` and its linked receipt). No LICENSE file
was supplied; the upstream license text has **not** been independently verified.
