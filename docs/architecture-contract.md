# Claude-Native Architecture Contract

This is the authoritative target architecture for the Linux-first, single-operator
Claude Agent enhancement layer. The approved refactor replaces the former
file-format/CLI compatibility constraints; it does not build another Agent runtime.

## Implementation and Cutover Status

The native-first refactor was completed and archived on 2026-09-26. Ordinary
domain readers and writers require the existing `TargetStore`; uninitialized,
legacy, preview or damaged state fails visibly instead of selecting a retired
backend. `/autopilot`, `/hunt` and the explicit Store init command own fresh initialization.
Case, Action, observation, assessment, delivery, report and saved experience
retain separate responsibilities in that single database.

Historical target cutovers and PatternDB/profile imports require explicit,
source-bound operations; repository changes do not migrate real data or install
runtime assets. The archived task records consumer/recovery acceptance. Online
model capability gains remain unproven; engineering completion does not establish
them. The subsequent practical audit and its repairs address concrete integration
defects without reopening the architecture or changing these evidence boundaries.

The Action adapter preserves descriptive producer type/source and material/reading
references separately from Store kind/status. Parameter-discovery and spray primary
consumers publish immutable review snapshots before creating pending work; they do
not turn scanner dispositions into action completion. OAST poll/stop append linked
handoffs without confirming findings or reopening/closing actions. Legacy data is
available only through explicit historical inspection, import and recovery.

`tools/evidence_identity.py` already owns the shared vocabulary and endpoint
normalizers. Ledger and native evidence registration accept valid open-ended
families; canonical Coverage mapping remains optional and unknown labels cannot close it.

## Single Runtime and Explicit Initialization — Target Contract

- Normal domain commands and queries use the existing `TargetStore` only.
  Legacy data is available through explicit import, historical inspection and
  recovery, not a missing-database fallback. A real empty initialized Store may
  return an empty page; an absent, damaged or inactive Store must not impersonate it.
- Retain one initialization primitive, `initialize_target_store(repo_root, target)`,
  exposed by `python3 tools/target_store.py init --store --target TARGET`.
  A fresh target is created; an active target is returned idempotently; legacy,
  preview and damaged/fenced-missing targets are refused without implicit migration.
- `hunt_target()` invokes that primitive as the explicit start-target operation,
  after input/scope/auth checks and before target execution or artifact side effects.
  Autopilot Bootstrap invokes it for a single target after argument, Scope/Auth/context
  and critical runtime checks, before state reading and Round prepare. Existing
  primary targets retain their identity and facts; rejected legacy/damaged targets
  are never migrated or recreated by startup.
  Lists initialize each actual target at execution time, not during list parsing.
  Other domain entry points must either be explicit creation operations or require
  initialization. Ordinary writes, queries, checkpoint/resume and previews never
  create a Store or silently select legacy.
- Store identity/role/schema/fence/receipt checks have one low-level owner.
  `runtime_store()` returns a valid Store or raises; it never offers `None -> legacy`.
- Keep internal `primary/preview` roles, durable fences and migration receipts
  where needed for integrity and recovery. Removing business backend branching
  does not justify renaming the database schema, deleting markers or creating a
  new TargetRuntime/repository/backend-driver abstraction.
- Delete obsolete runtime writers and compensating algorithms only after their
  useful behavior works through the remaining owner. Raw evidence, private
  material, rebuildable projections and resource locks remain outside this
  metadata-retirement operation; their JSON format is not grounds for deletion.

## Responsibilities

```text
Claude native reasoning / planning / tool use / context
    |-- on-demand Skills / Rules / Knowledge
    |-- native tools or deterministic executors -> raw evidence files
    |-- explicit domain commands -> per-target transactional metadata
    `-- read-only queries <----------------------'
                  |
        Context / candidates / Coverage / reports / handoff views
```

Claude chooses hypotheses, routes, priority, test inputs, interpretations, and
whether to investigate a chain. Project tools enforce mechanical constraints,
preserve evidence, and expose facts. URL words, family labels, object labels, and
hint counts must not substitute for business-value judgment. There is no new
Planner, Controller, model loop, automatic chain generator, or session manager.

Autopilot is an automatic execution mode, not a second investigation workflow.
Manual and automatic entries share `skills/src-hunter/SKILL.md` as the only native
Skill, its complete problem-scoped internal modules, the memory protocol, Rules and owner APIs. Autopilot adds continuation, waits, explicit-limit handling, read-only checkpoint cadence and handoff;
it does not own different finding, evidence or report standards. Shared execution
contracts are read on demand and never enable automatic continuation by themselves.

Skills provide methods, applicability conditions, counterexamples and evidence
requirements, not fixed test sequences or duplicated native tool manuals.
The native platform owns Skill discovery. Natural-language discovery retains the
original `src-hunter` description. Explicit Autopilot receives complete original
source bodies through `autopilot_host`; independent static parts and one Bootstrap
share the installed source contract. Static delivery is not execution admission.
`autopilot_host state` combines loop-check, Scope/Auth and prompt-bound rearming;
same-session continuation reuses context and admitted argument paths without Bootstrap/init.
Completed bindings stay inactive until the latest user prompt explicitly continues the
same task and its state command succeeds. Reopening renews only the invocation identity
used by Stop reviews; it retains entry time, limits, arguments and target facts.
SessionStart restores completed context without granting continuation by itself.
After compact/restart, SessionStart restores bodies and state adds owner/memory recovery.
Source/recovery failures suspend enforcement. The small
private session binding and source snapshot own no target progress or facts.
Oversized Bootstrap is delivered through a private JSON file; it is transport, never a state cache.
Normal Stop reads current owners and the existing Checkpoint review's optional
termination (reason, session_id, invocation_id, boundary; explicit_limit additionally
names an elapsed-seconds threshold or capped Round owner). The host measures elapsed
time from the preserved invocation start and reads the current Round owner; it does
not infer thresholds from prose or fabricate cost receipts. The optional explicit
time threshold and applicable Round limit are bound at entry; an ending review
cannot shorten them or borrow a prior completed Round. It checks unfinished
execution and known owner work; Closure alone retains exhaustion meaning. A repeated
unchanged rejection suspends as incomplete. New user prompts suspend enforcement;
only an explicit same-task state refresh rearms it, and native interruption needs no review.
Claude decides intent; ordinary questions/cancellation/task changes stay suspended.
Decision views carry the current Store goal even on ordinary refresh. Review basis v3
binds that goal in Closure state, independently of handoff/history presentation;
changing or clearing the goal invalidates a prior review without binding every memory note.
General state/memory queries remain read-only and independent of host bindings.
Running Recon/Scan keeps independent owner work visible; only dependent work waits.
A valid stop review retains its termination when residual-token form is incomplete:
scope/limit/global-blocker exits remain possible without claiming exhaustion.
Internal modules and knowledge remain problem-scoped; ordinary natural-language
work uses Skill or complete native reading under the shared runtime protocol.
Queue/Store do not require
Skill routes, inspect Skill files or prescribe method dimensions. Knowledge cards
retain `tools/knowledge_registry.py`; Context Pack adds no second registry.

Cached JS and source are read through native Read/Grep, without materials, reader
wrappers or local cognitive extractors. Live `/intel` retains its independent
advisory/version/provider/freshness contract. Observation residuals can prevent
an exhaustion claim without creating a mandatory next action; the current
session can end while keeping those residuals visible when the entry's stopping contract is met.
Handoff preserves continuity; it is not by itself a stopping reason. User/scope/explicit-limit boundaries,
actual blockers or evidence-based investigation judgment decide when to stop, not report counts or
automatic coverage enumeration. Both Autopilot modes consume fresh post-action state.

State acquires owner facts; `autopilot_gate` builds their continuation projection once.
Legacy action tokens, compact views and lane hints derive from that projection;
multiple owner items remain available for Claude to choose. Closure keeps its own
evidence verdict and shares only the reason-to-continuation rendering. Empty owner
work returns `continue_investigation`, with `run_recon` as the empty new-target default
under Shared Automation, not a prerequisite for existing evidence. Round retains
claims, optional explicit lane caps and recovery under the same Autopilot loop.
Neither mode assigns a default whole-investigation time, cost or lane budget.
Per-operation timeouts, rate limits and review allocations remain local execution bounds.

Recon's Shell owns execution, rate/time bounds, workers and raw-file lifetime.
Its FFUF phase runs synchronously while retaining bounded per-origin workers;
root and www stay distinct. Existing ReconAdapter, target selector, candidates and
gate modules own parsing, collection accounting, source navigation and manifest
publication respectively. Raw publication and a valid summary precede collection
progress. Read-side health checks do not publish or repair producer state.

The dedicated request-diff execution lane, request-pair parser, response-diff
module and `probe.py` request/ledger wrapper are retired. Native execution uses
browser, curl or a suitable raw sender; evidence/observation registration and
historical pair/probe material retain their existing owner contracts. Shared HTTP
`request_once` remains for parameter discovery and explicitly bound continuation
calls, enforcing child/parent Scope before initial and redirected requests. It
returns raw fields without saving or registering them. Native platform tools
require their own execution boundary; registration does not constrain their I/O.

### 6k-original Entry, CCST Engineering Base

The complete 6k method and capability contract lives inline in `CLAUDE.md`, which
imports all eleven `rules/<original-name>.md` files and the CCST integration overview.
Active instructions use the current checkout paths, host-visible tools and domain owners
directly. `skills/src-hunter/SKILL.md` preserves the methods and adds CCST integration;
source-byte preservation applies to the historical originals, not obsolete host instructions. Its `知识库/` holds the 49
original knowledge files with separately identified additions. Nine complete
`modules/*.md` resources retain recon, whitebox, credential, triage, reporting,
CI/CD, mobile, Web3 and token capabilities without extra Skill registrations.
CCST engineering rules live under `rules/ccst/`.

Read native Markdown directly. SRC starts from the original shortlist and expands
matching complete methods, while preserving exploration beyond that index. Context
Pack reads target facts, evidence and the reviewed-card catalog; it does not scan
historical methods or emit `hot_methods`. Method updates follow the complete
`rules/hunt-iter.md` admission and source review, edit the selected checkout
`skills/src-hunter/知识库/` and necessary indexes directly, and retain the diff in Git.
Installed copies are reading assets, not another writable method source. No catalog, manifest or hash reader
is required for normal method use.

`knowledge/index.md` links to the native shortlist and full method directory; the
Skill points back to that index for CCST experience and cases. Each existing body
keeps its path and maintenance owner. Directory consolidation, registration of all
native methods and topic deduplication are deferred until the explicit capability
comparison demonstrates a useful change. Native reading does not require review
admission; shared recall and knowledge-backed projections keep that distinction.

`rules/desktop-task-folder.md` owns current artifact paths and cleanup,
`rules/playwright-browser-mcp.md` owns host-visible browser calls, and
`rules/vuln-report-format.md` owns report prose and publication requirements.
`docs/ccst-runtime-adapter.md` summarizes their connection to target and evidence owners.
Engineering rules preserve persistent project preferences (including the default SRC
CORS exclusion) and explicit user overrides; target history does not invent preferences.
Startup and recovery follow the command entry and Shared Memory Continuity, without
an extra directory-rule init/set/show sequence. Known-target calls carry the target
explicitly; changing the shared active pointer is optional and is not a recovery prerequisite.
TargetStore owns domain facts and cognitive handoffs; Runtime, checkpoint, batch
continuations and Coverage retain their own interfaces rather than all becoming SQLite state.
Work notes are optional and use distinct work-item/thread paths. Real delegation
returns iteration candidates and source refs under `hunt-iter`; pending candidates
survive pause/switch/compaction through existing memory and handoff owners.
Temporary notes, matrices and campaign seeds cannot become another target lifecycle owner.
Campaign seeds retain cross-target discovery progress and references to established targets.
The original rules own investigation cadence and default SRC
prose; CCST retains Scope/Auth, claims, observations, cleanup and publication owners.
Explicit Autopilot integration follows `docs/ccst-runtime-adapter.md`.
The original S52's missing Phase 0 and other source defects stay visible. Browser
and FOFA support assets are in `bin/` and `mcp-servers/`; their presence does not
configure or enable an MCP host. Original Grok user guides are source material under
`docs/user-guide/`, with their host applicability stated separately.

`knowledge/methods/clown/`, its manifest and `.history` retain earlier source bytes,
versions and receipts. `hot_method.py` remains available for explicit historical
reading, maintenance and recovery, including the original narrow migration
protocols. It cannot publish current native Markdown and is absent from normal
Context/Checkpoint and installation prerequisites. Historical approvals and reviewed
knowledge are not rewritten to make the new layout look previously accepted.

Historical knowledge `related_skills` and reviewed bytes keep their review identity.
`skill_reference_contract` supplies exact current reading navigation, shared by
registry/audit and installer identity checks; unknown/missing references fail. It
neither registers old Skills nor changes ranking, target basis or Store schemas.

New/empty automatic targets without prior work or usable supplied evidence start
with Recon under the shared entry contract; supplied evidence can start directly.
Missing Recon on existing targets, zero live hosts and collection residuals do not choose an investigation
route or hide Queue/Finding/Runner work. Valid collection continuations are optional;
invalid cursors remain non-runnable. Real locks, Scope/Auth/parent scope, claims,
unknown-effect recovery and cleanup still bind execution. Partial/remainder facts
and review references survive full/bounded/loop/compact views and forbid false
exhaustion. Low priority and budget stops are not technical refutations.

### Business-tool retirement and native execution

Business CVE/takeover/cloud/secrets/org-CI wrappers and static token grading
are retired. Wordlist preparation, employee OSINT and EBurst remain optional
helpers for bulk operations, source normalization and bounded upstream execution.
Wrapping an upstream tool alone is not a retirement criterion. Native `src-hunter` and the model
choose methods and optionally invoke mature upstream CLIs directly; retained
helpers supply concrete acquisition, parsing, protocol, evidence or recovery value.
No new controller, mandatory tool sequence or static assessment owner is introduced.

Source acquisition captures explicit source and workflow originals with byte hashes,
revision context, bounds and partial diagnostics; secret/CI analyses stay `not_run`.
Explicit scanner execution preserves bounded Nuclei input/raw/exit/run receipts
and summary-reader residuals, including failure and missing-tool states. It does
not create Finding, Action or Coverage records or infer a scanner pass from old files.
Recon batch inventories retain completion order and source counts; cached CI links
are unverified source references. Historical evidence is retained. Store/schema,
Scope/Auth, evidence identity, memory, report and recovery owners remain unchanged.
Personal installation and host/live acceptance remain outside this repository change.

## Domain Facts and Ownership

| Concept | Durable meaning | Not its responsibility |
|---|---|---|
| Action | One intent, explicit claim, progress and blocking reason | A second Case backlog or computed business ROI |
| Execution attempt | A particular real execution, source and action association | Merging real executions because their bytes match |
| Registration / observation | Published input/output references, order, time, errors and completeness | Automatically confirming a vulnerability or closing an action |
| Finding / technical assessment | A claim and an explicit evidence-linked boundary/impact judgment | Destination eligibility or payment policy |
| Delivery decision | Eligibility for one destination, with reason and assessment binding | Rewriting technical validity |
| Case context | Actors, objects, tenant/workflow conditions and private session references | Another execution lifecycle |
| Conditional experience | Preconditions, failures, reopening conditions, primitives and next intent | Duplicated finding state or automatically created tasks |

Each logical owner has explicit domain commands. Sharing a physical database
does not permit consumers to UPDATE another owner's guessed lifecycle fields.
Registration, assessment, delivery decision, delivery event and action resolution
are separate commands. A generated report artifact is not an external submission;
submission receipts are appended only by an explicit delivery-event command.
Known, duplicate or accepted-risk issues do not automatically become technically
refuted. A valuable report claim cannot make unsupported evidence valid.

## Storage and Transactions

- One SQLite database per target: `state/<target-key>/metadata.sqlite3`, using
  standard-library `sqlite3`, explicit tables, foreign keys and indexes. Identity,
  relations, lifecycle and query keys are columns, not an arbitrary JSON store.
- Action context uses one bounded `metadata_json` detail on the Action row. It may
  carry AI-authored hypothesis, experimental dimension and evidence references, but it
  cannot carry Runner-owned observations or become an execution/assessment/delivery
  owner. Claims merge it through the action version/CAS; hypothesis caps and
  target-owned evidence/card references are enforced before mutation.
- Legacy writer admission binds the actual destination owner and runs inside the
  shared target switch lock. Explicit target/output overrides cannot redirect a
  different owner's files. Runner summaries bind target/backend/store generation;
  preview execution and report publication reject before generated artifacts.
- `runner_candidate_review` owns per-summary review-consumption receipts, not Finding judgments.
  Explicit closure binds the caller-reviewed summary hash and complete artifact material; changes
  invalidate that closure. Reopen preserves history and never alters assessment or delivery.
- Store schema v18 adds explicit `dispose_finding` for mistaken unbound claims only. Withdraw/reopen
  appends a predecessor-bound disposition; optional replacement names another active same-Store Finding.
  Evidence, assessment, Action or Coverage-review bindings refuse this operation. Original claims/history
  remain readable; active follow-up excludes withdrawn candidates, and new linked work requires reopen.
  This is not technical refutation or withdrawal of an existing assessment/report. Older Stores remain
  readable; the new command requires an explicit backed-up upgrade, never an automatic migration.
- Checkpoint owns report lane bindings and append-only evidence corrections. Shared witness readers
  verify the exact registered report identity and intact authorized bytes; original terminal results
  and budgets remain immutable. Report staleness alone does not erase historical production proof.
- Database identity binds target, schema version, store instance and revision.
  Missing, corrupted, foreign-target and unsupported-version stores fail visibly.
- Writes use short transactions. Registration publishes operation, observation,
  artifact bindings, optional finding links and audit together or none of them.
  No network call, model invocation or large file hash runs inside the transaction.
- Repeating a command is idempotent only for identical content and identity.
  Changed content under the same command key is a conflict, not last-writer-wins.
  Claims and judgments use explicit expected versions/previous judgment IDs.
- A new execution gets a new attempt ID. Additional recovered evidence can revise
  the registration of the same attempt by explicitly referencing the prior
  operation; old operation records remain intact. Unknown effects are not a
  request to replay the network action.
- Raw requests/responses, screenshots, HAR, JavaScript, source and report bodies
  remain files. Publish files first, then register metadata. Failure retains raw
  files for registration retry; missing or changed registered evidence is an
  integrity error, never empty history.
- Scanner-pass output, source-hunt bundles, technology/intel artifacts and their
  bounded review files are raw-material or rebuildable projection outputs. Their
  explicit producers may write them for a primary target, but those writes never
  advance Store revision, create findings, close Coverage, or replace an
  observation. Producers bind the target and publish atomically; missing, stale,
  or corrupt output remains an explicit refresh/review state.
- Artifact identities are immutable. Availability and provenance changes are
  append-only artifact events; authorization is derived from the latest event and
  an explicit fresh byte/hash validation. That source-acquisition step captures
  the checked digest, health result and one `as_of` value for the ensuing closed
  projection snapshot; a projection itself does not read the live filesystem or
  clock. Invalidated or revoked material remains historical evidence rather than
  being rewritten as absent.
- Observation envelopes use a closed relational head for target, operation,
  timestamp, actor, outcome, family and artifact bindings, with only a bounded
  canonical `detail` object open for extension. Queries never infer relationship
  keys from `detail`.
- Protect database/files and credential material with restrictive permissions.
  Session secrets stay in private files; metadata stores references, not headers
  or tokens. Public projections/exports need an explicit redaction boundary.
- WAL and `synchronous=FULL` target local filesystems, not network shares. Read-only
  connections use query-only snapshot transactions; SQLite may manage WAL/SHM
  bookkeeping, but queries never mutate domain rows. Backups use SQLite's backup
  API, not a copy of the main database while WAL may contain newer writes.
- SQLite does not replace process/resource locks, enforce all native tool usage,
  make files and network requests transactional, or prove semantic correctness.

## Query, Coverage and Memory

Queries do not create actions, submit judgments, reconcile owners or refresh
canonical state. Rebuildable caches may be refreshed only through explicit
operations. Primary Surface may derive recon component inventory in memory, but
must not publish inventory, probe logs or observation summaries as a read side
effect; retired metadata is not a runtime fallback. Primary
Checkpoint construction publishes neither witness nor Coverage cache. Primary
round settlement closes the runtime round explicitly without old root-claim/Queue
coordination or implicit Surface refresh.

Primary Coverage is rebuilt in memory from current truth. Historical matrix cells
and scanner advice do not authorize closure, and merely storing a Finding does not
make it tested. Exact terminal dispositions share the existing closure resolver;
query/hash/v2 evidence is not widened to a whole endpoint. Its source snapshot
includes reference time, Store/operation identities, evidence health and discovery
inputs. Primary Context Pack explicitly reacquires current owners and validates
needed artifacts because a stable Store revision alone cannot prove external
artifact integrity. The captured validation results and `as_of` are included in
the Pack binding; projection rendering uses those inputs only.

Primary report bodies are immutable, with identities bound to the Finding and
current assessment/delivery. INDEX/SUMMARY are rebuildable snapshots carrying the
Store binding and as-of boundary; drift before publication fails visibly. A retry
preserves registered bodies, and a stale or damaged report leaves the current index
without deleting history. None of these operations imply external submission.

Bounded queries report ordering, scope, exact remainder or explicit unknown,
and expansion references. Cursors bind target, store instance, revision and filter;
stale cursors fail instead of silently skipping or repeating a changed dataset.
Canonical Coverage and Closure share identity/interpretation rules. Unknown family
labels preserve observations but cannot close canonical cells. A projection is not
a second authority for technical finality.

## Memory Contract

Memory is retention and recall of the same facts, not another lifecycle system:
raw observations remain expandable; Claude's working context is disposable;
target experience retains conditions and evidence links; cross-target knowledge
is sanitized and reviewed. Primitives need not have continuation hints to remain
queryable. A negative result applies to its recorded conditions, not forever.
No background extraction, automatic task-per-primitive, or extra vector service
is added. `hunt-memory/targets/<target>.json` remains a legacy read projection and
must not acquire new duplicate finding, coverage or action truth.

SQLite owns authoritative structured target facts and only explicitly saved,
decision-relevant target experience. It does not accumulate every observation,
chat, model reasoning trace, raw response, report body or temporary Pack/
Checkpoint; raw artifacts remain files behind references, and cross-target
knowledge remains reviewed Markdown/registry content.

| Responsibility | Authority and lifetime |
|---|---|
| Original facts | Store domain relations and external raw evidence; observation, assessment and delivery remain distinct |
| Working context | Bounded, disposable Context/Checkpoint/Resume views with expansion references; never a write-back source |
| Target experience | Same-Store intent, advisory notes, conditional experience and provenance; no duplicate Action/Finding lifecycle |
| Cross-target knowledge | Existing sanitized, reviewed Markdown cards and registry; not automatic sharing of private field memory |

These are information responsibilities, not four stores or new services.
Mechanical evidence/receipt registration and terminal owner work remain immediate.
Cognitive consolidation is event- or boundary-triggered: stable conclusions,
counterevidence, changed conditions, path decisions, or pause/target switch/compaction/exit.
Ordinary observations, Skill reads, mode changes and checkpoint cadence do not
require another note, business-model rewrite or result form. The shared timing
contract is `skills/runtime-protocol.md#cognitive-write-timing`; live comparisons
stay in working context, recovery intent remains explicitly bound in the handoff,
and cross-target promotion remains reviewed. Manual hunt reuses the investigation
core instead of imposing a scanner or a second ordered loop. Coverage/Closure at
finish and actual claim/receipt/heartbeat obligations are unchanged.

The model-facing paths are recovery, problem recall and cognitive write-back.
Runtime-protocol owns timing; commands/target owns memory CLI, handoff and
correction operations; evidence-runners owns capture/registration. Command and
agent entries reference these contracts rather than maintaining alternative
write schedules. Before relying on history or repeating work, missing evidence
or changed conditions triggers problem recall and counterevidence review.
Sufficient current material is reused; no per-request classification/fusion cycle
or new memory controller is added. Recovery entries preserve their exact Store
version so their independent counterevidence can be expanded without another
latest-version lookup.

Normal memory commands, Python APIs, default text and JSON must use one domain
meaning. `target_memory.py` remains a thin interface; `show` must read the same
Store that accepted the write. `set TARGET` selects an initialized target only;
an explicit `--goal` changes that target's Store-owned intent. Retired mode,
phase, hypothesis, skill and knowledge flags must be routed to their real owner
or rejected, never copied into active-target state. Target intent has one
explicit current-value owner in the existing Store row; scope notes do not
change authorization, runtime phase stays with its runtime owner, and the
active-target pointer contains target selection metadata only.

The Store singleton owns `active_goal`; Experience supports advisory notes and
condition-bound negatives/primitives. Schema v17 retains exact historical experience
versions, source bindings, explicit supersedes/refutes/depends_on links and
append-only link withdrawals. Sources distinguish origin from basis; origin is
not supporting evidence. Material health and dependency invalidation propagate
without rewriting historical judgments or reviving a superseded conclusion.
Accepted relational claims retain exact endpoints and sources, remain advisory,
and cannot mutate Action/Finding/delivery. No execution is fabricated for notes.
Negative/primitive evidence requirements remain. Ordinary calls never upgrade a
Store; the explicit upgrade retains v12/v13/v14/v15/v16 development paths. Claims may additionally
bind named condition roles to exact same-Store entities and declare a timezone-aware
half-open validity interval. Missing declarations stay unknown; text is never proof
of compatibility. Entity changes propagate through the existing basis-health path.
Reviewed knowledge is an external source owned by the existing registry/publication
review. Its version is the publication receipt SHA256, separate from integer Store
versions; content binds the complete published Markdown. Knowledge and claim-source
attachments remain in the same Store. The shared publication lock and captured file
identities fence acceptance; hashing stays outside the write transaction. Revoked,
retired or changed basis propagates loss of support, while origin remains diagnostic.
Historical originals have an origin-only reader: `history_source(imported_id)`
binds the same Store's active migration manifest, exact import mapping and selected
original bytes. `full=True` expands the retained original and its metadata; byte
availability never promotes an unverified statement to evidence. Legacy memory
uses its bound archive, and explicit PatternDB backfill publishes immutable original
files under the target's `pattern-archive` before importing. Older completed receipts
can add the archive only by an explicit exact-source retry, without new Store writes.
Missing or damaged originals remain diagnostic; readers neither fall back to live
legacy files nor reconstruct original evidence from imported notes. History cannot
be basis or claim support. Receipt locks and file-identity fences protect acceptance;
the public read also rechecks target/store/revision after capture.
Corrections compare their explicit
scope with the declarations in both exact retained endpoint versions. Only three
identical known declarations affect the whole record; different or unknown endpoint
conditions retain a conditional connection without globally invalidating old advice
or its dependencies. This is not semantic or structured-identity equivalence.
Withdrawal retains the original challenge scope. Version/page/current views expose
the same derived applicability; no additional lifecycle state is persisted.

Current facts are read independently of historical ranking. `experience_recall.py
query` returns current/recalled/health/pagination; `history` expands the original
Store history cursor, which is not interchangeable with a query ranking cursor.
Target source acquisition loads the generation's disposable capture before asking
Store for an audit delta and its dependency closure. Only affected experience bodies
and relation owner groups are reassembled. Every referenced external source still
gets fresh owner byte verification; current facts remain independently acquired.
Semantic byte/health fingerprints survive restoration of identical originals, while
separate, ephemeral file-identity fences reject change-and-restore races during a
single acquisition, build or query. Fences are never persisted as semantic cache keys.
Text generations separate target history from the shared reviewed knowledge namespace;
unchanged source/model/chunking bindings reuse FTS rows and vectors. Shared knowledge
acquisition still performs a full owner audit, not incremental parsing. Target capture
reuse does not eliminate current-page reads, dependency metadata reads or byte probes.
Bounded output is not a claim of bounded source-read cost. Default text and JSON
preserve statement, conditions, reopening criteria, next intent and evidence/
source references. Pages identify ordering, filters, exact remainder or explicit
unknown, source health and usable query/ID expansion; a binary DB pathname alone
is not a readable continuation. Category scores cannot silently remove candidates
from the accessible set. Optional-source failure is visible, not a successful
empty result. Native reasoning still decides relevance and action.

Autopilot bootstrap preserves Resume's existing bound five-entry memory view and
separate current handoff; it does not wait for a filename search to recover intent.
The same owner queries refresh after target/context changes. Lists do not borrow a
member's memory, and advisory intent never overrides execution gates. Compact
experience anchors retain owner review state and exact expansion before bounded
detail; incomplete context requires expansion before use. Resume does not truncate
those anchors again. Text retrieval unions FTS and fresh substring candidates
before fusion/paging, so an index cannot hide a Chinese substring match.

Distillation's observation preview provides full operation-history navigation via
`target_store.py operations`; that ID-ordered cursor is not a continuation of the
chronological observation preview. Metadata pages mark artifact health unchecked;
ID expansion checks current bytes and preserves invalid historical references with
explicit health. Source-truncated preview counts remain unknown.

Legacy notes are mapped by evidence level: provably linked experience retains
its meaning; unsupported historical statements remain explicitly unverified
advice with their original type/source; corrupt, foreign or ambiguous material
has an inspectable quarantine disposition. Archive retention is not proof of
recall continuity. An already active target requires an explicitly authorized,
source-bound, idempotent supplemental import, not another cutover or rollback.

Working-context compaction never deletes the source. Projection echoes cannot
become new experience, and same-source retries are idempotent. Checkpoint and
explicit handoff are tested across repeated rounds and real process restarts.
Distillation reads the same Finding/Experience/Case semantics, including failure
conditions and contrary evidence; AI authors Markdown, then existing review,
audit and registry promotion control cross-target reuse. PatternDB, like the
legacy target profile, is history/projection rather than another final runtime
writer. Journal/audit history stays available on demand without becoming default
model context. No automatic long-term compaction or knowledge promotion is added.

`remember` commits experience through that same Store, then appends its audit
through `HuntJournal.append_once`. Optional journal `store_id/command_id` bind the
canonical target and command; no second receipt database is introduced. A failed
journal append retains the committed experience and returns a recoverable partial.
Identical-input retry fills a missing journal row without another Store mutation.
Deduplication covers retained live/numbered backups, not purged or unbound legacy
history; old bytes remain unchanged and that boundary is visible. Append, rotation
and explicit journal cleanup share the journal owner's sidecar lock.

Knowledge discovery is not review admission. `knowledge_promote` binds registry
`review_receipt` to immutable publication/review hashes and the explicit review
artifacts; `knowledge_review` is the shared reader. New and legacy recall adapters
use that same owner. Existing knowledge requires explicit byte-bound re-review;
no registration, maturity label or index build silently grants review. Publication
uses a knowledge-directory lock and compensating rollback, not a multi-file crash
transaction. Native manual reading keeps unreviewed status visible.

Surface advisory consumes the current bytes captured by that same publication
review reader, not a second read after review. Missing, changed or withdrawn review
material is an unavailable advisory with a reason; Surface facts and native method
reading remain accessible. Distillation text retains the target experience version,
review/applicability state, source health and exact correction/dependency references,
so disputed historical advice cannot lose its warning in a new draft.

Text and relation generations are rebuildable projections. Query never builds,
downloads, upgrades or changes owners. Real local encoder/reranker adapters require
explicit model directories and bound manifests; unavailable models are reported,
not substituted with hash vectors. Relation paths preserve edge sources, weakest
knowledge state and condition gaps; no path authorizes execution. Current indexes
separate target text and relations from their `.cache/knowledge-recall/` namespaces.
Reviewed frontmatter `method_relations` supplies shared pattern edges: both endpoints
bind active reviewed methods, exact content hashes and real heading anchors. Local
endpoints inherit their method hash, avoiding self-hash cycles. Audit and recall use
one pure declaration parser. Shared relation commands open no target Store; patterns
never become another target's facts. Per-source graph shards are reused or explicitly
rebuilt; target owner acquisition uses audit/dependency invalidation, while shared
method acquisition still audits the full source catalog. A build reports each partition
independently; an unavailable source does not replace a previous generation with
an empty one. Query remains read-only and uses fresh lexical originals on missing
or stale indexes, with explicit health. `--full-rebuild` repairs derived generations
without rolling back any owner. Claims use one pure `experience_contract` for
identity, predicates and condition/time declarations; relations do not redefine it.
Text and relation query results attach an independent `counterevidence` page of
exact retained corrections, dependencies and sources. Its cursor is not a ranking
or Store-history cursor. Oversized items retain exact expansion commands, correction
scope and withdrawal references, and mark context incomplete; repeated exact sources
are not independent support. Historical
peers and external bytes are rechecked, not replaced by the newest experience.
Model capability gains, default combination and release cutover remain unaccepted.

Target relation v4 also projects explicit Case actor/session/object associations and
Action-to-operation-to-artifact provenance. Nodes use Store identities; actual attempt
IDs and observation steps remain attached to edges. Display labels and actor/object
prose are not foreign keys. Experience paths and rejected owner sources contribute
exact-version counterevidence roots. Only target relation acquisition expands execution
owners into relation documents; ordinary text/current and shared queries do not.
Text dependencies may still verify referenced operations and their raw artifacts.
Captured external health is
part of the generation binding and is rechecked before publication/return, even without
a Store revision change. Legitimate empty collections are complete; damaged sources
remain partial, and canonical Store corruption fails explicitly. These associations
are not evidence of authorization, impact or simultaneous applicability. Old graph
formats require an explicit full rebuild. New target generations contain a digest-bound
`capture.json` with public documents, dependency descriptors, semantic probes and the
exact Store/schema/audit watermark, never current facts or private raw bodies. Old
generations without capture explicitly use full acquisition; corrupt captures are
unavailable, not silently trusted. Query/status never repair them. Watermark-only
advances publish a new capture without re-encoding unchanged projection sources.

Target-memory saves and knowledge publication/re-review can explicitly request
`--update-index text|relations|all` after the durable owner returns and releases its
transaction/publication lock. Target saves update only target projections; knowledge
publication updates only shared projections. No option means no index/model call.
Invalid options fail before mutation. Failed updates retain the committed receipt,
report `partial` in text/JSON and exit 2 with index-only recovery commands; they never
roll back the save or suggest repeating a non-idempotent publication. A relation
update with genuinely unavailable or challenged sources can remain partial after
rebuilding; repair or review the owner source rather than repeatedly saving the fact.

The task's M1-M8 gate covers save, restart, recall, expansion, recovery, historical
mapping, distillation and cost. Store unit tests, archived bytes or a migration
receipt cannot replace this consumer-level acceptance.

## Dependency and Trust Boundaries

```text
CLI / Claude-facing commands / execution adapters
                    -> domain commands and queries
                    -> domain identity / validation / sqlite3 / files
```

Domain code must not import Coverage, Checkpoint, CLI, or runners. Stable identity
functions live in `tools/evidence_identity.py`; target typing/storage keys remain
in `tools/target_paths.py`. Existing import re-exports are temporary compatibility,
not a second implementation.

Shared contracts and readers have explicit lower-level owners:

| Owner | Shared responsibility |
|---|---|
| `contracts` | Decision schema and bounded public observation validation; standard library only |
| `coverage_authoring` | Pure legacy Coverage author-draft and structural N/A classification shared by init/import; no Store or migration I/O |
| `experience_contract` | Pure exact entity, claim-predicate, condition-binding and explicit validity declarations; existence/health remain Store-owned |
| `experience_knowledge` | Read-only registry/review source capture and file-identity fencing; no index or target lifecycle writes |
| `experience_history` | Exact same-Store import-map resolution, original expansion and history-origin health; no import, repair or live-file fallback |
| `migration_receipts` | Strict receipt/manifest/archive readers, byte bindings and existing-state-directory receipt locks; no Store or CLI imports |
| `target_memory_schema` | Single legacy-memory normalizer and pollution vocabulary shared by import and memory CLI |
| `knowledge_relations` | Pure reviewed-method declaration, endpoint and heading-anchor contracts; no I/O or acceptance writer |
| `skill_reference_contract` | Finite retired identity vocabulary and exact current reading paths; no ranking, registration or target state |
| `claude_hook_contract` | Original-source capture, bounded Claude transport and owned hook settings; standard library and Skill path vocabulary only |
| `target_paths` | Target identity, resource locks and target-owned nonempty evidence references; no domain imports |
| `scope_context` | `url_belongs_to_target`, `target_list_entries` and Scope classification/publication; depends on target paths only |
| `browser_evidence` | Browser artifact references and readiness inspection; Runtime never imports the browser publisher |
| `resume_read` | Target/session queries; Resume CLI owns rendering and Checkpoint pickup orchestration |
| `artifact_io` | Ordinary UTF-8/JSON atomic file replacement; no domain validation or transaction ownership |

`tests/test_architecture_boundaries.py` enforces an acyclic tools import graph,
including function-local imports and direct-script fallbacks, plus foundational
dependency limits. Moving an import inside a function does not repair a boundary.
Scope consumers import matching from `scope_context`, not `target_paths`;
evidence consumers import admission from `target_paths`, not Action Queue internals.
Ordinary publishers share `artifact_io`; private material, Scope CAS, Store
fences, immutable snapshots and multi-file ordering retain their stronger owner
protocols. The shared writer provides file fsync and atomic replacement, not
directory durability, a cross-file transaction or read-modify-write locking.

Target pages, responses, JavaScript and logs are external data, including when
quoted by memory or an assessment. Hashes attest byte consistency, not truth or
instruction authority. Scope/Auth, side-effect rules, platform permissions,
executor checks and post-hoc registration have different guarantees; do not call
registration an execution sandbox or a semantic verifier.

## Migration and Retirement

1. Import isolated copies first. Preserve IDs, timestamps, provenance, raw hashes,
   unfinished work and private references. Map Case work to actions only through
   explicit associations; ambiguous links and corrupted/half-committed history
   are reported/quarantined, never silently merged or promoted.
2. Validate entity/relationship counts, evidence bindings and actual semantics.
   Do not reproduce historical bugs merely for byte-for-byte equivalence.
3. Cut over quiescent targets only after writers and consumers are connected.
   One writable backend per target; no permanent dual-write. Freeze old metadata
   as migration evidence and preserve original target artifacts. Runtime,
   coverage, unsafe-review and target-memory file mutations coordinate through
   the same target switch lock; primary/preview target-memory writes fail closed.
4. Retire old metadata writers, compensating sync, Case's second queue/ranker,
   duplicate closure reducers and obsolete compatibility algorithms after
   consumer migration. Retain a public name only when it is a useful thin Store
   adapter. Normal runtime must not import legacy writers or expose a switch
   that restores the old backend; unimported data requires explicit migration.
5. After new writes exist, rollback must export/migrate the current truth or fix
   forward. Pointing at stale pre-cutover JSON snapshots would lose progress.

## Verification and Evolution

Measure capability and efficiency separately: valid discoveries, verification
depth, coverage and evidence completeness alongside requests, Token use, latency,
I/O, Store/WAL size growth, backup/restore time and recovery work. Compare native
Claude, the current runtime and the target runtime on equivalent
fixtures/permissions/budgets using target-side oracles and actual traces; interleave
repeated runs and report variance/uncertainty. No speedup percentage or model
improvement is established yet.
Preserve the historical count-query baseline, but validate full facts, relations,
unfinished work and authorization semantics before comparing equivalent paths.
Measure the pre-revision Store against the converged Store as well as the legacy
baseline. Start with batch SQL, indexes, bounded queries and reuse within closed
inputs; do not trade away integrity checks or add speculative cache infrastructure.
Engineering closure, writer retirement, measured efficiency and online capability
evidence are separate results. An unapproved online budget leaves that acceptance
item open; successful cutover or more passing tests cannot replace it.

Ordinary method/knowledge improvements should not change the persistence core.
New domain facts or invariants require focused owner, transaction and consumer
tests. Module boundaries follow real responsibilities, not line-count targets.
No ORM, generic repository framework, event bus, event-sourcing runtime, database
service or duplicate Agent capability is required.

## Stable-kernel clarification (2026-09-30)

This section supersedes earlier v2 closure and all-or-nothing local-damage
wording. Identity v3 preserves absolute asset URL, explicit method, technique
and bounded declared conditions. Attempt/step identifies an execution occurrence;
conditions identify comparability; path/family views identify presentation groups.
They are not interchangeable. Historical v2 stays readable but cannot authorize
closure without an explicit evidence-bound replacement. No silent upgrade or
family-policy interpreter is introduced. Identical declarations do not establish
semantic sufficiency. Native multi-step evidence explicitly selects subject_step;
only an unambiguous single match can omit it.

For complete snapshots with identifiable damaged operations, suppress their
current closures after history reduction; never drop bad input and revive an
older conclusion. Damage includes controls in the same operation. Unknown
identities or truncated snapshots remain global integrity failures. Negative
results are condition-bound; stopping or deprioritizing work is not refutation.

Object inference, Recon business-value scoring/category quotas and the old learn
backend are retired. Inventory, source references, stable pagination and execution
budgets remain. The protected Checkpoint caller retains a no-I/O retired seed
adapter, not an object detector. Knowledge/Skill method content is outside this
refactor; its loading/storage boundaries change, not its substance.

Installation and synchronization share `runtime_doctor.sync_runtime()` and the
hash-based ownership receipt. Whole-batch preflight precedes payload/receipt writes;
only unchanged owned retired files can be removed. The selected Skill discovery tree
is inspected for known retired or duplicate identities, including renamed paths;
unowned/modified entries and unsafe or uninspectable paths reject the batch.
Unrelated external Skills and disabled commands are preserved, never tree-deleted.
Runtime discovery may read linked third-party Skill entries to inspect identity;
their normal directory/file links do not block Bootstrap. Linked known CCST
entries still conflict, even under a renamed path. Sources, managed writes and
ownership metadata retain strict path checks; discovery does not authorize
installation through a link or alter the host's native Skill loader.

An entry cutover requires all kinds plus prune and a fixed checkout/native
candidate. `.ccst-entry-migration.json` binds root, direction, executor/source/native
fingerprints, exact file operations, before/after receipts and expected entries
before payload. Non-entry resources precede old-entry retirement; the new entry is last.
The record's receipt phase fixes the verified after-state before receipt publication,
including when receipt bytes are unchanged. Interrupted payloads resume only at exact
recorded before/after hashes with the same version. Receipt-phase recovery verifies
and completes the receipt/cleanup only. Third states, unplanned entries and changed
sources are refused; read-only compare reports pending as critical drift, never repairs.
Reverse sync uses a separately approved prior asset set and the migration-aware tools.

Required Claude lifecycle settings use the same ownership receipt and journal:
`settings.json#ccst-autopilot` owns only matching hook groups, preserving unrelated
settings and order. Missing, modified, unowned or disabled groups block readiness.
Hook changes require all kinds and prune, exact-source preflight and recorded
before/after group hashes; interruption never grants ownership of user edits.
The contract module supplies settings without importing Bootstrap/domain owners.
Global Review's ordinary evidence references attest target ownership and nonempty
files; registered raw-artifact bytes retain their existing evidence-owner checks.

Root CLAUDE, rules, tools, support assets and reviewed knowledge stay in the
selected checkout. The complete src-hunter knowledge directory and modules are
installed recursively as part of its Skill package. A checked disk root is not all discovery roots or a
host cache, and does not prove natural method use or gains. Personal installation,
host refresh and live G4 remain separately authorized. No cross-file atomicity,
power-loss recovery or zero-downtime guarantee is implied.

### Execution guarantee boundaries

| Entry/boundary | Actual guarantee | Not guaranteed |
|---|---|---|
| Shared HTTP `request_once` | Initial and redirected target/Scope checks before send; caller-supplied AuthSession | Side-effect review, evidence persistence or automatic registration |
| AuthSession | Credential replay bound to target/allowed origins and saved Scope | General network isolation |
| Hunt request telemetry | Advisory throttling and observations; authenticated redirect strips credentials outside its credential boundary | Universal scope enforcement or sandboxing |
| Native evidence registration | Target-owned references, identity/subject checks and atomic metadata | Preventing an already executed request |
| Native shell/browser/MCP | Restrictions supplied by platform permissions and deployment network/process isolation | Enforcement by this repository on unrestricted platform tools |

Do not label an unrestricted deployment as constrained. Use platform execution
permissions for operations requiring approval, rather than inventing a command
parser or semantic danger classifier in this project. Scope/Auth checks remain
necessary within project executors; post-hoc evidence checks never substitute for
them. Engineering regressions establish these guarantees, not model capability
gains or exhaustive discovery.
