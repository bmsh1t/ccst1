# Claude-Native Architecture Contract

This is the authoritative target architecture for the Linux-first, single-operator
Claude Agent enhancement layer. The approved refactor replaces the former
file-format/CLI compatibility constraints; it does not build another Agent runtime.

## Implementation and Cutover Status

The native-first refactor was completed and archived on 2026-09-26. Ordinary
domain readers and writers require the existing `TargetStore`; uninitialized,
legacy, preview or damaged state fails visibly instead of selecting a retired
backend. `/hunt` and the explicit Store init command own fresh initialization.
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

Skills provide methods, applicability conditions, counterexamples and evidence
requirements, not fixed test sequences or duplicated native tool manuals.
The native platform owns Skill discovery and loading. Queue/Store do not require
Skill routes, inspect Skill files or prescribe method dimensions. Knowledge cards
retain `tools/knowledge_registry.py`; Context Pack adds no second registry.

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
Normal memory commands, Python APIs, default text and JSON must use one domain
meaning. `target_memory.py` remains a thin interface; `show` must read the same
Store that accepted the write. `set TARGET` selects an initialized target only;
an explicit `--goal` changes that target's Store-owned intent. Retired mode,
phase, hypothesis, skill and knowledge flags must be routed to their real owner
or rejected, never copied into active-target state. Target intent has one
explicit current-value owner in the existing Store row; scope notes do not
change authorization, runtime phase stays with its runtime owner, and the
active-target pointer contains target selection metadata only.

The Store singleton already has `active_goal`, and Experience supports advisory
`note` entries. Import
manifests and command receipts retain historical
source identity; per-entry provenance columns or tables require a demonstrated
consumer need. No keyed-note replacement chain is planned: corrections append
a new Experience and preserve the earlier entry. A note or historical claim
needs provenance, not a fabricated execution. New negative/primitive experience
retains observation requirements; negative experience carries conditions and
reopening criteria. Ordinary calls never implicitly upgrade an active Store.

Recall uses bounded domain queries and batch reference reads, not full-history
loading followed by per-entry expansion and slicing. Default text and JSON
preserve statement, conditions, reopening criteria, next intent and evidence/
source references. Pages identify ordering, filters, exact remainder or explicit
unknown, source health and usable query/ID expansion; a binary DB pathname alone
is not a readable continuation. Category scores cannot silently remove candidates
from the accessible set. Optional-source failure is visible, not a successful
empty result. Native reasoning still decides relevance and action.

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
