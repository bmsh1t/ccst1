# Runtime and Autopilot Contracts

> Claude CLI、Autopilot 和子进程执行边界。

## Claude CLI Autopilot Runtime Boundary

### 1. Scope / Trigger

Apply when changing native reading, Autopilot route/closure projections, or
command/agent guidance. Observations inform Claude; explicit owner work and
mechanical safety, evidence and recovery constraints govern execution.

### 2. Signatures

- `/autopilot <target> [--paranoid|--normal|--yolo|--quick|--deep]` runs inline.
- `autopilot_host.py body --part N [--round-defaults]` reads current sources without runtime/session I/O; installed `--session-id` is accepted and ignored.
- `autopilot_host.py state --session-id ID --invocation-id ID --prompt-id ID --target TARGET` refreshes/rearms the bound loop.
- `build_autopilot_state(repo_root, target, memory_dir=None, *, bounded=False, ...)`
  exposes the same owner facts in full or bounded form.
- `build_closure_projection(state, matrix, ledger_entries=None, *, global_review=None)` is read-only.
- `load_closure_projection(repo_root, state, ...)` reacquires owner snapshots.
- `build_decision_projection(state, "closure"|"loop_check")` preserves the
  canonical `owner_continuations` view and relevant residual diagnostics.
- `prepare_round(repo_root, target, max_lanes=None)` and
  `settle_round(repo_root, target, *, note="", refresh_coverage=True)` return
  `status=review_required` for the exact first-reason cases below.

### 3. Contracts

- The current Claude session alone selects hypotheses, routes, depth and stop
  points, and coordinates writes through existing owners. No second controller.
- `skills/autopilot-protocol.md#investigation-skill` triggers the shared
  `skills/runtime-protocol.md#native-skill-loading` contract for `src-hunter`
  before selecting new investigative work, after Bootstrap admission and required
  execution recovery. `/autopilot-round` consumes the same Shared Automation section;
  both commands allow the native Skill tool. Existing full body context is reused;
  explicit entry delivers original source through `autopilot_host`, without
  depending on model-initiated Skill invocation. Independent dynamic static parts
  may precede Bootstrap, but never admit investigation. Body reads access only current
  checkout sources; execution entry checks observed Hook arrival. Each part retains boundary whitespace with end markers;
  its source hash matches the admitted host binding. Description/manifest/hash
  metadata is not body context. The original description remains unchanged for
  native discovery; no Python selector, Store load receipt or per-lane invocation.
- Slash templates contain entry/permission gates and compatibility navigation only.
  `skills/autopilot-protocol.md` and `skills/autopilot-round-protocol.md` own the
  original automation bodies, delivered once through the same numbered transport.
  They are plain installed resources, not additional Skill entries. Source hashes
  bind those resources and the applicable command entry; entry/permission changes
  remain critical drift. Both resources belong to the existing critical manifest.
- The host stores only private session/invocation/target/arguments, original limits
  and a current source fingerprint. SessionStart settings hooks restore complete source parts for
  compact/restart. Prompt/target-bound `autopilot_host state` combines loop-check,
  Scope/Auth and rearming; admitted argument paths stay bound, not re-resolved aliases.
  Bootstrap/init/runtime compare remain entry-only.
  `needs_refresh` adds existing compact state/memory as `recovery`; otherwise reuse
  context. Refresh and SessionStart read current checkout sources. A changed
  body is returned through `recovery.source_context.commands` (existing numbered body
  reads, all matching `source_context.sha256`). All parts must be read before work.
  Refresh renews invocation_id without resetting allocation. No body snapshot is
  written, read, migrated or deleted; Git owns source history. Installed entry/frontmatter
  comparison remains at execution entry. Source fingerprints detect updates and bind
  complete numbered delivery. Missing/damaged current sources and bindings still fail;
  no protocol version or migration state is added. Failures
  stay suspended. General queries do not access host bindings. Bootstrap is never
  cached as target truth. Original body
  reads are independent of activation order and add no second preparation state.
  State CLI emits complete JSON without the dynamic-entry byte cap; serialization
  precedes activation. Entry/body and SessionStart transport limits remain enforced.
  Oversized Bootstrap uses `read_bootstrap` with a unique private, create-only JSON
  snapshot; both entries read it fully before the real action gate. It is transport,
  never a target owner or a reusable state cache. Small Bootstrap remains inline.
- Normal Stop consumes fresh state/Closure and the existing Checkpoint review's
  optional `termination`: `reason`, `session_id`, `invocation_id`, `boundary`.
  Only explicit_limit also requires `limit`, either positive integer
  `elapsed_seconds` measured from the persisted invocation start, or a `round_id`
  whose current owner has an explicit cap and budget_reached. Seconds must equal
  the optional entry `--max-seconds=SECONDS`; Round must match the saved active
  Round or a new Round under this entry's explicit cap, never its prior completed
  Round. Resume preserves the clock and admitted limits; review cannot create or
  shorten them. No natural-language threshold parser. Cost caps
  remain native host interruptions without a fabricated cost receipt.
  Reasons are scope_boundary, explicit_limit, global_blocker and
  no_worthwhile_work; only a complete current review can authorize the same
  invocation. Active execution/rounds block; no_worthwhile_work cannot bypass
  runnable blocking owners. A generic recon_budget_partial fallback is not
  runnable; partial coverage and required residual review remain intact.
  Concrete Recon phases precede the budget fallback, and a phase with a bound
  continuation takes precedence over an unbound residual when selecting its head.
  Evidence candidates and secondary Closure obligations retain their owner items
  even when the primary reason is a non-executable Recon residual.
  Other reasons retain unfinished owners/reopening
  conditions in residual_unknowns. A valid complete review with missing residual
  tokens retains its fields in form_insufficient: scope/limit/global-blocker stops
  may consume it, but Closure and no_worthwhile_work still require full review.
  Review checks do not prove semantic value or
  replace Closure exhaustion. A batch list uses its existing state continuation,
  never a synthetic list Store/review.
- Stop review failures name missing/invalid/follow-up/incomplete/stale review,
  stale Closure acquisition or missing/mismatched termination separately and return
  a current checkout/target Closure command plus the existing Checkpoint contract.
  A form_insufficient wrapper with review_status=follow_up still directs the
  existing next_action review even when missing_tokens is empty.
  A missing stopping attestation does not establish worthwhile new investigation.
  Result collection/write-back precedes final Closure/review; after needed Refresh,
  use its returned identity, record an evidence-backed review and reread Closure.
  Stop never chooses a reason, writes a review or relaxes normal-stop admission.
- Repeated identical Stop rejection suspends as incomplete, without a default
  investigation cap. The existing last_stop_basis includes review status,
  review_status, sorted unique missing_tokens, residual presence and snapshot_stale,
  alongside owner components/tasks/termination. Review-only repair is progress even
  though Closure excludes its own review from the owner snapshot; decision/residual
  prose and missing-token order do not reset protection. Repeated suspension retains the
  specific reason and current recovery command. Refreshing state does not clear that progress identity.
  New user prompts suspend enforcement; same-task continuation explicitly rearms
  using the current state command. Ordinary questions, cancellation and changed tasks
  remain suspended; intent is the model's choice, not a hook prose classifier.
  Completed bindings remain inactive but accept a current real-prompt-bound Refresh
  for explicit same-task continuation. Successful reopen renews invocation_id for
  Stop review binding only; started_at, max_seconds, round_limit, arguments and target
  facts remain unchanged. It restores the existing owner/memory view without Bootstrap.
  SessionStart may restore completed source bodies but cannot grant a reopen prompt;
  compact preserves an already current prompt grant, while restart, Stop, StopFailure
  and SessionEnd expire it; clear returns the binding to idle. Source failures retain completed status. Notifications
  cannot grant continuation. Only successful completed reopen or source refresh clears last_stop_basis;
  ordinary Refresh preserves repeated-rejection protection.
  Native interruption needs no review, ordinary
  later conversation is not forced into a hunt, and a bound session changing cwd
  still receives its suspension/recovery events. Subagent events are excluded.
  Native background `task-notification` envelopes delivered through
  UserPromptSubmit preserve the binding unchanged; they never suspend an active
  investigation or rearm a suspended one. Ordinary user prompts still suspend.
  Match the complete reserved envelope, including optional `tool-use-id` and
  `note`/`result`/`usage` tails; payloads are opaque text, not well-formed XML.
  Repeated completed/failed/killed notifications preserve status, prompt, invocation
  and binding bytes. Envelope recognition is not sender authentication; surrounding
  user prose is a real prompt and retains the ordinary suspension path.
  Scan opaque field boundaries without combinatorial regex backtracking; malformed
  repeated closing tags must not stall the binding lock.
- Skill application retains the same session, target type/Scope, mode and any explicit
  user/host limits, or `unset`. Waits, terminal cleanup and execution recovery do not require a fresh
  Skill call. Shortlist and complete relevant methods follow Shared Knowledge Recall;
  internal modules stay problem-scoped. Owner continuations supply pending work,
  while the model uses src-hunter and current evidence to choose questions/methods.
- `rules/dig-scope-workflow.md` §0 owns target classification: domain (including
  a bare primary domain), IP/CIDR, host:port, URL and target list are fixed-target
  inputs. In-scope subdomain discovery does not imply group/brand discovery.
  Missing history/material or Skill loading must not create a campaign seed queue.
  Shared Automation starts new/empty targets without prior work or usable supplied
  evidence with Recon; existing work and usable supplied evidence retain their
  recovery/direct-investigation paths. The Skill/module guidance preserves this
  command contract without another controller or a universal inventory gate.
  The 6k/Autopilot integration boundary lives in `docs/ccst-runtime-adapter.md`;
  command-specific control changes do not rewrite shared 6k investigation rules.
- Nested `/recon` retains the active Autopilot invocation. Live phase locks are
  duplicate-launch guards, not cross-owner hard gates: current Queue/Finding work
  remains visible and independent evidence-backed investigation may proceed.
  A background handle requires result collection before dependent work or final
  stopping, followed by fresh state and Surface Review. It grants no final response
  or "continue?" stop. Its standalone
  collection behavior is unchanged. The consumed Recon command is critical runtime
  content, so an older installed copy cannot silently omit this return contract.
- A loaded Skill/shortlist does not establish method use. Read and apply complete
  relevant methods before the selected question's first request, reusing body
  context when present; truncated output requires reading the remainder.
  Receive and consume required method/capture reads before generating dependent
  requests or execution scripts; do not batch those reads and requests in parallel.
  Shared runtime output identifies the question, fully read method/module file and key control
  at first use of a method or a direction change; tool descriptions are not
  assistant progress. Interim summaries and handoffs retain the actual endpoint,
  method, actor/state and evidence boundary, with untested conditions explicit.
  Separate observations from unverified explanations; untested/deferred surfaces
  must not be marked complete or ruled out.
  New identity/permissions
  require reconsidering business paths under `rules/dig-scope-workflow.md` §4.2.3;
  determine whether authorized test identities can be obtained before treating
  a missing session as a local blocker. No mandatory login or exhaustive grid.
- Both modes refresh post-action state; round mode first writes its terminal
  heartbeat. Result reassessment has one shared contract in
  `skills/runtime-protocol.md#5-execution-and-write-back`: consume accepted owner
  receipts, use the entry's existing refresh, compare relevant changed conditions
  and select further work. Background/specialist results return to that same loop.
  Reassessment identifies the changed premise and its evidence, checks both met
  and still-missing conditions, and compares eligible deferred work with independent
  questions. A new fact or topic match never automatically clears every blocker.
  Existing blocked/repeat APIs retain identity and terminal immutability; bounded
  previews and stale handoffs cannot replace current Action facts. Ordinary reads
  add no full-history recall or cognitive writes. Offline behavior checks live in
  `research/verify_autopilot_continuation.py`; they do not establish model compliance.
  `handoff` returns to investigation in this session unless an actual
  user/scope/explicit-limit boundary, demonstrated blocker or evidence-based no-worthwhile-
  next-question judgment justifies stopping. Report counts, anonymous denial and
  missing-but-obtainable sessions alone do not. Explain valuable unpursued leads.
  `loop_guard=continue` is advisory, not an endless execution mandate. Pending
  owner work requires continuity when stopping; handoff itself grants no stop or
  exhaustion claim. Neither entry assigns default whole-investigation time, cost or
  lane limits. Unset limits do not authorize inventing a deadline or write-back cutoff.
  Saved active Round limits remain authoritative across resume.
  Writer/object-cleanup failure constrains that operation; assess independent
  business paths before treating it as a blocker to useful target-wide work.
  Explicit-limit stops cite their user/host source and actual clock/count/cost receipts;
  resume retains the old boundary unless explicitly reallocated. Cumulative cost
  needs the allocation's baseline, retained across resume unless reallocated;
  unavailable cost is unknown, not exhausted.
- Shared Automation compares available business and technical surfaces in the parent
  after Recon. The thin `recon-ranker` is an optional second opinion for a concrete
  prioritization or missed-path question that benefits from independent review.
  Multiple subdomains, first post-Recon selection, resume/compaction or lane/round
  completion alone do not trigger delegation; a clear next experiment proceeds inline.
  The core Skill owns evidence-driven rotation and distinct-angle handoffs. Missing
  prerequisites constrain dependent work; ongoing uncertainty reduction remains progress.
  Stagnation/blind-spot dispatch carries prior methods, their conclusion boundaries,
  a distinct angle and distinguishing outcomes; repeated conclusions without independent
  evidence are not additional support. No timer, mandatory review or model-tier ladder is added.
  When selected, its existing content pack and single review include both surfaces,
  evidence refs and missing material. `rules/src-value-hunting.md` §1.1 owns default
  priorities and evidence-backed changes; no technical quota, score or new selector.
  Technical clues can precede routine object tests, but never execution recovery or
  cleanup. Missing material stays unknown; deferred paths remain untested.
  Unchanged material/question reuses its existing answer/handoff. User/scope/budget
  stops and execution recovery take precedence. The optional ranker stays outside
  the critical runtime manifest; its missing/drift status is advisory, not a startup gate.
  Other specialists remain optional bounded questions respecting any explicit limits.
  A review's local deadline does not end the parent investigation; an unset parent limit
  is valid and does not prevent a concrete review allocation.
  Ranker review sends no target requests, writes no state, creates no lane and cannot
  decide Closure or extend `max_lanes`. Unavailable/failed native Agent is explicit
  incomplete independent review; the parent continues its own investigation.
  The dispatch requests `run_in_background=false` because the next selection depends
  on it; current Claude CLI defaults to background. A returned handle requires its actual
  terminal result within the assigned allocation. Consume the complete matching native notification;
  TaskOutput/TaskStop depend on host availability, even when the entry allows those tool names.
  Missing/incomplete results remain pending; do not invent or repeatedly call an unavailable tool.
  Dispatch acknowledgment is not review completion. Same frontend/anonymous denial
  permits deduplicating that layer only; independent origin/object authorization
  remains subject to dig-scope-workflow's evidence and session conditions.
- Compressed guidance must reference real sections that retain the displaced
  constraints, not merely existing files. Keep command frontmatter, Bootstrap
  expansions, critical manifest and consumed headings stable: round reads the
  complete delivered Shared Automation protocol; `_lane_contract_text` includes lane subsections
  and fenced content. Retain CLAUDE's complete 6k imports. Measure resident imports,
  command bodies, on-demand lanes and optional agents separately; byte counts do
  not establish token, cost or model-behavior improvements.
  When DNS expansion returns positive
  `new_resolved_hosts` or `new_all_hosts`, the specialist hands off those counts,
  evidence refs and a Surface-refresh request through the existing pending-write
  tail; only the caller refreshes Surface. No added hosts means no DNS-driven
  refresh request. A stale projection is not an automatic refresh.
- State does not select a specialist from evidence-group counts or long-tail size.
  The shared command's Claude-side invocation applies `docs/autopilot-lanes.md#recon-ranker-review`
  and src-hunter's handoff contract; Python emits no ranker recommendation or review owner.
  Only accepted evidence/decision deltas need existing owner write-back; an advisory
  ranking alone creates no Action/Finding. The other four retired specialists stay retired.
- Read-only review reads current target memory/Findings/experience through existing
  Store queries with an explicit target, and raw evidence or current cached
  projections. Retired JSON/PatternDB is history, not a missing-Store fallback.
  Even plain `surface.py` can publish projections: refresh/build/init/repair
  belongs to the parent, not the reviewer. Review sends no target requests and
  performs no acquisition or Store import. Missing/stale/invalid inputs remain
  unknown with recovery advice; available raw material is still reviewable. Each pager
  keeps its own target/filter-bound cursor; `target_memory show` is not a pager.
- `next_tool_hint` / `enrichment_hints` remain compatibility fields. Ordinary
  state emits empty values; full-state `guard_safe_pivot` retains cached
  `context_pack` / `checkpoint` hints, while bounded state omits those hints.
  Existing Intel hints are unchanged. Bootstrap emits empty `enrichment_hints`
  even when supplied historical specialist hints; it does not revive retired entries.
  Surface facts, exact URLs, references, statistics and pagination stay available.
- Cached JS/source paths go directly to native Read/Grep. `js_reader`,
  `source_intel`, `intelligence_extractor` and `/js-read` are retired. Historical
  artifacts stay readable without becoming prerequisites or a new fact source.
- Recon can preserve raw JS and bounded discovery views but cannot create a
  deep-JS Queue obligation from file presence. Claude explicitly chooses work.
- Surface rank, resume previews, Case hypotheses, actor gaps and Intel advice
  do not select a route or enter the owner continuation array. Intel provider
  errors remain visible in `intel_continuation`, never a clean result.
- `owner_continuations` represents explicit Queue/Finding/runner work and durable
  Recon continuation. Runtime locks, target initialization, evidence integrity,
  budgets and transaction recovery retain their existing owners.
- `autopilot_gate.build_control_projection` constructs the ordinary owner frontier
  once and derives `next_action`, `primary_next_action`, `fallback_action`,
  `selection_mode` and `next_lane`. A single business owner retains its compatibility
  token; multiple owners use `continue_investigation` + `ai_priority`, with each exact action/ref
  preserved for Claude's selection. Recovery items precede new work in rendered
  hints without replacing the business token. Active lock tokens remain
  `wait_recon`/`wait_scan`; compact and loop views consume this projection, not
  separate owner priorities. Empty work returns `continue_investigation`;
  Closure maps that guidance to its existing handoff meaning. For a truly
  empty single target, the same projection defaults to `run_recon` with lane
  `recon-and-surface` and selection mode `fallback`, never a hard gate or Queue item.
  Resume's existing Store binding (revision zero means initialization only),
  saved memory, raw claims, runtime/Recon records, browser/source/scan material,
  observation/Surface health and claimed Round work prevent treating prior work
  as empty. Missing Recon alone never requires restarting it; partial/zero-result
  collection and invalid cached material retain their diagnostics and recovery.
  Conversation-supplied usable evidence can override this initial default at the
  command layer. State passes its cached observation/Surface facts into this
  projection before deriving all action/lane fields. Both modes use the same
  stat-based Recon control facts; full diagnostics retain exact counts separately.
  FFUF raw files without a summary remain prior material, through the existing
  adapter's metadata-only missing-summary view; no extra Store scan or schema.
  The same gate owns the existing Guard fallback: only empty-frontier fallback
  with Recon and all tracked hosts cooling changes `next_action`/`fallback_action`
  to `guard_safe_pivot`. `primary_next_action` stays the original owner hint;
  lock, recovery, owner priority, lane and Intel exemptions remain unchanged.
  Regression history: `76d16e6` removed the initial Recon branch while removing
  the blanket inventory gate; `bd619ea` made empty work fall back to `handoff`.
  Regress the real initialized Store path, not just the untouched-target shortcut
  or rendered instruction text. Native acceptance must verify expanded Bootstrap
  and complete Skill body delivery, actual requests and return/finish behavior;
  keep input open through background completion. Local 2026-10-26 acceptance
  restored Skill→Recon startup, but still observed probes during Recon, omitted
  method reads and early finish with budget/leads remaining. Two published lab
  reports do not establish full automation acceptance or stable model obedience.
  That run used the earlier global-rule edits, now withdrawn. Its model behavior
  does not validate the narrowed, adapter-only integration wording.
- Closure builds recovery descriptions only through `_closure_reason_frontier`.
  Finalization preserves fixed reason precedence/verdict, retains independent
  checkpoint recovery under a primary Round reason, and replaces duplicate
  diagnostics without discarding another Recon cursor or Queue item. Snapshot
  and repeated-prerequisite overrides still publish both continuation aliases
  after their final change. Reason IDs/text normalize to the shared helper;
  historical raw evidence and owner state are unchanged.
- Closure's `actionable_frontier` is a legacy read-only alias. Publish
  `owner_continuations` after every review/race/bounded-stop override, so an empty
  final continuation cannot retain an earlier action. Loop `control` uses the
  same canonical field; array order is not AI priority.
- Post-action `--loop-check --projection-only` retains `control.next_step`, the
  Surface status/path/fingerprint/refresh and continuation command, display-window
  counts, and observation inventory health/counts. These are reading references,
  not new owner actions or tested-coverage counts. Missing counts stay unknown;
  stale/missing projections remain diagnostic. Expand changed or unread material
  before selecting work; empty owner continuations return to src-hunter.
  Settling inherited Round work returns ordinary `/autopilot` to this same loop.
  Only this projection skips the unused twenty-entry diagnostic memory read;
  ordinary full/bounded state and Closure keep it. Recovery memory remains bound
  and independently checked; omitting an unused view does not omit owner validation.
- State, compact Bootstrap and loop control expose the existing Checkpoint's
  `round_progress` and `checkpoint_health` without creating a Round or replacing
  the business `next_action`. Unfinished lanes recover first; completed lanes
  with budget remaining allow further investigation. Invalid witness data requires
  repair; active Recon/scan locks retain priority. Closure can exclude Round
  recovery while computing post-round business state.
- `observation_residuals` records untested cell count, unresolved Case hypotheses,
  actor gap and incomplete Intel without creating new actions. With no owner
  obligation, unresolved observations yield `handoff` + `next_action=handoff`
  and `can_claim_exhausted=false`. They cannot establish a target-wide blocker
  or stop Round prepare. Actual user/scope/budget limits or evidence-based
  investigation judgment govern stopping; the existing claim owner enforces
  this round's budget. A later invocation can continue the remaining work.
- Repeated local prerequisite stagnation retains its reasons and `round_guard`
  but returns non-exhaustive `handoff` to independent investigation. Rebuild the
  frontier from real owners; a failed diagnostic lane is not a global blocker.
- Report continuations use Store's current assessment/delivery and checked report
  status. A historical report cannot suppress a new pending destination; damaged
  same-binding reports require repair. This check reads current evidence bytes,
  even when a bounded summary returns only a few claims.
- A valid digest-matched `global_review` covering every non-blocking residual token
  completes their review only: Closure publishes `handoff` with
  `bounded_recon_residual_deferred` and an empty continuation array, never an
  exhaustion or blocked claim. It returns to native investigation unless the
  entry's actual stopping conditions apply. Queue, Finding, unfinished-round, evidence and checkpoint
  obligations — including `closure_blocking` scanner lanes — keep their
  owner-backed entries. Scanner residual review tokens bind execution semantics
  (`execution_kind`, `status`, `input_total`, `selected`, `remaining`,
  `closure_blocking`, `accounting_valid`); semantic drift invalidates an old review,
  display/time drift does not. Store-mode partial/unreadable evidence maps to the
  same evidence-ledger owner, `repair_evidence_ledger` action and reason frontier
  as the legacy `ledger_*` reasons.
- An otherwise finishable target requires a valid current Global Review in both
  ordinary and Round modes, including when no Round has ever existed. Missing,
  invalid or stale review returns its existing review-required handoff. This
  gate does not preempt unfinished investigation, recovery or explicit owner work.
- Actor/session gaps are non-blocking context for unrelated work, not automatic
  session acquisition. Actual role-based evidence still requires the relevant
  identity boundary. Advisory review never impersonates execution evidence.
- `_coverage_terminal_evidence(matrix, evidence_projection, record_count=0)`
  queries `ClosureResolver.closed_result(..., identity_v2=cell.get("identity_v2"))`.
  A complete subject result cannot authorize an identity-free family terminal.
  Controlled structural N/A is separate; marker text alone is insufficient.
- Checkpoint cadence remains paranoid/normal/yolo. Repetition, siblings and
  response deltas inform AI choices, not fixed testing/rotation sequences.
  Cadence controls read-only snapshots, not cognitive consolidation. Shared
  `skills/runtime-protocol.md#cognitive-write-timing` separates immediate evidence,
  Candidate/Action registration and terminal heartbeats from event/boundary memory
  writes. Same-session Skill reads and tool executions add no result form; real
  delegation still returns evidence, unknowns and proposed owner actions through
  the investigation core's handoff contract. Manual hunt has no mandatory scanner
  or duplicate ordered loop; rotation alone requires no full checkpoint/coverage
  review. Completion gates and unresolved recovery work remain mandatory.
- `rules/desktop-task-folder.md` owns materials and cleanup only. Startup/recovery
  follows command entry and Shared Memory Continuity; no additional init/set/show
  sequence or mandatory thread/DONE file. Known-target calls pass the target
  explicitly, including concurrent/delegated work; shared active-pointer changes
  are optional. Store domain facts, Runtime/checkpoint/batch continuation files
  and Coverage retain their existing owners. Optional notes use work-item/thread
  paths and owner refs; real delegation still returns iteration candidates and
  source/report refs under `hunt-iter`. Pending candidates survive pause/switch/
  compaction through existing memory/handoff. Campaign seeds retain unbound
  cross-target progress; notes and seeds do not prove target completion.
- Explicit Round limits and lane completion remain mandatory. Reaching a supplied limit
  alone creates no new work. `recon_phase_partial` binds its recovery head to the
  actual phase, artifact and remaining count; other Recon work cannot substitute.
- A first Closure reason of `global_review_required`, `global_review_stale`,
  `global_review_invalid` or `global_review_form_insufficient` requires review in
  all three coordinator paths: prepare does not begin a round; completed settle
  stays read-only; active settle keeps the existing close order before returning
  `review_required`. Preserve the full Closure, including `missing_tokens`,
  `review_status` and `can_claim_exhausted`. Do not match arbitrary prefixes or
  secondary reasons, fill missing tokens, or automatically record a review.

### 4. Validation & Error Matrix

| Input | Required result |
|---|---|
| Only raw JS/source/browser/Case/Intel observations | No automatic route or Queue insertion |
| Empty, sparse or multi-source long-tail Surface | Preserve facts/cursors; no automatic specialist selection |
| All hosts tripped by request guard | Cached-evidence pivot and full hints retained; bounded output stays compact |
| Untested coverage, no explicit owner work, budget remaining | `handoff`, retained residuals; Round prepare starts/resumes investigation |
| Active runtime phase or explicit Queue work | Existing lock/owner continuation preserved |
| Evidence or snapshot damage | Visible integrity/recovery error, never empty success |
| Host refresh: stale binding / invalid Scope/Auth or failed read | Reject stale caller / remain inactive (completed on failed reopen); no init or Bootstrap; recovery adds root, arguments, batch/mode and memory |
| Completed task, current explicit continuation | New review invocation identity, original time/Round allocation and owner memory retained |
| Completed task, question/notification/restart alone | Remain completed; no automatic continuation; failed restart also expires an old prompt grant |
| Complete native background envelope, including result/usage | No binding write or continuation grant in active/suspended/completed states |
| Missing/stale/invalid review or mismatched termination | Block with precise diagnosis and existing in-session repair steps; no inferred new investigation |
| Same owners/termination, fewer missing review tokens | Continue repair; not an identical no-progress Stop |
| Same requirements, changed decision/residual prose or token order | Retain repeated-Stop protection; suspension reports its specific blocker |
| Goal changed/cleared or captured memory binding stale | Old review becomes stale / Closure requests a fresh state; handoff-only changes do not alter semantic basis |
| Exact subject closure with identity-free tested Coverage cell | `missing_matching_ledger_terminal` |
| Valid global review covers non-blocking bounded residuals | `handoff` with `bounded_recon_residual_deferred`; blocking owner obligations keep their entries |
| Otherwise finishable ordinary target without a current review | Existing Global Review handoff; `can_claim_exhausted=false` |
| Post-action projection with new or unread Surface material | Keep reading references, display remainder and next-step explanation without creating Actions |
| First reason is an exact review-required case, including form_insufficient | All three coordinator paths return `review_required`; diagnostics remain intact |
| Review-like prefix or non-first reason | Existing normal routing; no broadened review gate |
| Recorded review basis unchanged, whole digest changed | Consume Closure validity; no re-review or source inspection solely for digest drift |
| Snapshot races during review | Both fields expose the current recovery head |
| Repeated identity enrichment | Same summary path; historical `intelligence.md` untouched |
| Static review of task-folder guidance and active callers | No duplicate startup chain or mandatory shared note file; explicit target, durable candidate handoff and evidence/cleanup boundaries remain |

### 5. Good/Base/Bad Cases

Good: read raw JS directly, save a confirmed A immediately, choose optional B/C
within budget, and report unresolved context at bounded stop.
Base: no specialist or next investigation is useful; remain in the same session.
Host: continuation refreshes once; a question stays suspended; stale prompt cannot rearm.
Completed host: explicit continuation renews its review binding; source recovery alone stays inactive.
Bad: rename a frontier while keeping its automatic route control, or claim
exhaustion merely because the inferred frontier was deleted.
For review routing, a valid review missing residual tokens still needs form
completion; it is neither an invalid technical judgment nor a reason to begin a
new round. Ordinary settlement without a review reason retains its prior status.

### 6. Tests Required

- The 2026-11-10 live Stop acceptance uses the installed Claude CLI, the configured real
  model provider and isolated real Store/Closure/Checkpoint owners. Preserve per-request
  usage including child requests, one user input per case, actual hook transitions,
  review receipts and source hashes. Missing/stale/mismatched reviews must recover in-session;
  normal scope-boundary stops retain residuals. A random result read only by a real background
  child must arrive in a matching native notification, leave binding bytes/mtime unchanged,
  and reach the parent's owner review before Stop releases. Keep failed/budgeted trials
  and unavailable host tools visible. Fixture bindings do not prove full Bootstrap,
  browser use, unbounded investigation or model reliability across repeated real targets.
- `11-10-autopilot-stop-recovery/research/check_stop_recovery.py` under
  `.trellis/tasks/` compares old/new allow decisions, reproduces review-only
  progress collisions, and exercises the real isolated Claude CLI's Stop event
  sequence with scripted loopback responses and explicit synthetic owner projections.
  Repair must release only after accepted facts; unchanged failure suspends with
  its reason, active execution blocks, and explicit user stop stays inactive.
  This proves host transport, not model judgment, real target state or full owner writes.
- Replay the captured native notification and legacy/minimal envelopes against
  disposable bindings; cover optional note/result/usage, failed/killed, opaque
  angle brackets, repeats, cancellation/questions, surrounding prose and child events.
  Assert binding bytes/mtime and prompt/invocation identity, not only status. Include
  child cancellation and a timed malformed repeated-tail case to distinguish guards.
- `python3 -I research/verify_autopilot_continuity.py` uses a temporary Store and
  host binding to check current/cleared goals, review v3/legacy behavior, a handoff
  outside the five-entry history, compact/restart/prompt/notification sequences,
  source/Scope failures, unchanged time/Round limits and repeated Stop protection.
  A real temporary source update with an old hook digest exercises entry, completed/
  suspended Refresh, compact/restart full-body equality, old-review invalidation,
  missing hooks and corrupt snapshots. Runtime comparison retains receipt checks,
  allows only freshly delivered body drift, and rejects entry/configuration changes.
  A real Closure read rejects a captured memory revision older than the current
  Store. Scope and host state acquisition are injected; no target requests, model,
  personal configuration or project tests are read. This is not live host acceptance.
- `10-27-autopilot-session-continuity/research/check_continuity.py` under `.trellis/tasks/`
  checks real-owner recovery, event-delivered CLI commands, retained auth paths and failure suspension in isolated copies.
- For Skill entry guidance, review the composed Shared Automation instructions:
  fresh investigation loads src-hunter; retained body is reused; missing body after
  compaction is restored; round shares the same rule; waits/cleanup/recovery retain
  priority; unavailable Skill tools use complete native file reads. Verify unchanged
  description and absence of a second controller. Prompt/diff checks establish the
  written contract only; actual host/model invocation requires separate live evidence.
- For investigation priority and Recon review, compare ordinary business evidence,
  a target-bound technical clue, an unverified product name, missing technical material
  and pending execution recovery. Parent review and any selected ranker pack consider both
  surfaces; strong evidence may change the next question under src-value §1.1,
  while weak signals cannot force priority and deferral cannot count as coverage.
  Preserve command arguments, selected-review budget/wait and owner boundaries.
  Multiple hosts or first/resumed selection must not force a ranker call. In an isolated
  runtime copy, missing/drifted ranker is advisory while a missing core Skill remains critical.

`tests/test_autopilot_round.py` covers all four exact reasons at prepare and both
settle paths, unchanged witness/Store on completed replay, active close ordering,
round identity/budget and full diagnostic preservation. Its exact-first-reason
regression guards normal statuses; `test_autopilot_round_contract.py` checks the
command consumer. Keep the real residual-token regression in
`test_autopilot_state_tool.py` aligned: filling tokens completes review but retains
investigation handoff, never a stop or exhaustion claim. Producer diagnostics
alone do not test coordinator routing.
The offline reproduction at
`.trellis/workspace/Codex/research/10-23-autopilot-continuation/check_continuation.py`
checks multi-subdomain prepare/settle and next-round continuation, existing lane
budget/recovery gates, ordinary/round Global Review parity and post-action
material navigation in an isolated source/Store copy. It never reads `tests/`,
private runtime or real target data, and does not establish model obedience.

`tests/test_autopilot_bootstrap.py::test_state_preserves_surface_facts_without_choosing_ranker`
checks full/bounded state across empty/sparse/rich evidence, exact facts/cursors,
Store binding and source-byte preservation. Historical specialist-hint serialization
is retired; cached-evidence guard, owner continuation and closure-advice digest
checks remain relevant.
The former ranker CLI and old agent checks describe the historical implementation,
not the restored thin review role. Its explicit ordinary/Round command wiring and
read-only handoff require focused guidance review; temporary runtime sync must discover
the agent and enforce its existing critical-manifest binding, including missing/changed
installed bytes. These checks do not establish actual host invocation or model depth.
Historical agent retirement used an isolated baseline-to-current runtime check:
ordinary sync retains old owned files, prune removes exactly unchanged retired
agents, modified obsolete files reject the whole batch, and user extras remain.
Also preserve surviving agent/command/module bytes, recursive Skill resources,
critical manifest and bounded owner/Surface/memory projections. No host/model
behavior is inferred.

`tests/test_ai_native_skill_convergence_baseline.py` keeps the thin-agent owner
contract, resolves the three-mode reference to its actual section, and checks
positive/empty DNS-count handoff wording within the DNS clause, including
caller-only Surface refresh. These are static guidance checks, not model A/B.
Its event-timing and output-contract regressions preserve immediate receipts,
Candidate registration, Round heartbeat and final Closure while rejecting a
per-execution result form, mandatory manual scanner or rotation checkpoint.
References in hunt/autopilot/core/hunting must resolve to the single shared
`Cognitive Write Timing` section; no efficiency gain is inferred from this check.

Run `python3 .trellis/tasks/09-29-native-first-boundary-optimization/research/check_native_first.py`
for observation/owner separation, lock preservation, malformed matrix input,
bounded residuals, final alias consistency, Intel artifacts and protected edits.
Run `python3 .trellis/tasks/09-29-validation-closure-scope/research/check_closure_replay.py`
for actual Runner/Store replay and both accepted/rejected terminal-check branches.
Import/syntax checks alone do not exercise late-bound resolver names.
Run `bash -n tools/recon_engine.sh` when changing the JS collection branch.
Existing legacy tests that import retired readers are not a reason to resurrect
those readers. Migrate those assertions to native-reading boundaries, preserving
user-owned edits. `test_js_reader.py` checks retirement instead of the deleted API.

### 7. Wrong vs Correct

```text
Wrong: observed JS / missing actor / Intel lead -> mandatory route or session task
Correct: observations -> native reasoning; explicit owner command -> durable work
Wrong: every continuation -> full Bootstrap + separate state read
Correct: bound state refresh; only lost context adds owner/memory recovery
Wrong: native result/usage tail -> treat as user request and suspend
Correct: complete reserved envelope -> preserve binding; ordinary user prose -> suspend
Wrong: completed refresh reuses the old stop review or restarts the budget
Correct: explicit current-prompt reopen renews only review identity and preserves allocation
Wrong: no generated frontier -> target exhausted
Correct: unresolved observations -> native investigation handoff; actual stopping conditions remain separate
Wrong: a non-empty completed Round is the only reason to require Global Review
Correct: every otherwise finishable target needs current review, independent of mode
Wrong: form_insufficient -> start new round or return ordinary settlement
Correct: form_insufficient -> review_required, original diagnostics and owner boundaries
```

## Claude CLI Autopilot Argument Contract

### 1. Scope / Trigger

Use this contract whenever `/autopilot` flags, `commands/autopilot.md`,
`tools/autopilot_args.py`, direct tool cadence parsing, or Claude runtime
wiring changes.

### 2. Signatures

- Inline command: `/autopilot <target> [--paranoid|--normal|--yolo] [--quick] [--deep] [--max-lanes N] [--auth-file PATH] [--context-file=PATH]`
- Parser: `parse_autopilot_args(argv, cwd=None, *, round_defaults=False) -> dict`
- Capability profile: `build_capability_profile(repo_root=None, *, which=shutil.which) -> dict`
- Capability degraded marker: `load_capability_degraded_marker(runtime_root=None)` /
  `write_capability_degraded_marker(runtime_root=None, *, reason, missing, source, profile)` /
  `clear_capability_degraded_marker(runtime_root=None)`
- Bootstrap: `build_autopilot_bootstrap(argv, cwd=None, repo_root=None, runtime_root=None) -> dict`
- Direct cadence helper: `cadence_from_namespace(namespace) -> str`

### 3. Contracts

- `commands/autopilot.md` uses one root-aware dynamic bootstrap invocation with
  `$0..$9` and `allowed-tools: Bash`; it locates the current Git worktree and
  the emitted JSON is the authoritative inline contract, not a hint for the
  model to reinterpret. Empty slash invocation may pass the dynamic command's
  executable shell as its sole `$0`; `parse_autopilot_args()` must normalize
  only an absolute, executable, known-shell fallback to no arguments, then
  return `ask_target`. It must not discard an ordinary token or a non-shell
  readable list file.
- The parser response always has `schema_version`, `valid`, `action`, `argv`,
  canonical target fields, URL `seed_url`, auth-file fields, cadence fields,
  `recon_flags`, `hunt_auth_flags`, and `errors`. It exits zero for invalid argv
  so the prompt can consume the structured action.
- Both entry modes omit a lane cap by default: `max_lanes=null`,
  `invocation_batch.bounded=false`, `handoff=normal_finish_condition`.
  `round_defaults=True` changes only cadence/deep to normal/true; it never supplies
  a numeric limit. Explicit `--deep --max-lanes N` retains its 1..32 validation and
  existing handoff contract. Unset whole-run limits do not disable per-operation
  timeouts, collector batches, rate/concurrency controls or evidence recovery.
  An ordinary invocation with an explicit lane cap uses the existing Round
  prepare/claim/result/settle owner; uncapped ordinary work creates no Round.
- Bootstrap order is args -> Scope/context and explicit/bound Auth validation ->
  read-only runtime compare -> advisory capability profile -> explicit single-target
  Store initialization -> compact target state. Explicit/bound auth is parsed by
  `AuthSession.from_sources(env={}, ...)`, never by ambient credential discovery.
  List startup validates credential content only; concrete target binding is checked
  after selecting a child, so a domain-bound credential is not compared with a list path.
  Lists initialize selected targets through their execution owner. Existing primary
  Stores retain identity/revision/facts; legacy, preview, fenced-missing and damaged
  targets are refused without migration or replacement. Invalid arguments/context
  or critical runtime drift never initialize a Store or call the
  capability profile or `build_autopilot_state()`; advisory drift continues and
  clean root/nested invocations emit the same conclusion.
- Bootstrap `capabilities.schema_version=2` is a bounded target-independent local
  dependency view: `checked`, `status=checked|unknown`, flat `available`/`missing`,
  `local_files`, fixed `session_managed`, and `session_status=unchecked`.
  It no longer publishes category readiness, lanes, recommendations or fingerprints;
  v1 external consumers must explicitly adapt. No historical snapshots are rewritten.
- Bootstrap may additionally expose an explicit runtime-global `degraded_marker`.
  The marker is written only through the capability-profile writer/CLI, is
  atomic and lock-serialized, and remains advisory: it is not target evidence,
  Queue work, or an automatic stop condition. CLI `show`, `record-degraded` and
  `clear`, host, runtime doctor and installer share `claude_runtime_root`: explicit
  root > `CCST_RUNTIME_ROOT` > `CLAUDE_CONFIG_DIR` > `~/.claude`. Host preserves
  unresolved links for its binding path checks; doctor/marker resolve after selection.
  Recovery is explicit, never inferred from PATH presence. Invalid UTF-8/schema,
  oversized files, symlinks and special files remain visible as invalid rather
  than hanging bootstrap; CLI invalid/error exit is 2. Startup never writes this marker.
- `surface_advisory` is a bounded read-only projection over the existing Surface
  review window. It may expose missing questions and a smallest-safe-probe
  description, but must not send requests, refresh stale projections, select a
  Skill, create owner continuations, or claim a Finding. Questions and local-read
  suggestions come from registry card `surface-unknown-probes`, with card/family
  provenance; missing material is unavailable, not a second hardcoded question set.
  Browser request-shape methods and inferred MIME remain explicitly unverified
  hints, not observed HTTP method/header facts. Shape labels never establish side effects. Any live probe
  still requires an explicit AI decision and the existing execution owner.
  JSON keeps at most 16 items and exposes `has_more_candidates`; Pack preserves
  the upstream `source_window` separately. Text shows at most 8 with a JSON
  expansion command, marks shortened questions, and identifies card/section/family.
  Remaining URLs use the existing Surface index, not an unbounded advice queue.
- `operational_metrics` derives only from the Pack's already verified `ledger_truth`
  snapshot, before binding recheck. It preserves source revision/health/truncation,
  excludes superseded rows, reports field/reference coverage and recorded unchecked
  mutations, and returns null rates for empty denominators. Unknown evidence roles
  are not complete. Safety outcomes, semantic replay and stopping compliance remain
  null with an explanation; an artifact ref does not prove any of them.
- Checks use PATH/file presence only; retired business lanes are not prerequisites. Never
  run version probes, subprocesses, networks, installers or browsers. Presence is
  not execution success; HTTPX tool identity remains Recon's responsibility.
- Session MCP names remain declarations, always unchecked here. A local browser
  importer file does not imply a session browser is available. The Agent uses its
  actually exposed tools; executors still enforce selected-path dependencies.
- Missing dependencies do not block Bootstrap or imply tested-clean. Profile errors
  return `checked=false`, `status=unknown`, `reason=profile-error`, empty fact sets;
  empty unknown sets do not claim absence. Target state still runs after fail-soft.
- URL-form targets keep canonical host state but retain exact path/query as
  `seed_url`; a valid relative `--auth-file` resolves against invocation cwd and
  is passed only to hunt/recon/scan paths.
- `continue` is the only action that may pass Runtime Preflight. Missing target
  uses `ask_target`; unknown flag, multiple target, conflicting cadence,
  overflow, or legacy-only flags use `stop_invalid_arguments`.
- `cadence_from_namespace()` is the shared helper for direct parser consumers;
  inline `/autopilot` uses the structured parser result as its only cadence
  source.

### 4. Validation & Error Matrix

- no target -> `valid=false`, `action=ask_target`
- unknown or legacy-only flag -> `valid=false`, `action=stop_invalid_arguments`
- two distinct cadence flags -> `cadence_conflict`, stop
- two targets -> `multiple_targets`, stop
- tenth captured non-empty token -> `overflow`, stop
- duplicate identical core flag -> accepted idempotently
- missing, conflicting, or unreadable `--auth-file` -> `stop_invalid_arguments`
- malformed auth content or a mismatched credential target -> `stop_invalid_context`,
  bounded non-secret diagnostic and no Store initialization
- invalid arguments/context or critical runtime drift -> `capabilities.checked=false`; profile and
  target state are not called
- advisory-only runtime drift -> project bounded advisory paths, then continue
- clean runtime + tools missing -> `capabilities.status=checked`, names in `missing`;
  `action=continue` without installation or inferred lane readiness
- capability probe raises -> `capabilities.status=unknown`,
  `reason=profile-error`; target state still runs and `action=continue`
- fresh single target + clean runtime -> explicit init before state read; loop-check
  and Round prepare can use the Store without requiring a later execution to create it
- repeated startup -> existing Store binding, goal, experience, Actions and Scope unchanged
- ordinary state query on an absent Store -> visible initialization error, no implicit init

### 5. Good/Base/Bad Cases

- Good: `/autopilot --quick https://target.test/orders?tab=open --deep --normal`
  emits canonical target, exact `seed_url`, `normal`, `quick=true`, `deep=true`,
  and `recon_flags=["--quick"]`.
- Good: `/autopilot target.test --auth-file .private/auth.json` emits an absolute
  `auth_file`, shell-safe path, and `hunt_auth_flags`.
- Base: `/autopilot target.test` emits `paranoid` and no recon flags.
- Base: `/autopilot` receives only the dynamic shell fallback and emits
  `ask_target`, never a synthetic target state for that executable path.
- Base: `nuclei` is missing but curl/native scanner helpers exist; bootstrap
  records `nuclei` in `missing` and continues without installation.
- Base: an unrelated command differs in the installed runtime; full doctor stays
  dirty, but `runtime.critical_clean=true` and bootstrap continues.
- Good: browser MCP is visible in the current Claude session; Claude uses it even
  though `session_managed` is not an availability probe, then imports useful
  artifacts through the existing browser evidence contract.
- Bad: inline docs advertise unsupported controller or worker flags as part of
  the slash-command contract.
- Bad: missing `httpx` or a session-managed browser MCP stops `/autopilot`, triggers
  an installer, or is recorded as recon/browser tested-clean.

### 6. Tests Required

- `tests/test_autopilot_args.py` covers target kinds, URL seed, auth relative/
  absolute/equal form, ordering, missing/unknown/conflict/multiple/overflow/
  legacy errors, empty dynamic-shell fallback, compact JSON, and direct helper
  reuse.
- `tests/test_autopilot_bootstrap.py` covers root/nested equivalence and proves
  invalid/drift gates do not read capability/target state, profile execution is
  ordered after runtime and before state, and profile failure remains advisory.
- `tests/test_capability_profile.py` covers full/empty PATH fixtures, helper-gated
  fallbacks, fixed MCP declarations, bounded/path-free lane output, per-lane
  isolation, read-only behavior, and unchecked versus checked-but-degraded.
- Parser wiring is covered by `tests/test_autopilot_args.py` and
  `tests/test_autopilot_bootstrap.py`; the former inline-contract test file is retired.
- `tests/test_claude_release_wiring.py` runs staged runtime + localhost fake API
  for real CLI discovery, empty arguments and flag-first quick/deep expansion.
- Current cold-start engineering acceptance lives in
  `.trellis/workspace/Codex/research/10-22-autopilot-cold-start/check_startup.py`.
  It calls real Bootstrap/Store/loop/Round APIs with baseline state readers,
  staged runtime receipts and an offline audit hook; it does not run project tests
  or establish real Claude Recon execution or host synchronization.
  Parser/bootstrap edge cases remain covered by their owner tests.

### 7. Wrong vs Correct

Wrong:

```text
Claude reads raw slash args and decides which flags to ignore.
```

Correct:

```text
Claude obeys the parser JSON action and fields before state/recon work begins.
After runtime is clean, Claude treats capabilities as bounded route hints and
continues through the best available evidence path without installing tools.
```

## Claude CLI Autopilot Startup Safety

### 1. Scope / Trigger

Use this contract whenever `/autopilot` startup ordering, candidate-rubric routing,
`tools/hunt.py` recon/scan execution, `tools/autopilot_state.py` list handling,
runtime markers, or target-owned URL filtering changes.

### 2. Signatures

- Bootstrap: `python3 tools/autopilot_bootstrap.py --json -- <slash tokens>`
- State refresh: `python3 tools/autopilot_state.py --target <domain|ip|cidr|list-file> [--json]`
- Recon phase: `python3 tools/hunt.py --target <target> --recon-only [--quick]`
- Scan phase: `python3 tools/hunt.py --target <single-target> --scan-only --quick`
- Runtime lock: `runtime_phase_lock(repo_root, target, phase)` where `phase` is
  `recon` or `scan`.
- Direct scanner: `bash tools/vuln_scanner.sh RECON_DIR [--quick] [--skip MODULES]`.
  Pass `SCANNER_LOCK_TARGET=canonical_target_value(SCANNER_AUTH_TARGET)` to
  `runtime_phase_exec.py --target`; the child compares that same identity with
  `BBHUNT_RUNTIME_LOCK_TARGET`. Keep the raw manifest target for auth/scope.
- Runtime liveness gate: `runtime_phase_in_progress(repo_root, target, phase, runtime_state=None)`.
- Hunt breadcrumb writer: `_persist_runtime_state(domain, *, mode,
  last_executed_workflow, ctf_mode=False, enrichment_tools=None)`.
- Target ownership: `url_belongs_to_target(url, target, allow_subdomains=True)`.

### 3. Contracts

- Every Claude CLI `/autopilot` invocation consumes one admission/bootstrap result
  before starting recon, scan, surface, or historical resume work. Bootstrap
  owns ctf mode, runtime drift, repo root, args, advisory capabilities, explicit
  single-target init and initial compact state. Inspect unfinished owner work before
  choosing investigation. New/empty targets without prior work or usable supplied
  request/source/browser evidence default to Recon in Shared Automation; supplied
  evidence may start directly. Existing-target inventory gaps do not force Recon.
- Compact bootstrap uses `build_autopilot_bootstrap_state()` and the same shared
  control-facts/action selector as full state. It may stat recon inputs and read
  bounded sidecars, but must not line-count/parse `with_params.txt`, load the
  monolithic observation body, call `load_surface_context()`/`rank_surface()`,
  synchronize inventory, or write target state. Only an exact-hit bounded
  projection may supply ranked candidates; otherwise expose missing/stale material
  as a residual rather than selecting a collection route. This state reader remains
  strictly read-only; initialization belongs to its explicit Bootstrap caller.
- Recon budget telemetry is read through `recon_artifacts.run_budget`, not a second
  Autopilot state owner. `status=ok` with `advisory_exceeded=true` remains eligible
  for normal Closure; `status=partial` is a resumable handoff and cannot be treated
  as tested-clean or target exhaustion.
  Local `--recon-only --deep --recon-collect katana|ffuf` preserves prior manifest
  receipts. `runtime_state._phase_gate_state` retains unrepaired collector failures
  as `collector:<name>` for full/fast/compact review; `_derive_current_status` stays
  partial until that collector succeeds. Local run_budget still describes the
  latest call. These residuals neither force Recon nor preempt independent work.
- State selector priority is `wait` -> owner revalidation/structured candidate
  evidence/validation -> validation-runner candidate -> substantive durable queue
  -> pending report/draft -> handoff. Shared Automation selects new investigation,
  including the fresh-target Recon default; the Python selector does not launch it.
  `action_queue.py` owns durable selection/sorting; `autopilot_state.py` only
  projects its selected row.
- Checkpoint-generated typed actions, including `viewstate-integrity-review`,
  remain substantive when their evidence type is `checkpoint-next-action` so
  they reach the Autopilot frontier without broadening generic command rules.
- Legacy target-memory is a visible recovery bridge, not a lifecycle owner. Only
  an independent `/validate` command token may become `memory_candidate_next`;
  validation prose stays visible without promotion, and it must not mask
  `draft_completion_pending` or `validated_pending_report`.
- A structured `next_validation` with explicit `rubric.ready=false` returns
  `collect_candidate_evidence`; `rubric.ready=true` returns `validate_finding`.
  Legacy candidates without a rubric keep `validate_finding` compatibility.
  Live recon/scan wait gates always remain higher priority than either candidate
  action.
- Bootstrap `state.structured_next.rubric` is a bounded decision projection, not
  a second evidence model: keep rubric identity/status/readiness/counts, at most
  three `missing_labels`, and one non-empty `next_actions` item. Do not copy full
  finding/checkpoint/raw evidence into the dynamic slash-command prompt.
- A recon directory with no live inventory is `recon_no_live_hosts` only when a
  completed, non-running workflow breadcrumb exists. It records offline/infra
  evidence and never automatically restarts recon.
- `hunt_target()` acquires `state/<target_key>/locks/<phase>.lock` before writing
  `run_recon_started` or `run_scan_started`. The file descriptor remains open for
  the entire long phase; process exit releases the kernel `flock` automatically.
- Hunt breadcrumb writes pass only persisted fields to `update_runtime_state()`.
  Do not query Recon/Finding to populate discarded derived fields: an unavailable
  projection must not prevent a phase marker from being saved. Readers derive
  current state; the owner retains its legacy rename and whitelist compatibility.
- A Claude-facing wait action requires both a matching running breadcrumb
  and its matching target/phase `flock` to still be held. A released lock makes
  the marker orphaned: state, checkpoint, and queue readers must immediately
  resume normal action selection without deleting the marker or guessing a PID.
- A full classic single-target run acquires locks in fixed order `recon` then
  `scan`. List targets may acquire only `recon`; list scan/hunt is invalid.
- List state reads current normalized list entries on every invocation and returns
  `target_kind=list`, `next_action` in `invalid_batch_target`, `run_batch_recon`,
  `wait_recon`, or `select_completed_domain`, plus current,
  completed, failed, pending, candidate, and artifact projections.
- A completed domain must be selected and passed to a new single-target state
  preflight before surface/scan/hunt. `recon/<list-stem>/` remains an index.
- `url_belongs_to_target()` checks absolute URLs against each non-comment primary
  target in a readable list. It accepts root/subdomain matches and rejects
  third-party URLs; nested list files are not recursively expanded.

### 4. Validation & Error Matrix

- Same target + same phase already locked -> raise `RuntimePhaseBusy`; CLI exits
  with code `2`; do not write or clear the real runner's runtime marker.
- Hunt breadcrumb write failure -> preserve the old session and emit the existing
  non-fatal warning; do not suppress diagnostics or change phase execution results.
- Different target or different phase -> locks do not conflict.
- Recon reaching normal end with an actual incomplete phase/collector returns 75;
  Hunt and direct runtime wrappers retain their existing failed breadcrumbs, and
  batch targets remain pending. Optional missing tools and advisory derived caches
  keep their phase receipts without requesting an automatic full Recon restart.
- `test_runtime_state.test_local_collection_preserves_unrepaired_collector_failure`
  fixes gau error → local success → skipped/unavailable → real success: only the
  last clears the failure; stale clean review cannot claim exhaustion beforehand.
- Direct scanner URL/bare-host/missing-manifest inputs all reach admission when
  unlocked; real same-target scan contention returns `75` before scanner artifacts.
  An empty recon fixture reaches the explicit no-live-host error without network I/O.
  Shell status output must follow variable initialization under `set -u`.
- Unsupported lock phase -> `ValueError`; do not create a phase scheduler implicitly.
- Fresh list without completed domains -> `next_action=run_batch_recon`.
- Matching running batch marker plus held recon lock -> `next_action=wait_recon`
  even if handoff files exist; a marker with a released lock is not a wait.
- Completed domains available -> `next_action=select_completed_domain`; candidates
  must be a subset of completed domains.
- Empty current list -> `invalid_batch_target`. Failed entries remain pending for
  a later bounded `run_batch_recon`; untried inputs precede retries, which rotate
  by last attempt using shared `recon_target_selector.batch_progress`. Successful
  domains remain available for immediate selection. Legacy `batch_failed` state
  is still recognized by terminal-state consumers.
- Rewritten list input filters old completed/failed/pending/candidate artifacts;
  only current entries may reach completed-domain handoff.
- Missing/invalid batch JSONL or score -> ignore the invalid record/score and keep
  the state preflight usable.
- Absolute URL outside every list root -> `False`; relative path -> `True`.
- Structured candidate rubric explicitly not ready ->
  `next_action=collect_candidate_evidence`; output names the bounded gaps and first
  evidence action, then requires a state refresh before `/validate`.
- Structured candidate rubric ready or absent on a legacy row ->
  `next_action=validate_finding`.
- Bare `validate`, `validated`, `validation`, `/validated`, or `/validate-later`
  target-memory prose -> no memory candidate; an independent `/validate` keeps
  legacy evidence/no-evidence routing unless canonical report closure is pending.
- Fresh recon/scan marker with its matching held lock plus a non-ready candidate
  -> return the matching wait action; do not collect evidence or validate until
  the long phase completes.

### 5. Good/Base/Bad Cases

- Good: state reports `wait_recon`; Claude waits, while a concurrent direct CLI
  attempt also fails at the recon lock without changing `session.json`.
- Good: a host kills a background scanner after it wrote `run_scan_started`; the
  flock is released while `session.json` remains fresh, and the next state read
  immediately selects normal cached work instead of waiting for two hours.
- Good: an Authz candidate missing actor comparison and response-diff evidence
  reaches Claude as `collect_candidate_evidence` plus one concrete replay action;
  after evidence updates the rubric, a new state read returns `validate_finding`.
- Base: state reports `run_recon`; one process acquires the lock, writes the
  running marker, completes, and writes the completion workflow.
- Base: an old structured candidate has no rubric; startup preserves the previous
  `validate_finding` behavior rather than treating the absent field as false.
- Good: a validated finding with an unresolved draft/report and optional handoff
  prose reaches `complete_report_draft`/`report_finding`, not candidate evidence.
- Bad: prompt launches recon before state inspection, or a busy process writes a
  second running/completion marker after lock acquisition fails.
- Bad: any `next_validation` immediately becomes `/validate`, or bootstrap drops
  missing evidence / injects the complete raw finding payload.
- Bad: `/autopilot targets.txt` runs surface/scan against `recon/targets/` instead
  of selecting `alpha.example` and restarting state inspection for that domain.

### 6. Tests Required

- Prompt ordering: bootstrap precedes all project commands; root/nested execution
  prefixes project calls with bootstrap `repo_root_shell`.
- Lock behavior: same target/phase conflicts; target/phase isolation and release
  after context exit succeed; a held lock plus matching marker waits, while a
  released marker is an orphan and does not wait.
- Busy behavior: `hunt_target()` does not call recon or `_persist_runtime_state`.
- `tests/test_runtime_state.py` proves hunt breadcrumb writes perform zero
  Recon/Finding queries, preserve validation breadcrumbs, and retain success,
  failure, interruption, busy-lock and batch behavior with real session writes.
- `tests/test_scanner_store_registration.py` exercises the real direct wrapper
  with URL/bare-host/no manifest, both unlocked and under a held canonical lock.
  Empty recon proves admission without network I/O; contention returns 75 with
  no scanner artifacts or runner marker. Do not inject a pre-held child marker
  or a default Nuclei status into this regression.
- Batch state: manifest fallback, current-input filtering, empty/all-failed
  terminals, completed-only ranking, and formatted single-domain handoff are asserted.
- Target ownership: list root/subdomain/port positive cases, third-party negative
  case, and nested-list non-recursion are asserted.
- Candidate routing: `tests/test_autopilot_state_tool.py` asserts ready, non-ready,
  legacy, wait-preemption, exact `/validate` token boundaries, and report-closure
  precedence plus the human-readable evidence action, including the
  `viewstate-integrity-review` checkpoint route.
- Bootstrap/prompt wiring: `tests/test_autopilot_bootstrap.py` asserts rubric list
  bounds and raw-payload exclusion. Command/runtime guidance is covered by
  `tests/test_ai_native_skill_convergence_baseline.py`; the former startup-contract
  test file is retired.
- Run targeted tests plus full `pytest -q` and `git diff --check`.

### 7. Wrong vs Correct

Wrong:

```text
fresh guess -> launch recon -> read state later
next_validation -> /validate (rubric evidence ignored)
"validated report" memory prose -> collect_candidate_evidence
targets.txt -> recon/targets/ -> scan aggregate index
```

Correct:

```text
state preflight -> wait | collect_candidate_evidence | validate_finding | cached work
explicit /validate memory token -> legacy recovery; canonical report -> report closure
targets.txt -> batch recon -> select completed domain -> domain state preflight
```

## Scenario: Automation-Only Entry Contracts

### 1. Scope / Trigger

Apply when changing Autopilot entry guidance or its shared reading boundaries.
Autopilot automates the existing investigation, rather than defining another
method. This supersedes both the old combined 11 KiB cap and the expanded
readability revision.

### 2. Signatures

- Keep command frontmatter, critical manifest and exact dynamic Bootstrap lines.
- `skills/autopilot-protocol.md#shared-automation` owns restore/continue/execute/refresh
  timing and stopping. Keep its `state-consumption-loop` and `investigation-skill`
  anchors; Round and Bootstrap consume the former paths.
- `skills/runtime-protocol.md#native-skill-loading` owns body loading/reuse/recovery.
  `commands/checkpoint.md#global-review` owns review scope and snapshot submission.
- `skills/autopilot-round-protocol.md` retains prepare, claim, heartbeat, correction,
  settle/status and exact native-loop cleanup. Ordinary Autopilot reads it only
  to recover existing Round obligations; it does not start a Round implicitly.

### 3. Contracts

- Keep the main command near upstream scale (about 4–6 KiB including wiring).
  Delete duplicated explanations; keep the original complete body in its installed
  protocol resource and deliver it automatically. Do not add expanded controller
  prose or require a second manual read of already delivered content.
- Measure the command, shared owners, resident imports and conditional sections
  separately. Remove duplicate prose; a required execution/recovery example may
  grow its on-demand owner document. Report comparable static startup/action/finish
  reading sets, including the unchanged resident baseline and added bytes.
  Bytes do not prove tokens, fees, host loading or investigation effectiveness.
- Native dispatch examples supply actual Skill `skill/args` and Agent
  `subagent_type/description/prompt`; use host-exposed names. Ranker receives explicit
  deep/mode/budget and zero target requests, with DEEP HUNT MODE applied to review.
- Same-call state may reuse Resume runtime/recon/repo-source facts and an explicit
  `coverage_state` passed to `build_autopilot_state`/`load_closure_projection`.
  Closure rechecks discovery fingerprint and reacquires current evidence bytes;
  drift rejects reused Coverage. Public queue/case snapshot arguments are forwarded.
  No cross-call cache, serialized private truth or changed memory page windows.
- Explicit Autopilot applies src-hunter after admission/recovery and before new
  investigation. Native Skill loading never points back to an automation entry.
  Full existing 6k rules, methods, discovery description and modules remain intact.
- Bootstrap returns data, not automatic continuation. Claude must obey action and
  hard gates, wait on real locks, preserve pending work, execute/record and read
  fresh control. Owner continuation order and loop_guard remain advisory.
- Round alone adds new Round claims/heartbeats. Existing unfinished Round work
  still needs recovery from ordinary mode. Registration precedes heartbeat;
  heartbeat precedes refresh. Report identity and corrections remain Round-owned.
- Scope/Auth/context, pre-execution Action claims, evidence receipts, unknown-effect
  recovery and failure handling remain in the selected execution owner. Preserve
  exact argv and read the complete section before use. Never replace a parent-bound
  executor by dropping context.
- Detailed browser/registration retry rules remain at their owners. The default
  failed-source rule permits only explicit bounded exceptions; failed Action claims
  do not gain retries. Browser cleanup still runs before leaving a used session.
- Continue after publication unless an actual stopping reason holds. Handoff,
  report count, anonymous denial or missing-but-obtainable sessions are not reasons
  alone. Budget limits new work, not recovery/cleanup/write-back/Checkpoint/Closure.
  Exhaustion needs fresh Closure finish plus can_claim_exhausted, with Global Review.
- Keep exactly one final presentation-only Memory recommendations section. It
  does not write, promote knowledge or alter routing/budget/lifecycle.
  Optional `agents/autopilot.md` remains a delegation contract, not a second loop.

### 4. Validation & Error Matrix

- Changed Bootstrap line/manifest/frontmatter -> native entry wiring may break.
- Missing Shared Automation body/anchor -> Round or Bootstrap loses instructions.
- Malformed applicable command frontmatter or missing compatibility heading ->
  capture/SessionStart/Refresh still fail after moving its body to a protocol resource.
- Native Skill body absent or circular reference -> restore from its shared owner.
- Missing owner section -> cannot treat a link as preserved behavior.
- Failed/missing state -> recover; do not act on stale control.
- Round recovery removed from ordinary mode -> stranded claimed execution.
- Smaller entry with larger mandatory reading set -> no proven context reduction.

### 5. Good/Base/Bad Cases

- Good: restore -> continue src-hunter -> execute/write back -> refresh -> repeat.
- Base: selected action reads its existing complete execution section once and
  reuses it until invalidated; finish reads the existing review owner.
- Bad: copy method steps into Autopilot, create a new controller/manual, or delete
  an explicit wait/claim/write-back trigger because the called tool validates inputs.

### 6. Tests Required

- One isolated focused check: real parser-backed usage, exact release wiring,
  complete Round shared-section consumption, incoming/outgoing links, actual lane
  extraction, preserved method bytes and composed reading measurements.
- `11-09-autopilot-entry-single-delivery/research/check_entry_delivery.py` under
  `.trellis/tasks/` checks exact moved bodies, actual staged body CLI, compact/restart,
  changed sources, both command/protocol corruption and critical installed resources.
  Refresh owner acquisition is explicitly stubbed; token estimates exclude Bootstrap
  JSON. Full receiver/model adherence and real request billing remain unverified.
- Review normal, blocked, compaction, pending-Round, validation/publication and
  finish paths for retained obligations. Static checks do not establish Claude behavior.
- Historical document-shape assertions need separate review; this 2026-10-22 scope
  neither reads nor changes project tests. Evidence remains in workspace research.

### 7. Wrong vs Correct

Wrong: duplicate a full command suffix in its dynamic output, or replace required
body context with a link. Correct: automatically deliver the complete protocol once,
retain entry gates and source validation, and measure the composed input.

Correct: keep automation timing in the entry, full methods with src-hunter,
shared loading/write-back with runtime-protocol and review details with Checkpoint.

## Claude Runtime Packaging and Drift Preflight

### 1. Scope / Trigger

Use this contract whenever `install.sh`, `tools/runtime_doctor.py`, files below
`skills/`, or `/autopilot` runtime preflight wording changes. Skill references
are executable prompt resources, not optional repository documentation.

### 2. Signatures

- Full staged install: `HOME=<staged-home> bash install.sh`
- Read-only full drift check:
  `python3 tools/runtime_doctor.py --kind commands,agents,skills --fail-on-drift`
- Read-only Autopilot gate:
  `python3 tools/runtime_doctor.py --kind commands,agents,skills --fail-on-critical-drift`
- Explicit mutation after operator confirmation:
  `python3 tools/runtime_doctor.py --sync [--prune] --kind <kinds>`
- Programmatic APIs: `load_critical_runtime_manifest(repo_root)`,
  `compare_runtime(repo_root, runtime_root, kinds)`, and
  `sync_runtime(repo_root, runtime_root, kinds, prune=False)`.

### 3. Contracts

- Repo-managed Skill files are all regular files under each repo-owned
  `skills/<name>/` directory, recursively, plus shared top-level `skills/*.md`.
- Flat `commands/*.md` and `agents/*.md` are runtime sources except explicit local
  development artifacts ending in `.patch.md` (case-insensitive within that
  existing `*.md` source set). Doctor owns this discovery rule; `install.sh`
  delegates to Doctor rather than maintaining separate shell copy loops.
  A repo-side patch stays in place and is never copied; a patch previously
  copied into runtime is an `EXTRA`. Explicit prune removes it only when its
  receipt and unchanged bytes establish ownership.
- Runtime inventory recursively scans current repo-owned Skill roots and includes
  receipt-owned retired files. Single-entry checks also inspect the complete selected
  Skill tree for the finite known identities in `skill_reference_contract`; identity
  may differ from the directory name. Quoted keys/names are inspected; aliases,
  merges, ambiguous preambles or uninspectable frontmatter reject the check.
  Unrelated external Skills are not drift/prune.
  Runtime discovery reads external directory/entry-file links only to inspect
  their logical entry path and actual identity; renamed linked CCST identities
  still conflict. Ancestor directory cycles stop expanding. Repo sources,
  the selected skills root, managed destinations and ownership metadata remain
  link-free; read compatibility never permits writing or pruning through a link.
- Managed-root nested extras are drift, but a directory name is not file
  ownership. `--sync --prune` removes only unchanged receipt-owned retired files.
  Unknown or locally modified files remain; modified owned files report conflicts.
- `install.sh` delegates to `runtime_doctor --sync --prune` for one ownership-bound
  publication path. It copies current Skill resources recursively and retires
  unchanged owned files, including files under a removed Skill root. Empty
  directories are not deleted. Unowned known legacy/duplicate entries reject a
  single-entry cutover, rather than silently coexisting with a clean result.
- Compare, sync, and prune must use the same repo/runtime file discovery contract.
- `commands/autopilot.md` owns the versioned JSON critical manifest. It lists
  runtime-relative command/agent/skill paths plus declared MCP contracts,
  publishes a canonical SHA-256, and excludes HackerOne MCP.
- `compare_runtime()` retains complete `kinds`, `drift_count`, and `clean`, then
  adds `critical_drift`, `missing_critical`, `advisory_drift`, their counts,
  `critical_manifest`, and `critical_clean`. Missing/invalid manifest state is
  both full drift and critical drift.
- A pending `.ccst-entry-migration.json` is critical drift even when all installed
  payload bytes already match. Compare never completes it. Detailed publication,
  same-version recovery and ownership contracts are in Ownership-bound runtime installation below.
- `/autopilot` dynamic bootstrap locates the Git worktree and runs a read-only
  doctor compare before ctf mode, state inspection, recon, surface, or scan.
  Only `critical_clean=false` returns `stop_runtime_drift`; advisory drift is
  bounded in bootstrap and continues. Runtime mutation requires explicit
  operator confirmation and is never automatic.

### 4. Validation & Error Matrix

- Missing repo kind directory -> empty managed file set; doctor remains usable.
- Managed nested file missing/different -> `MISSING` / `DIFF`, non-zero with
  `--fail-on-drift`.
- Critical file diff/missing or invalid manifest -> non-zero with both
  `--fail-on-critical-drift` and strict `--fail-on-drift`.
- Advisory-only drift -> zero with `--fail-on-critical-drift`, non-zero with
  strict `--fail-on-drift`.
- Managed nested runtime-only file -> `EXTRA`; explicit `--prune` removes it only
  when its ownership receipt and unchanged bytes authorize retirement.
- Repo command/agent ends in `.patch.md`, `.PATCH.md`, or `.PaTcH.md` -> ignored
  during install and Doctor source discovery; same filename already in runtime
  -> `EXTRA`. Explicit prune removes only an unchanged owned copy, without
  touching the repo copy.
- Ordinary names such as `local.md` or `local.patch-notes.md` -> copied unchanged;
  patch exclusion must not become a substring filter or enable disabled commands.
- Unrelated external Skill root, including a directory or SKILL.md file link ->
  inspected for identity, ignored as drift and preserved. A linked known CCST
  identity, including renamed/nested entries -> visible error. Repo source links,
  a linked skills root, unreadable entry files or ambiguous identity syntax
  prevent a complete entry inspection. An asset link without an entry is not a
  CCST identity merely because its directory has a known name.
- Repo-root marker missing -> `/autopilot` stops and asks the operator to launch
  Claude from this repository.
- Critical runtime drift -> `/autopilot` stops, shows `/sync-check`, and requests explicit
  confirmation before any sync.

### 5. Good/Base/Bad Cases

- Good: staged install copies `SKILL.md`, cheatsheets, references, and nested
  resources; doctor immediately reports clean for commands/agents/skills.
- Base: a Skill contains only `SKILL.md`; recursive copy behaves like the old install.
- Base: an unrelated command drifts; Runtime Doctor reports it as advisory and
  strict mode fails, while Autopilot startup continues.
- Bad: installer copies only `*/SKILL.md`, leaving progressive-loading links broken.
- Bad: using a known-identity inspection to report/prune unrelated user capabilities,
  or ignoring a retired identity merely because its directory was renamed.
- Bad: a local design note such as `agents/autopilot-fix.patch.md` blocks every
  `/autopilot` invocation or is installed as an executable Agent.
- Bad: `/autopilot` detects drift and silently runs `--sync` against `~/.claude`.

### 6. Tests Required

- Staged HOME install compares each current Skill's complete relative file set
  and bytes against the repo; retired owned files follow receipt-based cleanup.
- Staged install output must be clean under `compare_runtime()` for all kinds.
- Runtime fixtures cover nested missing, diff, managed extra, sync, and prune.
- Runtime fixtures cover critical diff, missing-critical, advisory-only drift,
  missing/invalid manifest, manifest hash, HackerOne exclusion, and both gates.
- Runtime fixtures prove external Skill nested resources survive compare/prune.
- Runtime link fixtures prove external directory/file links pass the real
  Bootstrap runtime gate; renamed/nested CCST identities still stop it. Cycles
  terminate, external bytes survive sync, and managed write checks remain strict.
  Focused isolated acceptance lives in
  `.trellis/tasks/10-20-business-tools-native-execution/research/runtime-skill-links-check-20261021.py`.
- Upgrade/repeat fixtures exercise the shared ownership-based installer, with
  command and agent patches in lower/upper/mixed case plus ordinary/near-match filenames.
  Every install retains source bytes, excludes patches, and preserves disabled
  commands, external Skills, private settings/material, and Store binding.
- Doctor fixtures cover both kinds and all three patch spellings: repo sources
  cause no `MISSING`; an old runtime copy is reported as `EXTRA`, only unchanged
  owned copies are pruned, and the repo file remains byte-identical.
- A synthetic predecessor must exercise retired Skill identities and migration to
  the sole `src-hunter` entry, then compare every current installed
  file and receipt against source bytes. Full `--fail-on-drift` is required;
  critical-only checks do not cover every current module. Known unowned old entries
  cannot coexist with a clean single-entry result; unrelated external Skills can.
- The existing PR `core-contracts` job must run `tests/test_install_script.py` and
  `tests/test_runtime_doctor.py`, enforced by `tests/test_ci_contract.py`; do not
  defer these regressions solely to the main-branch full suite.
- Autopilot prompt tests assert repo-root/drift checks precede state/recon/surface/
  scan and that the preflight contains no `--sync` action.
- Run targeted pytest, full `pytest -q`, and `git diff --check`; release acceptance
  runs doctor against an explicit staged runtime, never the operator's default.

### 7. Wrong vs Correct

Wrong:

```text
skills/<name>/SKILL.md -> ~/.claude/skills/<name>/SKILL.md
doctor -> scan/prune every ~/.claude/skills/* root
```

Correct:

```text
skills/<managed-root>/**/* -> ~/.claude/skills/<managed-root>/**/*
doctor -> recurse current repo roots + receipt-owned retired files; ignore unowned external roots
commands/*.md - case-insensitive *.patch.md -> ~/.claude/commands/*.md
agents/*.md - case-insensitive *.patch.md -> ~/.claude/agents/claude-bug-bounty/*.md
full drift -> --fail-on-drift; Autopilot-only drift -> --fail-on-critical-drift
```

## Real Claude Runtime Wiring Tests

### 1. Scope / Trigger

Use this contract whenever installed Claude commands/agents, slash-command
frontmatter, `$ARGUMENTS`, Claude CLI discovery paths, or staged runtime tests
change. Lexical assertions alone do not prove that Claude CLI loads a file.

### 2. Signatures

- Staged install: `HOME=<tmp-home> bash install.sh`
- Slash probe:
  `claude -p --setting-sources user --tools Bash --allowedTools 'Bash(python3 *)' --strict-mcp-config --no-session-persistence "/autopilot <args>"`
- Fake API routing: dummy `ANTHROPIC_API_KEY` plus
  `ANTHROPIC_BASE_URL=http://127.0.0.1:<ephemeral-port>`.

### 3. Contracts

- Real wiring tests run the installed Claude binary and staged user runtime;
  they do not call a parser that merely imitates Claude behavior.
- The fake endpoint accepts the Anthropic Messages POST and returns a complete
  minimal SSE message ending in `message_stop`. It never forwards traffic.
- Tests build an allowlisted child environment with staged user/config paths,
  dummy API key, localhost base URL, no session persistence and disabled
  non-essential traffic. Only the Python bootstrap expansion needs Bash; a fully
  empty tool set denies that expansion in Claude Code 2.1.278. The fake endpoint
  returns text only and never emits tool calls. Real OAuth/provider/config
  variables are not inherited; MCP config is strict.
- `/autopilot <args>` must produce `command-message=autopilot`,
  `command-name=/autopilot`, exact raw `command-args` when non-empty, and the
  installed command body with YAML frontmatter removed and its root-aware
  `$0..$9` bootstrap expansion replaced. Bootstrap and target reads run from
  an isolated checkout, not the operator's workspace state. Copy only the flat
  `memory/*.py` modules; copying the whole `memory/` directory also carries
  untracked `memory/goals/targets` state into the fixture.
- Empty slash arguments omit `command-args`. Claude may supply its executable
  shell as dynamic `$0`; the expanded bootstrap must normalize that interface
  fallback to empty argv and still require the exact target.
- The optional `--agent autopilot` is not the slash-command backend; release
  acceptance covers the current inline slash entry, not that optional mode.
- Staged install parity remains a socket-free required layer. Real CLI wiring
  is a second layer that skips explicitly when the binary or localhost sockets
  are unavailable.

### 4. Validation & Error Matrix

- `claude` absent -> explicit pytest skip; do not substitute a fake executable.
- Local bind fails with `EPERM` -> explicit pytest skip with sandbox reason.
- Installer fails or staged doctor reports drift -> fail before invoking Claude.
- CLI reports unknown command/agent, exits non-zero, or does not call localhost
  -> fail with captured stdout/stderr.
- Request path is not Anthropic `/v1/messages` -> fail wiring test.
- Command metadata/body differs, frontmatter leaks, or the root-aware dynamic
  bootstrap remains -> fail exact expansion assertion.
- Any real auth/provider config could override the dummy path -> remove it from
  the child environment before launch.

### 5. Good/Base/Bad Cases

- Good: `/autopilot --quick example.test --deep` reaches localhost with the exact
  raw args and an expanded staged command body; fake SSE returns a fixed result.
- Good: `/autopilot` omits `command-args` but retains the missing-target rule.
- Good: `--agent autopilot` includes explicit optional-agent boundary text and
  the original user prompt.
- Base: a CI worker has no Claude binary or cannot bind localhost; parity and
  lexical contracts run, while real wiring cases report skip.
- Bad: tests read `commands/autopilot.md` directly and claim slash wiring passed.
- Bad: tests use real Anthropic credentials/network or allow the command prompt
  to execute recon/scan tools.
- Bad: `--bare` is used for legacy custom command discovery; Claude reports
  `/autopilot` as unknown.

### 6. Tests Required

- `tests/test_claude_release_wiring.py` executes real Claude CLI against the
  localhost fake endpoint for empty arguments and a flag-first quick/deep target.
  It checks command metadata, parsed bootstrap fields and the remaining installed
  body exactly. Argument edge cases retain their existing parser tests; do not
  restore the deleted broad runtime integration test merely to satisfy stale refs.
- `tests/test_install_script.py` must keep the socket-free staged install and
  `runtime_doctor.compare_runtime(clean)` assertion.
- Run the wiring test in a localhost-capable environment and record the CLI
  version and pass. An absent CLI or denied bind is an explicit skip, never
  release evidence; obtain a successful host run before claiming compatibility.
- Run related runtime/autopilot tests, full pytest, and `git diff --check`.

### 7. Wrong vs Correct

Wrong:

```text
read repo Markdown -> assert keyword -> claim Claude slash command works
```

Correct:

```text
install staged runtime -> real claude -p -> localhost fake Messages API
-> inspect command metadata, expanded body, raw args, and agent prompt
```

## Long-Running Runtime Phase Markers

### 1. Scope / Trigger

Use this contract whenever a Claude-facing command can launch a long-running
background phase from `tools/hunt.py` or an equivalent wrapper, especially
`--recon-only` and `--scan-only --quick`. Process-list checks are diagnostics
only; runtime flow control must use durable target state.

### 2. Signatures

- `python3 tools/hunt.py --target <target> --recon-only [--quick]`
- `python3 tools/hunt.py --target <target> --scan-only --quick`
- `python3 tools/autopilot_state.py --target <target>`
- `python3 tools/action_queue.py next --target <target>`
- `python3 tools/action_queue.py ingest-checkpoint --target <target>`
- Runtime state file: `state/<target_key>/session.json`
- Running breadcrumbs:
  - recon start: `mode=recon_running`, `last_executed_workflow=run_recon_started`
  - scanner start: `mode=scan_running`, `last_executed_workflow=run_scan_started`

### 3. Contracts

- `hunt.py` must write the relevant `*_running` breadcrumb immediately before
  starting the long-running phase, then overwrite it with the completed workflow
  name when the phase exits.
- `autopilot_state.py` must convert a matching running breadcrumb into a wait action
  only while its matching target/phase `flock` is held: `next_action=wait_recon`
  or `next_action=wait_scan`. A matching breadcrumb with a released lock is an
  orphaned process record, not an active wait.
- `action_queue.py next` and queue summaries must honor the same wait action as a
  transient egress gate. Existing queued validation/report/surface work stays on
  disk and resumes after the marker clears or the matching lock releases.
- `action_queue.py ingest-checkpoint` must not retire existing checkpoint actions
  merely because checkpoint is currently in `wait_recon` / `wait_scan` and
  therefore emits an empty `next_action_queue`.
- Running breadcrumbs use a bounded stale window only as a compatibility and lock
  probe-error fallback. A released lock clears their wait effect immediately, and
  a held lock remains authoritative even after the old timestamp window.
- These breadcrumbs are execution state only. They must not encode attack-surface
  value, scanner-negative completion, tested-clean status, or finish readiness.
- Prompt text may mention the wait actions, but must not ask Claude to infer
  running state from `ps`, shell job text, or repeated startup narration.

### 4. Validation & Error Matrix

- Matching `recon_running/run_recon_started` + held recon lock + missing ready recon
  artifacts -> `wait_recon`; do not relaunch recon.
- Matching `recon_running/run_recon_started` + released/missing recon lock -> allow
  normal recon selection immediately.
- Stale `recon_running/run_recon_started` with no held recon lock -> allow one
  fresh recon run.
- Matching `scan_running/run_scan_started` + held scan lock -> `wait_scan`; do not
  relaunch `scan-only --quick`.
- Matching `scan_running/run_scan_started` + released/missing scan lock -> resume
  normal state/checkpoint/queue selection immediately.
- Matching `scan_running/run_scan_started` plus held scan lock and old queued
  validation/report/surface actions -> `action_queue next` returns a transient
  `wait_scan` pointer without deleting or resolving the old actions.
- Stale `scan_running/run_scan_started` with no held scan lock -> allow one fresh
  scanner run.
- Completed `run_vuln_scan` or `run_recon` breadcrumb -> normal AI-first
  surface/context/checkpoint flow resumes.

### 5. Good/Base/Bad Cases

- Good: recon is complete, scanner quick starts, session state says
  `scan_running/run_scan_started`; the next `/autopilot` prints `Scan: in
  progress` and waits/polls instead of starting a second scanner.
- Good: while scan is running, `action_queue next` prints `runtime-wait`; after
  `run_vuln_scan` is written, the same queued validation/report action becomes
  selectable again.
- Good: an abruptly terminated scanner leaves its marker on disk but loses
  its flock; `autopilot_state`, checkpoint, and `action_queue next` stop returning
  `wait_scan` without requiring a marker rewrite.
- Base: scanner quick finished and state says `run_vuln_scan`; `/autopilot`
  reads cached recon/surface evidence and lets Claude choose the next hypothesis.
- Bad: prompt text says "if scan is already running, do not start another" but no
  durable state exists, so a new Claude turn starts the same scanner again.
- Bad: checkpoint wait output has an empty `next_action_queue`, and
  `action_queue ingest-checkpoint` marks older valid actions `n/a`.
- Bad: a scanner-negative or timed-out phase writes `tested_clean` or suppresses
  high-value leads.

### 6. Tests Required

- `tests/test_runtime_state.py` and `tests/test_runtime_phase_execution.py`
  must assert running breadcrumbs before phase execution, wait only while the
  matching lock is held, and terminal breadcrumbs plus reusable locks afterwards.
  Preserve hunt recon failure's `recon_only/run_recon` versus direct's
  `recon_failed/run_recon_failed`; these are not interchangeable.
- `tests/test_runtime_state.py` must assert a child process holding a running
  phase lock yields a wait, then termination releases the lock and clears that
  wait while the marker remains fresh.
- `tests/test_autopilot_state_tool.py` must assert matching recon/scan markers
  with held locks produce `wait_*`, while released locks resume normal behavior.
- `tests/test_action_queue.py` must assert `action_queue next` respects live
  runtime wait gates, does not delete queued actions, and an orphan marker leaves
  the queue selectable; checkpoint wait projections do not retire existing queue
  entries.
- `tests/test_autopilot_state_tool.py` must assert command and agent prompts mention
  `wait_recon`, `wait_scan`, `Recon: in progress`, and `Scan: in progress`.

### 7. Wrong vs Correct

#### Wrong

```markdown
If `ps` shows hunt.py is running, do not start another scan.
```

#### Correct

```python
with runtime_phase_lock(repo_root, target, "scan"):
    _persist_runtime_state(
        target,
        mode="scan_running",
        last_executed_workflow="run_scan_started",
    )
    # autopilot_state.py renders wait_scan only while this lock is held.
    run_vuln_scan(target, quick=True)
```

## Scenario: Active target and child-process argv boundary

### 1. Scope / Trigger

Use for any active target entry point or scanner wrapper that passes target,
URL, path, option, or token-derived data to a child process. State readers may
still use `canonical_target_value()` for legacy lookup compatibility; active
callers must use strict `classify_target()` first.

### 2. Signatures

```python
classify_target(value) -> {"kind": "domain|ip|cidr|list", "target": str}
target_https_url(value) -> str
run_argv_command(argv, *, cwd=None, timeout=600, env=None) -> (bool, str)
run_argv_command_split(argv, *, cwd=None, timeout=600, env=None) -> (bool, str, str)
run_live_argv_command(argv, *, cwd=None, env=None, timeout=None,
                      pass_fds=(), require_signal_handlers=False) -> int
```

### 3. Contracts

- Active targets accept existing files, domains (including localhost and
  single-label lab hosts), leading wildcards, IP/CIDR, bracketed IPv6, valid
  host:port, and HTTP(S) URLs. URL paths/queries remain exact seed data while
  canonical identity is host/port only.
- Active parsing rejects empty/raw whitespace or control characters, unsupported
  or nested schemes, userinfo, malformed brackets/IPv6, invalid ports, path-like
  non-files, non-ASCII hosts, and command syntax before state or process effects.
  Existing readable paths may contain ordinary spaces; control characters are
  always rejected.
- Canonical DNS identity is lowercase for bare, host:port, wildcard, and URL
  forms. One trailing absolute-DNS dot is accepted and removed; two or more
  trailing dots are invalid active input and never match target scope.
- `target_https_url()` formats a strictly classified target as an HTTPS origin;
  bare IPv6 authorities use brackets while existing IPv6 ports remain intact.
- `target_storage_key()` may sanitize a historical non-active label for cache or
  read compatibility. It is not an active validation gate; active orchestrators
  must call `classify_target()` before deriving a storage path.
- `run_argv_command[_split]` requires a non-empty `Sequence[str]`, uses
  `shell=False`, and preserves cwd/env, text pipes, timeout diagnostics, and
  process-group SIGTERM/SIGKILL cleanup. Shell helpers remain only for explicit
  static shell syntax.
- `runtime_exec.run_live_argv_command` is the mechanical owner for hunt recon,
  hunt scan, and direct phase execution. It reuses argv validation and `_spawn`,
  inherits stdout/stderr, and returns the raw exit code. It owns SIGINT/SIGTERM
  installation/restoration; callers retain target locks, breadcrumbs and domain
  work, with no parallel Popen/wait/signal/kill implementation.
- Live and captured execution share `_terminate_process_group`: TERM, up to
  3 seconds grace, then KILL and bounded reaping. A reaped leader is not proof
  its group is empty; retain the original group ID and check remaining members.
  ProcessLookupError is a normal exit race; other cleanup errors stay visible.
- Hunt retains bool results, BASE_DIR cwd, mode/env timeout budgets, credential
  filtering, inherited lock FDs and best-effort signal registration. Direct
  retains raw int results (busy=75), inherited cwd/env, timeout=None, inherited
  lock FDs, and require_signal_handlers=True. Recon's exact
  URL marker, scan's canonical marker, inventory sync and raw-artifact preservation
  remain caller-owned; shell internals are unchanged by this execution helper.
- Both phase adapters acquire `runtime_phase_lock(..., include_fd=True)` and pass
  the returned FD through `pass_fds=(lock_fd,)`. The context only closes its own
  FD, never explicitly unlocks the shared open-file-description. If the direct
  wrapper is SIGKILLed while its work child retains that FD, the lock and wait
  remain active and another same-phase start returns 75 without rewriting state.
  SIGKILL cannot run finally: the running marker remains historical after the
  final lock holder exits, but no longer causes wait. Do not add PID/time guesses
  or claim coverage of descendants that deliberately close the FD.
- Hunt and the retained scanner pass data as separate argv elements; generated
  scanner input uses `-l`. AuthSession is selected through environment/file binding;
  its headers enter only the private upstream invocation, while command receipts
  record header names/session references without values. This is not protection
  against local process inspection.
- Response bodies and generated scanner input lists use invocation-owned
  temporary files, close them before child-process use, and remove them after
  synchronous completion or failure. Fixed `/tmp` or target-directory input
  names are invalid because concurrent runs can overwrite evidence. The retained
  scanner instead publishes input files in a unique target-owned run directory;
  these persist with raw/exit/status receipts after completion or failure.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| Invalid active target | `ValueError`/`invalid_target` before state, network, scanner, or `Popen` |
| Bare/host:port DNS case differs from URL case | one lowercase canonical target and storage key |
| One trailing DNS dot / multiple trailing dots | canonical host / `ValueError` before effects |
| Bare IPv6 converted to HTTPS | bracketed authority such as `https://[2001:db8::1]` |
| Empty/non-string argv or non-string element | `ValueError` before `Popen` |
| Valid URL with reserved path/query characters | canonical host/port plus exact seed URL |
| Captured API timeout | partial output retained once, process group terminated, stable timeout text |
| Live timeout / SIGINT or SIGTERM / spawn or wait failure | group cleanup when spawned, handlers restored, original exception re-raised; cleanup diagnostics go to stderr |
| Live signal registration fails outside main thread | best-effort continues; strict restores handlers, cleans child and re-raises registration error |
| Direct child exits 124 | raw 124 and failure breadcrumb; not a wrapper deadline |
| Direct wrapper SIGKILL, work child still holds lock FD | wait remains; duplicate returns 75 without spawning or changing the running marker |
| Final inherited lock holder exits after wrapper SIGKILL | lock releases; stale running marker no longer implies active wait; next start can acquire the lock |
| Concurrent scanner/config checks | distinct temporary inputs, each removed after its command |
| Residual shell caller | must be static shell syntax with no target/path/header interpolation |

### 5. Good / Base / Bad Cases

- Good: `https://example.test/a?next=https://other.test` becomes canonical
  `example.test`, while the exact URL is one argv value for the seed-aware path.
- Good: an interrupted phase reaps its leader and kills a TERM-ignoring same-group
  descendant before the caller releases its lock and finishes its breadcrumb.
- Base: a legacy state lookup receives an invalid historical key and uses the
  read fallback without making it an active target.
- Bad: join a target or output path into a shell string, treat a scanner-negative
  as validation, or pass a token/header through argv or logs.

### 6. Tests Required

- `tests/test_core_foundation_tools.py`, `tests/test_hunt_initialization.py`,
  `tests/test_scope_context.py`, and `tests/test_autopilot_args.py`: valid
  target/storage compatibility, DNS case/tail-dot normalization, strict
  rejection, IPv6/brackets, exact seed, and no-side-effect invalid entry.
- `tests/test_runtime_exec.py`: argv shape/spawn flags, combined/split output,
  cwd/env, timeout partial-output deduplication, process cleanup, live handler
  restoration, non-main-thread policy and original failures with diagnostics.
- `tests/test_runtime_phase_execution.py`: real local hunt/direct recon/scan
  success, nonzero, signals, busy, hunt deadline, spawn failure, argv/env/cwd/FD,
  inherited streams, markers and lock recovery; leader-first exit must not leak
  a TERM-ignoring same-group descendant. Direct SIGKILL regressions use a real
  wrapper CLI and an isolated test subreaper to prove child-held lock, busy=75,
  unchanged marker and final release/reaping without changing pytest's process
  ownership. Core PR CI must include this matrix and
  `tests/test_runtime_exec.py`, enforced by `tests/test_ci_contract.py`.
- `tests/test_scanner_store_registration.py`: shell/direct canonical lock wiring,
  busy admission and replayable scanner material. Scanner wrappers must retain
  unique temporary inputs and cleanup on success/failure; live execution does
  not replace their result-parsing or material-registration checks.

### 7. Wrong vs Correct

#### Wrong

```text
f'curl "{url}"' -> shell=True -> target/path controls command parsing
hunt/direct each implement signal handlers and process-group cleanup
parent-only phase lock -> wrapper death releases the lock while work survives
```

#### Correct

```text
["curl", url] -> shell=False -> existing timeout/output contract -> parser
phase adapter -> run_live_argv_command(argv, ...) -> one shared cleanup boundary
include_fd=True -> pass_fds=(lock_fd,) -> final holder closing releases the lock
```

## Scenario: Canonical Checkpoint Decision Projection

### 1. Scope / Trigger

Use when Autopilot `next_action`, Checkpoint candidate selection, or Checkpoint `decision` changes.

### 2. Contracts

- Checkpoint reads the existing Store Action Queue, Case, Coverage, evidence and
  material sources. It never proposes, ingests or resolves actions.
- Pending actions are ordered by stable ID, with a five-item page, total,
  remainder and explicit expansion. AI selects new work. An already-running
  action may be shown as the current action; otherwise the pointer is empty.
- `decision=continue` leaves selection to AI, including an empty queue. Live
  `wait_recon` / `wait_scan` is a transient phase pointer, used when no running
  action is selected. Independent claims and materials remain visible; only
  duplicate phase launches and work needing unfinished outputs wait.
- Same-call private assembly can reuse acquired owner inputs. Public Pack/State
  entries reject caller snapshots and read fresh owners; each Checkpoint reads
  current evidence integrity and checks Store revision drift before returning.

### 3. Tests Required

`tests/test_checkpoint.py` covers candidate pages/expansion, claimed action
recovery, empty queues, no automatic actions, current integrity and bounded reads.
`tests/test_context_pack.py` rejects foreign, stale and same-revision damaged
caller projections.

## Scenario: Coordinator Maintenance Gate

### 1. Scope / Trigger

Use this gate whenever a diff changes `tools/checkpoint.py`,
`tools/autopilot_state.py`, or an owner projection consumed by either module.
The operator does not need to identify refactor opportunities manually.

### 2. Required Review

Before editing, inspect the changed call path and answer:

1. Does it read the same state owner more than once in one invocation?
2. Does coordinator code directly parse or write an owner-managed file?
3. Does the new block mix I/O, policy/priority decisions, and output rendering?
4. Does the same decision already exist in the sibling coordinator or an owner module?
5. Does a new field bypass the owner API and create a second schema interpretation?

### 3. Contracts

- No match means no coordinator refactor. File size alone is not a trigger.
- Repeated reads reuse an invocation-local in-memory projection only when the
  changed path proves the duplication. The projection is a plain value, is not
  persisted, and never becomes a mutation owner.
- Mixed logic may extract one independently testable pure derive/decision
  function. Do not add a coordinator base class, event bus, database, or writer
  abstraction.
- Direct state access moves to the existing owner API. A shared decision keeps
  one canonical implementation rather than two synchronized copies.
- Completion notes include exactly one concise disposition:
  `Coordinator impact: none|reused|extracted|deferred - <reason>`.
  `deferred` is valid only when the issue is outside the requested call path or
  cannot be changed without widening the public/state contract; it must name
  that boundary.

### 4. Tests Required

- `reused`: assert the same output and, when duplicate I/O was the defect, the
  owner loader call count for the changed path.
- `extracted`: add a focused pure-function test for the changed decision and
  keep the relevant Checkpoint/Autopilot integration test.
- `none`: run the narrow behavior test for the requested change; do not add a
  test that merely asserts no refactor occurred.
- `deferred`: preserve current behavior with the narrow regression and report
  the named boundary; do not add speculative scaffolding.

### 5. Wrong vs Correct

Wrong:

```text
checkpoint.py is large -> split by line count -> add another state facade
```

Correct:

```text
changed path reads Coverage twice -> reuse its in-memory owner projection
changed policy mixes I/O/rendering -> extract one pure decision function
no trigger matched -> keep the coordinator unchanged
```

## Scenario: Deep Evidence Lane Budget and Route Contract

### 1. Scope / Trigger

Use when Autopilot deep mode, parameter discovery, AI-selected HTTP replay,
zero-day fuzzing, context-pack Skill routing, or Action Queue hypothesis
continuation changes.

### 2. Signatures

```python
project_budget(base, *, minimum=1, maximum=None, url_count=0,
               parameter_count=0, response_variance=0,
               high_value_evidence=0, adaptive=False) -> dict
discover_parameters(..., max_urls=5, deep=False, resume=False) -> dict
```

### 3. Contracts

- Normal/legacy invocations keep their existing per-call budgets. `--deep` is
  the explicit opt-in for adaptive projection; the shared `project_budget()`
  helper is deterministic and always clamps to a positive hard maximum.
- Adaptive signals are bounded surface/evidence hints only: URL breadth,
  parameter density, response variance, and high-value evidence may enlarge a
  batch, but never bypass Scope/Auth or the caller's minimum. A budget boundary
  is not a clean result.
- Parameter discovery remains GET/POST scoped, keeps the default `max_urls=5`,
  records the requested/effective budget, and persists an input-fingerprint
  cursor. `--resume` consumes the same source/method/auth snapshot; incomplete
  work remains `partial` and retries the unadvanced POST batch when its tool is
  unavailable or fails.
- AI-selected JSON/query/form experiments use the existing native HTTP
  boundary and preserve exact request/response evidence. Zero-day fuzzing may
  adapt only in deep mode and retains the same scope and evidence gates.
- Skill selection/loading belongs to the native platform. Queue/Store do not
  validate `skill_route`, `route_required`, preset `required_dimensions` or Skill
  files; parameter discovery never preselects a method. Experimental
  `active_dimension` and Runner `tested_dimensions` retain their existing roles.
- An action with `activation_required=true` is executable only after an AI claim
  carrying `depth_contract_version=1`, `hypothesis_id`, open `family`/`technique`,
  `active_dimension`, `expected_learning`, `kill_condition`, `risk_tier`,
  `max_hypothesis_actions`, target-owned evidence references, and a bounded
  decision reason. `selected_knowledge_refs` is optional and canonicalizes to
  `[]`; non-empty refs must use action recommendations or record an override
  reason. Missing required execution evidence or budget metadata rejects the
  claim before queue mutation.
- The Runner may observe only a prior running claim. It writes `last_outcome`,
  replayable `summary_ref`/`evidence_ref`, `runner_operation_id`,
  `tested_dimensions`, a bounded `observed_difference`, `observation_kind`,
  and `at`; the action remains `running`, and the Runner never chooses
  terminal status. An explicitly declared `baseline_only` observation is
  recoverable context, not a controlled difference, and cannot satisfy a kill
  resolve.
- A versioned AI resolve supplies exactly one continuation kind or
  `kill_condition_met=true`. Continuation materializes at most one child,
  preserves the `depth_contract_version=1` hypothesis/parent/evidence lineage,
  and respects `max_hypothesis_actions`; `rotation` creates no child. Kill
  closes the hypothesis and emits no sibling/pivot action.
- Checkpoint may project at most one versionless advisory
  `capability-chain-review` for a finalized target-owned primitive with a
  concrete continuation hint. Queue `source_id + metadata.generation` carries
  parent plus normalized primitive identity; active/final matches and immediate
  chain children suppress replay. The review is outside the hypothesis cap and
  follows running, validation, candidate, and report work.
- Legacy versionless actions retain the existing `pivot_hints` behavior; it does
  not apply to `depth_contract_version=1` terminal resolution.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| Deep flag absent | Exact legacy budget and behavior |
| Adaptive signals exceed capacity | Effective budget equals the hard maximum |
| Budget/cursor exhausted before coverage | `partial`, resumable cursor; never `clean` |
| Input fingerprint, method, source, or auth session changes | Resume rejected without overwriting the prior summary |
| POST discovery tool missing/fails | Forms may be observed, but cursor does not advance the failed batch |
| Required Skill route missing/invalid | Action Queue persistence rejects the action |
| Unknown/non-primary Skill or path mismatch | Action Queue persistence rejects the action |
| Active dimension outside route without override reason | Action Queue persistence rejects the claim |
| Hypothesis kill condition met | No sibling/pivot action is generated |
| Versioned action without activation or before a running claim | Claim/observation is rejected; queue state is unchanged |
| Valid versioned observation with a controlled difference | `last_outcome` is persisted and the action remains `running` |
| Undeclared baseline-only versioned summary | `blocked`, no outcome write |
| Explicit `baseline_only` observation with target-owned refs | `updated`, action remains running; continuation required |
| Versioned resolve supplies both continuation and kill, or neither | Reject before terminal status mutation |
| Primitive is evidence-backed but has no executable bounded hint | No review; unsupported speculation cannot block Closure |

### 5. Tests Required

- `tests/test_deep_budget.py` covers legacy stability, signal-based expansion,
  hard caps, and invalid bounds.
- `tests/test_param_discovery.py` and `tests/test_zero_day_fuzzer_scope.py`
  cover deep flags, cursor/resume, partial semantics, scope/auth preservation,
  and adaptive summaries.
- `tests/test_action_queue.py` and `tests/test_context_pack.py` cover route
  validation, idempotent hypothesis pivots, and checkpoint route propagation.
- `tests/test_checkpoint.py` and `tests/test_autopilot_hypothesis_replay.py`
  cover primitive review identity/serialization, owner-work priority, active
  handoff, final finish, and unsupported-speculation finish.

## Scenario: Advisory Memory Recommendation at Bounded Finish

### 1. Scope / Trigger

Use when `/autopilot` produces the final response for one bounded invocation.

### 2. Signatures

```text
Memory recommendations
- promote: <recommendation or none + reason>
- target-only: <target-scoped item or none>
- reject: <rejected material or none>
```

### 3. Contracts

- One bounded `/autopilot` invocation emits the section exactly once, only in its
  final handoff/finish response; lanes, replays, and checkpoints do not emit or
  summarize it.
- A `promote` item cites target-owned evidence and states the destination layer,
  value, transferability, next action, and stop/validation condition.
- The review is advisory and presentation-only. It uses retrospective material
  only for classification and never writes target memory, knowledge, Skills,
  Rules, pending candidates, or `/remember` state.
- The review never changes routing, budgets, Action Queue state, evidence/finding
  lifecycle, closure, the selected next action, or any existing project
  capability.
- No reusable lesson produces the compact value
  `promote: none — no new transferable lesson`.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| Invocation reaches final response | Emit exactly one three-bucket section |
| Lane/replay/checkpoint completes | Do not emit the section |
| No transferable evidence exists | Emit compact `promote: none` reason |
| Recommendation lacks target-owned evidence | Keep it target-only or reject it |
| Recommendation review fails | Preserve execution and closure; do not mutate state |

### 5. Good/Base/Bad Cases

- Good: one evidence-backed reusable stop condition is recommended at handoff.
- Base: no new lesson; the three buckets stay concise and execution is unchanged.
- Bad: create a candidate, alter the next action, or repeat the review per lane.

### 6. Tests Required

- The former `test_autopilot_inline_contract.py` is retired. Final-only frequency,
  three-bucket shape and advisory-only behavior remain review requirements; do
  not cite that absent file as executable coverage.

### 7. Wrong vs Correct

Wrong:

```text
lane ends -> write pending candidate -> adjust next action
```

Correct:

```text
bounded invocation ends -> show one advisory review -> preserve all runtime state
```

## Ownership-bound runtime installation

### Scope / Trigger
Installer and runtime_doctor changes share one publication/retirement path.
### Signatures
`sync_runtime(repo_root, runtime_root, kinds=None, prune=False)` returns copied,
removed, conflicts, conflict_details and status (`complete|rejected|partial`);
CLI --sync returns nonzero on rejection/partial. Successful entry migration also
returns direction, native_entries and release fingerprints.
`compare_runtime(repo_root, runtime_root, kinds=None)` reads ownership receipts
when comparing skills or required command-owned hooks; Bootstrap consumes its existing OSError/ValueError boundary.
### Contracts
`.ccst-installed.json` records relative destination, kind and installed SHA256.
The optional virtual key `settings.json#ccst-autopilot` records kind=hooks,
exact owned groups and their semantic SHA256. It is not a filesystem destination.
Required groups come from `claude_hook_contract`, which imports no domain owner.
Compare preserves legacy receipt read semantics and checks this entry independently;
it never applies the writer's full receipt requirements to unrelated legacy entries.
Unowned matching groups, missing/modified owned groups and disableAllHooks refuse
publication; missing/changed/unowned/disabled groups block critical readiness.
The installed digest may predate source edits: compare the expected complete hook
shape using that digest, and verify the receipt against the actual groups.
`refreshable_source(relative, installed, current)` only admits body changes from
`CONTEXT_SOURCES` with identical entry/frontmatter and intact installed ownership.
Such disk diffs remain advisory; other critical diffs stay blocking.
Only managed groups are replaced, preserving unrelated settings and hook order.
Hook source changes require all kinds and prune, using the same fixed-source
entry journal, preflight, publication and receipt-phase recovery below.
An exclusive local file lock serializes sync. Whole-batch source/path/ownership/hash
preflight precedes any payload/receipt publication; parent files, symlinks and local
conflicts at managed destinations reject the batch. Unrelated external Skill
links are inspected read-only and preserved; they are not install destinations.
Root/lock creation is not a zero-filesystem-write promise.
Only owned, unchanged obsolete files are pruned. No receipt means no deletion or
overwrite of different bytes; native entries cannot be adopted on matching bytes
alone. Disabled commands retain their name and state.

An actual single-entry switch requires all kinds and prune. Its versioned
`.ccst-entry-migration.json` binds direction, resolved roots, full native inventory,
source-scope/executor/method/native fingerprints, before/after receipts/hashes,
every operation's path/source/owner/before/after hashes and expected entry identities.
Ordinary later partial-kind sync remains available; it does not claim a cutover.
Strict entry-cutover conflicts apply only to an actual switch. For ordinary
updates, an already owned file matching the current desired source may complete
an interrupted receipt update. A third state, including an intermediate payload
after its source changes again, still conflicts.
Source scope covers CLAUDE, rules, runtime docs, Python/Shell tools, Python memory
and active knowledge (excluding historical archives); tests and target data are not
release authority. The method manifest and reader bind method publication separately.

After preflight, record phase `payload` before publishing non-entry resources,
retiring unchanged old entries, then publishing new entries last. Verify all bytes
and entries; persist phase `receipt` before writing the after receipt. This phase
fixes the after-state even when before/after receipt bytes are identical. Recheck
receipt/payload/entries before clearing the record. During an entry cutover, only
identical fixed-version recovery may adopt recorded desired exact-after files;
no record, source changes, unplanned entries or third states are refused. Receipt-phase recovery may only
verify the after-state, complete its receipt and clean the record, not replay payload.
Reverse synchronization requires approved prior assets and the migration-aware
executor. These are process-interruption guarantees, not cross-file atomicity,
power-loss recovery, zero downtime, all-roots inspection or host-cache acceptance.
The read-side receipt root and every entry must be objects. Missing receipts and
empty objects retain their current comparison semantics. Read-side entries need
no new hash field or unknown-field policy; Skill inventory ignores non-skills object records.
Do not lift the writer's stronger admission checks into the reader as a shape fix.
When skills are selected for a single-entry profile, compare also checks the
selected matching resources against existing hashed ownership records. A stale
receipt becomes an existing `diff` item with an ownership reason and follows the
same critical/advisory classification; it must not report clean merely because
source and installed bytes match. Disabled-command renames use the existing
ownership mapping. When the core entry has a hashed ownership record, a matching
selected resource with no ownership entry is also drift (for example, a newly
copied file whose receipt publication was interrupted). Missing/hashless legacy
receipts and commands/agents-only comparison retain their read semantics;
compare never repairs the receipt.
### Validation & Error Matrix
Unknown/malformed ownership metadata fails visibly. Path escape/symlink or local
modification preserves the destination and reports whole-batch conflict. An entry
retry adopts exact-after bytes only when its fixed operation record authorizes them.
Pending records always prevent `critical_clean`; compare never mutates or recovers.
On receipt reads, non-object root → ValueError("invalid runtime ownership manifest");
non-object entry → ValueError("invalid runtime ownership entry"), not AttributeError
or an empty fallback. Bootstrap returns `stop_runtime_error` with `error.type/reason`
(single-line reason, at most 500 characters), before capability/target-state acquisition.
Its JSON CLI still returns 0 after emitting the stop action; the doctor CLI error
protocol is unchanged. Comparison never repairs receipts or invokes sync.
### Good/Base/Bad Cases
Good: update unchanged managed content. Base: repeat is idempotent. Bad: deleting
all extra Markdown under a shared commands directory.
Read-side base: no receipt, or a commands/agents-only comparison, adds no receipt
requirement. Bad: calling items/get on a root array or null entry and leaking a traceback.
### Tests Required
Temporary runtime upgrade, whole-batch conflict preservation, known unowned/renamed
entry refusal, parent-path conflicts, entry-before-receipt and receipt-phase
interruption, same-version recovery and third-state/source-drift rejection;
disabled command/external Skill preservation and installer parity. Never use real HOME.
`tests/test_runtime_doctor.py` covers non-object roots/entries, unchanged comparison
results and read-side compatibility. `tests/test_autopilot_bootstrap.py` exercises
real malformed receipts through the JSON entrypoint, bounded diagnostics, unchanged
file paths/bytes/mtime and uncalled capability/state/sync entrypoints. Keep the real
receipt reader; a mock-only read error cannot prove the owner rejects bad shapes.
### Wrong vs Correct
Wrong: repo-wide rsync --delete. Correct: owner receipt plus current hash, then
remove only unchanged obsolete files. Legacy filename similarity is not ownership.
Wrong: catch AttributeError at bootstrap or silently replace malformed receipts with {}.
Correct: validate object shapes in the existing reader, then use the established ValueError boundary.

Before any file publication or pruning, sync checks every selected previously
owned source directory exists. For an installation owning the autopilot command,
the source critical manifest must be valid. A missing checkout is not an empty
release. Source inventory collection precedes writes. Reconcile an owned command's
active-to-disabled rename before computing removals, even when the source command
has already been retired. Local changes still conflict and retain their receipt.

Source admission validates each path declared in the critical runtime manifest:
existence, regular-file/readability and containment, before publishing or deleting
anything. This applies to a skills-only sync too. Receipt coordination handles
both active→disabled and disabled→active; the prior installed hash follows the
command identity. User edits retain a conflict and their ownership receipt.

## Closure display separation
Closure state snapshots omit `enrichment_hints` and only the top-level Intel
`reason` explanation. Intel action, blocked facts, advisory data, review-group
queries, long-tail counts and source/disposition bindings remain digest inputs.
Closure acquisition does not regenerate or filter specialist recommendations;
advice remains display-only and cannot create an owner obligation.
Nested reason fields and query commands are not blindly stripped: they may carry
unrepresented source/cursor facts. Display changes must not expire a review;
source/state changes still must. Prior digests may become stale on this change;
refresh and explicitly review, never rewrite historical witnesses.
`test_closure_digest_ignores_advice_but_preserves_intel_facts` covers prose/tool-hint
stability, immutable input and source/remaining/status/query-change invalidation.


## Scenario: Recover inherited constraints without promoting them to facts

### 1. Scope / Trigger
A current handoff contains a tool restriction, admission rule or next-operation
constraint that the agent plans to act on or repeat in a new handoff.

### 2. Signatures
Existing guidance owners: `skills/runtime-protocol.md#shared-memory-continuity`
and the consumed recovery summary in `commands/autopilot.md`. No CLI or schema change.

### 3. Contracts
Separate recorded observations from inherited judgments. Check only the relevant
operation's current command contract before treating inherited restrictions as
current facts; unverified statements stay explicitly inherited/unverified.
Compare source timestamps with timezone and precision for historical order.
Historical order does not prove current reachability, and unknown reachability
does not erase comparable historical ordering. Do not rewrite historical memory.

### 4. Validation & Error Matrix
- Contract not checked: label inherited/unverified, not a confirmed current gate.
- Missing/incomparable timestamps: order unknown; do not invent chronology.
- Comparable historical timestamps: retain order, current reachability separate.
- Successful memory write: transport result only, not semantic acceptance.

### 5. Good/Base/Bad Cases
Good: consult the next operation's current command guidance before carrying a gate.
Base: reuse still-valid observations without rereading the whole source tree.
Bad: copy a historical admission rule as fact or automatically promote a Finding.

### 6. Tests Required
`test_recovery_guidance_checks_inherited_constraints_without_full_source_read`
in `tests/test_ai_native_skill_convergence_baseline.py` checks both consumed and
shared guidance. It does not prove model obedience; live acceptance remains separate.

### 7. Wrong vs Correct
Wrong: old handoff says blocked -> new handoff asserts blocked without checking.
Correct: inspect relevant current contract -> retain or revise current judgment,
leaving old memory untouched and unchecked claims explicitly unverified.

## C3 memory entry integration (2026-10-11, engineering only)

`target_memory.load_goal_memory` produces separate question-recall and Store-history
commands. Context Pack, Resume and Autopilot render those commands without building
indexes or reinterpreting cursors. `query` keeps current owner facts independent of
historical ranking; `history` preserves Store paging and exact ID expansion. An
index/model failure does not authorize old permissions or replace fresh Bootstrap.
The former mandatory playbook router is now complete on-demand method content in
`knowledge/playbooks/web2-evidence-contracts.md`; Coverage/report gates remain.
Runtime installation and model/default capability acceptance are still pending.
