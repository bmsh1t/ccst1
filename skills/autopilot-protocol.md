## Shared Automation

If Bootstrap returns `action=read_bootstrap`, read its exact `bootstrap_path` fully;
use that JSON as Bootstrap. Missing/truncated output forbids work; never select an older file.

Apply `skills/runtime-protocol.md#输出契约` throughout this loop.
Choose initial discovery under step 2. While collection runs, investigate independent
questions using published evidence; wait only for inputs the next experiment needs.
Apply the selected method, capture/register, refresh and choose the next question.
Collect Recon's final result and review new Surface material when it arrives.
Publishing a report returns to investigation; a saved next action is not completion.

Round mechanics belong to `/autopilot-round`; use them for existing Round work or
an explicitly supplied lane cap. Ordinary uncapped runs need no new Round.

The native host reads current checkout bodies without session, Hook or runtime access;
only execution entry checks observed lifecycle events. Bodies accompany Bootstrap; only
`action=continue` admits investigation. Each `CCST_ENTRY` source hash must match
`host.source_sha256`; apply these current bodies in place of cached bodies for the same files.
`CCST_SOURCE` names the original file/package root.
Missing bodies, truncated previews or `CCST_AUTOPILOT_INCOMPLETE` forbid new target
work. Natural Skill discovery remains available; no duplicate Skill invocation is
needed for an already delivered complete body.

Keep the latest returned `host.session_id` + `host.invocation_id`. Same-session continuation reuses context
and enters Refresh before work. A completed invocation can reopen only from the current
user prompt's state command when that request explicitly continues the same task.
Successful reopening returns a new invocation identity for a fresh Stop review, while
preserving the original start time, time/Round limits, arguments and target facts.
Questions are answered directly; cancellation/task changes
stay suspended. User interruption needs no review. SessionStart restores bodies after
compaction/restart; Refresh's `recovery` replaces entry arguments/root/mode, Scope and state/memory.
When `recovery.source_context` is present, run its `commands` and read every numbered part
before work; all `CCST_ENTRY` hashes must match its `sha256`. These bodies replace prior
instructions. Source refresh renews the review identity while retaining the original limits.

### State Consumption Loop

1. **Start.** Only fresh Bootstrap `action=continue` admits a new invocation; obey
   `state.hard_gate`; report missing input/error. Confirm critical drift
   through `/sync-check`; never auto-sync/install. After admission checks, Bootstrap
   initializes a single-target Store before reading state; lists initialize each
   selected target through the execution owner. Bind the supplied domain, IP/CIDR,
   host:port, URL or list as fixed-target scope under `rules/dig-scope-workflow.md` §0.
   Domain Recon may discover in-scope subdomains; missing history or loading a Skill
   does not turn the target into group/brand discovery or a campaign seed queue.
   At start consume `state.target_memory`; after compaction/restart consume
   `recovery.state.target_memory` under `skills/runtime-protocol.md#shared-memory-continuity`.
   `active_goal` comes from that target's Store. Save an explicitly changed objective
   through `commands/target.md`; never replace it with a session summary or an inferred default.
   Carry any explicit user/host time, cost or lane limit. Treat absent limits as
   unset; do not invent a deadline, allocation or write-back cutoff.
   `host.started_at` is the invocation's Unix starting time; `host.elapsed_seconds`
   is measured, not estimated. Resume/compaction preserves this clock. Retain the
   admitted `host.max_seconds`/`host.round_limit` and their source; reserve write-back time only when
   the user/host supplied that boundary.

2. **Continue.** Recover unfinished execution first; read current
   `state.round_progress` or refreshed `control.round_progress` and use
   `skills/autopilot-round-protocol.md` for existing Round work.
   With an explicit lane cap and no active Round, use that command's Prepare And
   Terminal Precheck, claims, heartbeats and settle without invoking its Bootstrap.
   Otherwise no prior Round means no Round recovery. Completed lanes allow further investigation
   unless an explicit limit was reached. Settling an inherited Round returns here.
   `wait_recon`/`wait_scan` tracks that running phase, not a global pause.
   Retain its background handle and avoid duplicate launches. Independently supported
   tests, evidence analysis, validation and registration may proceed in parallel;
   do not race the same mutable session/object or read unfinished artifacts as final.
   Consume the host-delivered terminal result; use TaskOutput only when that tool is available.
   A matching terminal notification with the complete result is a delivery; a launch acknowledgment is not.
   Finish step 3's write-back and enter Refresh before relying on its final outputs or stopping.
   If the result is missing/incomplete, wait for the notification or use the host's available handle query;
   never invent or repeatedly call an unavailable tool.
   Before selecting or executing new work (including fresh Recon), apply the complete
   delivered `src-hunter` body under [Investigation Skill](#investigation-skill).
   For a new public-domain target with `arguments.deep=true`, start with available
   FOFA mapping and apply `skills/src-hunter/modules/web2-recon.md#incremental-discovery`.
   Keep usable supplied evidence and prior work first. FOFA absence/failure and
   local/private targets use direct discovery without waiting for that provider.
   Ordinary non-deep fresh targets default to `/recon`. Preserve
   `arguments.recon_flags`, seed URL and auth/context; explicit quick still limits collection cost.
   After Recon's Surface finalizer, apply [Surface Review](#surface-review) to its new
   material and adjust the next question; keep prior parallel work and its evidence.
   Before relying on history or repeating an experiment, apply
   `skills/runtime-protocol.md#problem-recall`; use returned corrections and conditions.
   `owner_continuations` order is advisory; keep deferred work and obey `runnable=false`.
   Existing-target gaps mandate neither Recon nor Checkpoint. Do not loop `/hunt`.
   For a selected deep discovery or collection stage, use the local batch
   commands in `commands/recon.md#deep-collection-batches`; preserve auth/context,
   inspect the returned material and choose again. Unexplored assets justify
   broad discovery without a pre-existing vulnerability lead. Remaining words/seeds do not
   mandate another batch or a full Recon rerun.

3. **Execute and save.** Before the selected question's first experiment, read
   its method under `skills/runtime-protocol.md#shared-knowledge-recall`.
   Then read current evidence and the selected `docs/autopilot-lanes.md` section;
   reuse matching `state.lane_contract` at `text_available=true`. Before the first native request,
   read the complete [capture and registration contract](../docs/evidence-runners.md#在执行时捕获原件).
   Follow that contract's script and continuous browser-workflow capture boundaries. Use `record-observation`
   when no Finding exists; consume the registration receipt before the next experiment.
   Recover failures from saved materials under that contract.
   Apply `skills/runtime-protocol.md#5-execution-and-write-back`.
   Save accepted memory deltas under `skills/runtime-protocol.md#cognitive-write-timing`.
   Round claims before execution and writes its terminal heartbeat after write-back.

4. **Refresh.** After each action/terminal heartbeat or same-task continuation, run
   the current `host.state_command` once. It checks Scope/Auth, reads loop state and
   rearms Stop. Require `action=continue`, consume any `recovery`, and retain the host
   binding. No separate resume, Bootstrap or Store initialization.
   Consume the projection's current `active_goal`; an empty value clears the previous
   goal. Goal changes invalidate the prior Global Review; handoff notes alone do not.
   Read the full JSON, including persisted output; expand oversized files in consecutive
   chunks until complete. Never discard the remainder with head/tail or repeat a truncated full read.
   Use fresh `control`, including `control.next_step`; expand changed or unread material
   through `surface_projection.path` and `surface_projection.continuation.command`. `surface.review_window`
   counts describe the display window, not tested coverage. Missing/stale material
   needs raw-source reading or an explicit refresh when needed; failed reads require recovery.
   Apply the result reassessment in `skills/runtime-protocol.md#5-execution-and-write-back`,
   then return to step 2, including when `control.owner_continuations` is empty.
   `commands/validate.md` and `commands/report.md` use this same cycle.
   Apply the Finish Contract before stopping.

Apply `rules/ccst/hunting.md`. Use Bootstrap's quoted root/target, exact seed URL and
`arguments.hunt_auth_flags`. For bound context or `run_recon`, follow
`docs/autopilot-lanes.md#recon-and-surface`; never drop context. Network calls use
`docs/resin-proxy.md` in the same shell.

Before Action work read `docs/autopilot-lanes.md#state-and-queue` and
`docs/evidence-runners.md#绑定已认领行动`. Inspect failed Action claims once; never guess/retry.
Use visible MCP only; missing/failed stays partial/blocked. Retry only when the
selected contract permits. Surface review follows the rule below; specialists
are optional for bounded independent questions. Delegation follows
`docs/autopilot-lanes.md#inline-specialist-propagation`; this session owns writes.

`loop_guard` is advisory. Review bounded deltas at new evidence, phase change,
blocker, rotation or batch end. Waits/later writes use `--bounded` alone; reread
only after owner writes. Use `arguments.checkpoint_trigger` for snapshots and
save decision-relevant memory under `skills/runtime-protocol.md#cognitive-write-timing`.

### Investigation Skill

Apply the delivered original body and `skills/runtime-protocol.md#native-skill-loading`
in this parent session with current target/Scope, facts, mode and explicit limits
or unset. Child reading and description metadata are not parent body context.
Reuse retained bodies; apply Shared Knowledge Recall to read the complete method
for the selected question. Recovery restores numbered original-source parts.

### Surface Review

After Recon, compare available business and technical surfaces in this parent session
before choosing the next question. Apply `rules/src-value-hunting.md` §1.1 when stronger
evidence changes the default priority; keep unread or missing material explicit.

`recon-ranker` is an optional read-only second opinion. Select it when independent
review would help a concrete prioritization or missed-path question, whether after
Recon, at stagnation or before evidence-based finish. Multiple subdomains, the first
post-Recon choice, resume/compaction or lane/round completion alone do not trigger it.
When the next experiment is clear, continue in-session. Reuse the prior answer for
unchanged materials and question, including through the existing handoff.

If selected, invoke the native `Agent` tool with `recon-ranker` and `run_in_background=false`.
Read `docs/autopilot-lanes.md#recon-ranker-review` for the dispatch pack; include the
concrete question, actual deep mode and a bounded review allocation. Honor any explicit
parent limit; this review allocation never ends the parent investigation.
Wait for its result before choosing or executing the dependent experiment;
an asynchronous dispatch acknowledgment is not the review. Apply the result or state
its failure before proceeding in-session.
User/scope/explicit-limit stops and execution recovery take precedence.
If a selected review cannot run because the Agent tool/role is unavailable or fails, report it as incomplete
and continue in-session with src-hunter; do not retry repeatedly or claim a review occurred.

### Transition And Finish Contract

Continue after publication. Stop only for a user instruction, scope or explicit user/host limit, a blocker
preventing useful work, or evidence-based lack of worthwhile next work. Apply
`rules/ccst/coverage-gate.md`; explain why and remaining leads. `handoff` alone
is no stop reason. Unresolved observations or reviewed deferrals keep Closure at
`handoff`; they do not prove a blocker. `stagnant_prerequisite` retains the local
failure and guard as a handoff to independent investigation. Consider independent
paths after a writer or cleanup failure.

Only an explicitly supplied `max_lanes` stops new work by count. Per-request timeouts,
rate limits, collector batches and review deadlines bound that operation, not this investigation.
Complete evidence, write-back, cleanup, Checkpoint and Closure before leaving: resolve hypotheses,
register pending Actions before Checkpoint, drain used `oast_listen`, import/close
browser work under its lane contract, and save memory/current handoff.
Use `commands/target.md#交接与证据` for handoff and consume its receipt.
External submission remains manual.

When stopping at an explicit limit, name its entry/owner source and use the exact
admitted time threshold or Round identity in `termination.limit`, using
`commands/checkpoint.md#global-review`. An early write-back reserve is not itself
an elapsed limit. A time limit not bound by `--max-seconds=SECONDS` cannot be
introduced at the stopping review. Native host time/cost limits remain host-enforced interruptions;
unavailable cost receipts cannot authorize a normal completion. Without an explicit
limit, return to step 2 while worthwhile work remains. Saving a next action or
reaching a report/checkpoint never creates a stopping limit.
An explicit time cap is a ceiling, not a minimum runtime. Continue useful work or
use another evidence-backed stop reason when it applies; never sleep merely to
reach the deadline.

Before exhaustion, run Coverage `rebuild` then `find-gaps`, and read Closure:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```

Apply `commands/checkpoint.md#global-review`; incomplete evidence proves nothing.
Reread after writes. Exhaustion requires `closure.verdict=finish` and
`can_claim_exhausted=true`.

For every normal automatic stop, record that same current Global Review with
`--termination-json` bound to `host.session_id` and `host.invocation_id`; preserve
unresolved owner work and reopening conditions. Finish result collection and
handoff/write-back first; if host recovery is pending, Refresh and retain its returned
identity before reading fresh Closure. Submit once and reread Closure before ending.
Follow Closure/Checkpoint validity diagnostics under `commands/checkpoint.md#global-review`;
overall digest drift alone does not invalidate a review whose bound basis still matches.
An actual user/scope/explicit-limit
boundary may stop with `closure.verdict=handoff`; do not try to manufacture exhaustion
or repeat a valid stop review solely to clear residual coverage tokens.
Use the structured reasons in `commands/checkpoint.md#global-review`. The Stop hook verifies current owners and
binding, then releases this invocation. On rejection, follow its specific diagnosis:
refresh stale owners/reviews, complete missing review fields, or rebind termination
to the current host identity. Repair these in-session without asking for “continue”;
a review gap alone does not establish worthwhile new investigation. Never fabricate
evidence or a stop reason. Running execution keeps Stop waiting for its result;
it does not count as failed repair. Repeated non-waiting Stop with unchanged
owner/review requirements suspends as incomplete with the actual blocker;
it never establishes exhaustion or a default budget.

Final output: target/mode, evidence, findings/candidates, blockers, next action;
exactly one final-only, presentation-only `Memory recommendations` section
(promote / target-only / reject; empty buckets: `none` + reason), under
`knowledge/promotion-rules.md` and `rules/ccst/retrospective.md`. Advice causes no
writes or routing/budget/lifecycle changes; promotion stays review-gated.
