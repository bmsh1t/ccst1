---
description: AI-first autonomous hunt loop for one target or a target list.
allowed-tools:
  - Bash
  - Agent
  - Skill
  - "mcp__Playwright__*"
  - "mcp__chrome-devtools__*"
  - "mcp__fofamap__*"
---
# /autopilot

Carry an investigation forward in the current Claude session: recover the target,
understand its business, test useful questions, validate findings, and continue
while worthwhile work remains. `src-hunter` supplies the investigation methods.

## Usage

```text
/autopilot target.com
/autopilot https://target.com/app --normal --deep
/autopilot target.com --quick --deep --max-lanes 16
/autopilot targets.txt --normal
```

Targets may be domains, IPs, CIDRs, URLs, or existing target-list/Scope-manifest files.
Use `--auth-file PATH` for an explicit session and `--context-file=PATH` for a bound
continuation. Preserve the exact seed URL and the supplied Scope/Auth boundaries.

| Option | Effect |
|---|---|
| `--paranoid` (default) | Checkpoint after each substantive change |
| `--normal` | Checkpoint after a coherent batch of evidence work |
| `--yolo` | Checkpoint at blockers, handoff, or finish |
| `--quick` | Reduce initial Recon cost |
| `--deep` | Pursue depth according to evidence and value; can combine with quick |
| `--max-lanes N` | With deep, bound new lanes to 1–32; finish evidence and cleanup afterward |

A lane is one investigation work item, such as Recon, validation or report publication.
Checkpoint frequency does not change evidence standards or authorize stopping.
For one resumable scheduled round, use `/autopilot-round`; it shares the workflow below.

<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST
{"schema_version":3,"paths":[{"kind":"commands","relative_path":"autopilot.md"},{"kind":"commands","relative_path":"autopilot-round.md"},{"kind":"skills","relative_path":"runtime-protocol.md"},{"kind":"skills","relative_path":"src-hunter/SKILL.md"},{"kind":"skills","relative_path":"src-hunter/modules/web2-recon.md"},{"kind":"skills","relative_path":"src-hunter/modules/triage-validation.md"},{"kind":"skills","relative_path":"src-hunter/modules/report-writing.md"},{"kind":"skills","relative_path":"src-hunter/知识库/README.md"},{"kind":"skills","relative_path":"src-hunter/知识库/打穿短表.md"}],"mcp_contracts":["mcp__Playwright__*","mcp__chrome-devtools__*","mcp__fofamap__*"]}
AUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->
Authoritative bootstrap contract (do not reinterpret): !`python3 "$(git rev-parse --show-toplevel)/tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"`
Arguments: `<target> [--paranoid|--normal|--yolo] [--quick] [--deep [--max-lanes N]] [--auth-file PATH] [--context-file=PATH]`.

## Shared Automation

The current Claude session carries the investigation through the five steps below.
`/autopilot-round` uses the same steps and adds its own lane claims, heartbeats and
round budget. Run round mechanics only for that command.

### State Consumption Loop

1. **Recover the target and unfinished work.** Apply [Startup And Recovery](#startup-and-recovery).
   Establish the current goal, Scope/Auth, saved evidence and next intent. Resolve
   execution recovery or wait for active work before starting another request.

2. **Choose one useful question.** Apply [Investigation Skill](#investigation-skill)
   to understand the business, actors, objects and normal behavior. From current
   evidence, select a question and the observation that would distinguish competing
   explanations. Read the complete relevant method before its first request.
   `owner_continuations` lists explicit pending work: its order is advisory,
   `runnable=false` forbids execution, and deferred entries must remain visible.
   Choose bounded discovery when information is missing; inventory gaps or residuals
   do not mandate Recon or Checkpoint. Do not loop `/hunt`.

3. **Test and save what happened.** Apply [Execution Invariants](#execution-invariants),
   claim when required, and carry out the selected test or pending action once.
   Preserve actual requests, responses, state changes and failures; register evidence
   and record progress or resolve the action through its existing owner as the evidence
   supports. Then [refresh after the action](#refresh-after-an-action).
   Use the result to continue, change the hypothesis, or choose another path.

4. **Validate and publish when the evidence is ready.** Follow `commands/validate.md`
   and `commands/report.md`, using the same claim, evidence and refresh cycle.
   Save each confirmed finding immediately without waiting for other candidates.
   Publish the supported result, then return to step 2 while useful investigation
   remains.

5. **Continue, rotate, or finish deliberately.** Return to step 2 when new evidence
   or a worthwhile remaining question supports it. Apply the
   [Transition And Finish Contract](#transition-and-finish-contract) before stopping.
   A `handoff` result returns to `src-hunter` in this session; saving continuity
   alone does not end the investigation. Explain the stop reason and valuable
   unpursued leads when a real boundary is reached.

### Startup And Recovery

Only a fresh Bootstrap `action=continue` admits target work. Otherwise request the
missing target or report the returned error. Critical runtime drift requires
confirmation through `/sync-check`; never auto-sync or install.

Consume Bootstrap `state`, then fresh `control`, and obey `state.hard_gate`.
Missing, stale or partial data is not a clean result. For `wait_recon` or
`wait_scan`, poll the existing lock and refresh; never launch a duplicate job.

At start, target change, resume or compaction, apply the complete
`skills/runtime-protocol.md#shared-memory-continuity`, beginning with
`state.target_memory`. That section owns current handoff, condition warnings,
history expansion and checking inherited judgments against current commands.
Reuse valid context and refresh it after owner changes; a filename search cannot
establish that no memory exists.

Use `cd -- <repo_root_shell> &&`, `arguments.target_shell`, the exact
`arguments.seed_url`, and `--auth-file <arguments.auth_file_shell>` when supplied.
Retain `--context-file <arguments.context_file_shell>` and the complete
`arguments.hunt_auth_flags`. An executor that cannot enforce that context must use
the supported boundary in `docs/autopilot-lanes.md#recon-and-surface` or report the
limitation; never drop the context to make a request work.

### Investigation Skill

After Bootstrap admission and required execution recovery, use the native Skill
`src-hunter` before choosing new investigative work. It supplies business understanding,
hypotheses, method selection, evidence interpretation and rotation in this same
session, with the current target/Scope, facts, mode and remaining budget.

Reuse its complete current body when already in context. Otherwise invoke the
host's native Skill tool with `src-hunter`; on a host without that tool, read and
apply the complete `skills/src-hunter/SKILL.md` from the selected checkout.
A description, path or runtime hash is not body context. Restore missing body
after compaction; do not invoke again per lane or round. Waiting, terminal cleanup
and execution recovery do not require a fresh Skill invocation.

Apply `skills/runtime-protocol.md#shared-knowledge-recall`: start SRC from the
shortlist, then read and apply complete relevant methods and internal modules for
the chosen question. Loading the Skill or shortlist alone is not method use.
Reuse available material; do not load the whole library. This command retains
continuation, waits, claims, evidence write-back and closure; loading a Skill
starts no separate hunt, controller or delegation.

### Execution Invariants

Before execution, apply `rules/ccst/hunting.md`. Before network calls, use
`config.json.resin` through `docs/resin-proxy.md` in the same shell; never print
secrets or persist proxy setup. Scope/Auth, request caps and partial cursors hold.
Under `rules/ccst/tool-ai-boundary.md` and `rules/ccst/coverage-gate.md`, supported
families, primitives and chains remain eligible. Scanner-negative, incomplete
material or memory alone proves no Coverage. Quick only lowers Recon cost;
deep follows evidence and value.

Read the selected evidence and execution contract before making the call:

| Situation | Required preparation |
|---|---|
| A selected lane | Reuse `state.lane_contract` if it matches the work and `text_available=true`; otherwise read the matching section of `docs/autopilot-lanes.md` |
| Selected `run_recon` | Preserve `arguments.recon_flags`; follow the full-state and cursor rules in `docs/autopilot-lanes.md#recon-and-surface` |
| Any Round action, including Recon or validation | Follow `commands/autopilot-round.md#round-mechanics` and obtain fresh `allowed=true` before execution; missing round requires prepare **then a new claim**; report claims bind Finding/assessment/delivery |
| Action-bound work | Read `docs/autopilot-lanes.md#state-and-queue` and `docs/evidence-runners.md#绑定已认领行动`; claim/bind with the same explicit `--actor OPERATOR`; inspect a failed Action claim once, never guess or retry it |
| A useful independent subtask | Default zero specialists; follow `docs/autopilot-lanes.md#inline-specialist-propagation`. The current session owns claims, writes and closure |

Use only session-visible MCP tools; presence does not establish readiness.
Missing or failed tools stay partial/blocked. Follow the selected lane's bounded
retry allowance: the browser contract permits one transient-error retry in
`docs/autopilot-lanes.md#browser-source-and-js`. Without an explicit allowance,
do not retry a failed source/tool in this invocation.

Save raw evidence immediately and register/resolve/kill as applicable, using real
receipts. Follow `skills/runtime-protocol.md#5-execution-and-write-back`: when there
is no Finding, use `record-observation`; for an existing Candidate, use `record-evidence`.
Queue completion follows `docs/autopilot-lanes.md#state-and-queue` separately.
Registration failure retries only registration with the saved attempt/material.
Missing outcomes stay recoverable; never replay requests with unknown effects.

For publication, follow `commands/report.md`: no placeholder reports or automatic
external submission. Without an operator-declared external destination, record
delivery eligibility Q7 as `internal delivery: not-applicable` and publish in-turn;
never pause to ask for a platform. External submission remains manual.

### Refresh After An Action

Both modes refresh after each action, including validation or publication.
Round writes its terminal heartbeat after registration/resolve and **before** this
refresh. Run once:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json
```

Use fresh `control`; re-read only after owner writes. A failed read stops work
based on stale state until recovery. `loop_guard` is advisory: it neither overrides
gates/claims nor requires an endless run. Decide continue/rotate/stop in-turn;
write decision/next_action on rotation, blocker or stall only. Round heartbeats
remain mandatory.

Review bounded owner/Surface/observation deltas on new evidence/assets, phase change,
blocker, rotation or batch end. For waits and later writes, use `--bounded` alone.
Read-only checkpoint snapshots follow `arguments.checkpoint_trigger`; cognitive
writes follow `skills/runtime-protocol.md#cognitive-write-timing`.

### Transition And Finish Contract

Stop for an actual user/scope/budget boundary, a demonstrated blocker preventing
useful in-scope work, or an evidence-based judgment that no worthwhile next question
remains. Explain the specific reason and valuable unpursued leads.
Findings/report count, anonymous denial or missing-but-obtainable sessions alone
do not justify stopping. Otherwise continue with `src-hunter`, including after
publication. A failed writer or object cleanup constrains that operation; assess
independent business paths before declaring a target-wide blocker.

Round budget ends only that bounded round. `max_lanes` limits new lanes, not
evidence import, owner write-back, cleanup, Checkpoint or Closure; budget alone
never requires another round. Before pause, handoff or finish:

- Resolve hypotheses and retain leads/gaps. Drain any used `oast_listen`.
- Import browser artifacts and close the session under
  `docs/autopilot-lanes.md#browser-source-and-js`; failed close stays partial/blocked,
  and an unclosed session must not be replaced.
- Save memory/current handoff through Shared Memory Continuity. Register unresolved
  Actions before read-only Checkpoint. A justified stop with pending owners needs
  handoff; handoff alone authorizes no stop or exhaustion.

#### Claiming Exhaustion

Before claiming exhaustion, run Coverage `rebuild` then `find-gaps` per
`rules/ccst/coverage-gate.md`, then read-only Closure:

```bash
cd -- <repo_root_shell> && python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json
```

Missing, empty or truncated data proves nothing. Global Review covers bounded
Surface/Observation long-tail, Coverage/Ledger/Finding, Case/business chains,
Queue/pending reports/Runtime, asset relations/`chain_context`, Browser/JS/Source/Intel,
Scope/external dependencies/blockers/residual candidates. Expand needed evidence;
external relations stay passive. Use the `--record-global-review` operation in
`commands/checkpoint.md` to bind the current snapshot/evidence; `follow_up` needs
active Queue work.

Re-read Closure after writes. Exhaustion requires `closure.verdict=finish` **and**
`can_claim_exhausted=true`. Actor gaps are cell-local; observation residuals create
no mandatory actions.

#### Final Response

Give target/mode, evidence, findings/candidates, blockers/dead ends and next action.
Include exactly one presentation-only `Memory recommendations` section in this
final response only: promote / target-only / reject, with `none` and a reason for
each empty bucket. Use `knowledge/promotion-rules.md` and `rules/ccst/retrospective.md`.
This advice causes no writes or routing/budget/Queue/lifecycle/closure changes;
promotion remains review-gated.
