# Design

The reviewed architecture and alternatives are retained in
`research/architecture-proposal.md`: one parent-session investigation loop,
unchanged 6k method source, a thin Claude host boundary and existing domain owners.

## Phase 1 boundary

Create one isolated research harness outside `tests/`, running the real Claude
binary with synthetic commands/hooks and a loopback fake Messages API. Mount and
network namespaces keep personal settings, real target data and external network
unavailable. The API uses dummy authentication and deterministic replies; this
proves host mechanics, not model reasoning or investigation quality.

Verify dynamic content, command-frontmatter hooks, SessionStart resume/compact,
Stop continuation and new-prompt/interruption. Measure whether oversize hook
content becomes a preview. A simulated Claude parser cannot replace native proof.

## Phase 2 boundary

Use the proven native mechanism around existing Bootstrap/runtime protocol.
Preserve JSON API and Scope/Auth ordering. Use one source body with its package
root. Host state contains invocation/session binding only, never target progress.
Normal stop intent belongs to existing Checkpoint review with current evidence
and snapshot binding. Closure remains the exhaustion owner. No shell classifier,
LLM controller, target queue or knowledge registry is introduced.

## Proven host integration boundary

Command frontmatter cannot provide resume/compact hooks in the verified CLI.
`runtime_doctor` will therefore install one CCST-owned group per native event in
settings.json, preserving all other settings/hooks. Groups share the existing
ownership receipt, preflight, source binding and recovery journal. Modified or
unowned matching groups reject the batch; no independent settings installer.

One small standard-library host contract module supplies source capture, escaped
chunk sizing and hook configuration to both installation and execution. This
keeps runtime_doctor independent of Bootstrap/state and avoids an import cycle.
The execution adapter consumes those owners. Recovery emits complete static
source chunks plus a fresh bounded owner view with exact expansion; resuming the
same binding refreshes the full Bootstrap/memory view before target execution.

UserPromptSubmit suspends the binding but retains target/arguments/invocation;
ordinary requests are never automatically rearmed. A same-task continuation uses
the emitted resume command; new `/autopilot` creates a new invocation. Native
interrupt needs no model approval or Stop event. No transcript parsing.

Expected additions are tools/claude_hook_contract.py and tools/autopilot_host.py;
runtime_doctor/install documentation joins the existing expected production scope.
The transport module owns no domain facts. Existing review receives optional
termination fields; historical reviews and Closure exhaustion rules remain intact.

Expected production scope: commands/autopilot{,-round}.md; one small host module;
Bootstrap/gate/state only where shared public contracts need it; Checkpoint's
existing review validation; runtime-protocol/adapter/architecture and focused specs.
6k methods and original rules remain outside the change scope.

Claude executes independent dynamic expressions concurrently and downgrades a
large single output to a saved-file preview. Entry therefore keeps exactly one
Bootstrap call and independent bounded static body parts. Each part validates the
installed/observed source contract, independent of activation order; its source
hash must match Bootstrap's host binding. Static delivery is not admission. This
avoids a second prepared-Bootstrap cache or deduplication by user turn, which would
merge multiple native Skill/scheduled invocations. Only activation stores the
immutable recovery source snapshot; all current target facts remain in Bootstrap.

## Live acceptance correction

The first real-model lab delivered all source bodies and published two reports,
but stopped after 505 seconds against an explicit 720-second allowance. The
four-field review proved invocation identity, not attainment of its stated limit.
The smallest correction keeps the same Checkpoint review: only explicit_limit
requires either elapsed_seconds or the existing capped round_id. The host retains
the invocation start across resume and checks the clock/current Round owner.
An optional `--max-seconds=SECONDS` binds the explicit threshold at entry; an
ending review cannot invent or shorten it. Round limit binding retains the active
Round or the entry cap and excludes the previous completed Round. Native cost
limits interrupt the CLI, without a cost ledger, prompt parser or default budget.

The entry puts the investigation loop first: initial Recon may run in parallel
with independent evidence-backed work; collect its result and new Surface material
before dependent work or final stopping. Apply the selected method, capture plus
registration, refresh and next question.
No 6k method or per-tool semantic gate is changed. The live trace, not a prompt
assertion, must show consumption. A report alone is still insufficient acceptance.

User steering allows independent work during Recon and defers low-impact procedural
issues. Retain method guidance but do not add per-tool compliance gates. Runtime
phase locks must not erase existing Queue/Finding continuations. A complete valid
review may retain missing residual tokens without losing its checked termination;
scope/explicit-limit/global-blocker stops may use it, while exhaustion and a
no-worthwhile-work claim retain the complete-review requirement.

Native CLI evidence additionally shows background task results can arrive through
UserPromptSubmit. Preserve binding unchanged for the exact reserved notification
envelope, rather than suspending active investigation or rearming paused work.
This is host-envelope recognition, not sender authentication or transcript parsing.
An explicit elapsed-time cap remains a ceiling, not a request to sleep until expiry.
The research harness uses native cost/time supervision without another turn ceiling;
restart keeps the original cost ceiling because Claude restores cumulative usage.

## Failure, compatibility and rollback

Preview is not full delivery. Recovery never replays unknown network effects.
Missing/damaged owners are errors, not empty history. User interruption wins;
stale hooks cannot restart work in later ordinary conversation.

First prove host capability. If lifecycle/size behavior cannot meet the contract,
record it and revise the host decision before editing product owners. No fallback
runtime or speculative global settings installer. Baseline `e7f6b3d` preserves
the prior product; Phase 1 only changes task research. Never reset unrelated WIP,
overwrite real stores or synchronize the personal Claude runtime.
