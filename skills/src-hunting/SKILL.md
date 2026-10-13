---
name: src-hunting
description: Web2 hunting entry for business-model reasoning, competing hypotheses, evidence-selected experiments, cross-domain investigation and conditional stopping; specialist Skills answer bounded questions without taking over the target.
---

# SRC Hunting — Shared Investigation Core

The native main session owns the global investigation: what question matters,
which explanations compete, what evidence distinguishes them, and whether to
continue, pivot or stop. Manual and automatic work share this core; automatic
continuation, waits and budgets remain in `commands/autopilot.md`. Loading a Skill
never starts another controller or grants permission to continue autonomously.

## Workflow

Recover current target, explicit intent, Scope/Auth, unfinished work, saved
experience and current handoff through `skills/runtime-protocol.md`. Current
owner facts outrank a conversation summary; owner waits, locks and unresolved
execution effects remain binding. A resumable Queue item is a candidate for
attention, not an automatic priority or permission to bypass its owner.

Build the business model from observed features, actors, objects, tenants,
workflows, crown jewels and trust boundaries. Maintain
`evidence/<target>/business_model.md` with native Read/Write/Edit as evidence
arrives: keep source references, distinguish observation from judgment and edit
incrementally rather than regenerating prior conclusions. It is an advisory
business-context note, not another Action/Finding or target-memory authority.

Work from the information gap rather than a Recon → Hunt → Validate checklist:

- State the concrete question and competing explanations without assuming the
  desired impact. Compare expected learning, plausible impact, current evidence,
  ownership, reversibility and cost. Machine scores and route labels are advisory.
- Choose the smallest experiment that can distinguish those explanations. Keep a
  normal baseline; compare one actor/object, parser, workflow/state, client/version
  or downstream-consumer boundary at a time. These are lenses, not a taxonomy;
  combine or invent dimensions when the observed feature demands it.
- If evidence is thin, actively discover material: browser/API requests, saved JS,
  source, schemas, relevant component intelligence, business flows or owned actor
  comparisons. An existing high-signal question need not wait for broader recon.
- Execute through an existing owner/native tool and preserve target-owned raw
  inputs, outputs and actual receipt. Unknown effects after interruption require
  recovery, not blind replay. Read only the matching execution contract in
  `docs/autopilot-lanes.md`, including State And Queue before claim/resolve.
- Interpret both confirming and contrary evidence. A primitive is not impact:
  connect `primitive → connector → victim/asset path → demonstrated impact`.
  An unobserved consumer cannot decide a kill condition; make one bounded consumer
  check or leave its effect unknown. A framework, status, parser error or scanner
  result alone remains a Lead/Signal.
- Send an evidence-ready Candidate to `skills/triage-validation/SKILL.md` now.
  Optional write/sibling/severity expansion is justified only by a missing proof
  dimension or a bounded result that can change the claim. It must not postpone
  an already supported finding or inflate its impact. Draft validated reports
  through `skills/report-writing/SKILL.md`; never auto-submit.

There is no per-thought form. Preserve decision context when it changes action,
needs recovery or crosses a real handoff: question, hypothesis, evidence refs,
expected learning, owner budget, prerequisites and kill/reopen conditions.
A depth pack from target-observed request shapes may support comprehensive API
work; one passive observation is not API completion. Partial cursors and untested
dimensions stay visible and resumable.

## Evidence-Driven Rotation

Compare hypothesis, surface, actor/state, observation kind and evidence reference
with the prior result. Continue while evidence changes an explanation, reduces
uncertainty or makes a connector testable. Rotate after homogeneous no-information
results, a repeated progress fingerprint, an owner budget boundary or unavailable
prerequisite; a higher-value structural signal can justify an immediate pivot.
Stop this path when its actual kill condition is met. Record the evidence delta
(including no delta), remaining prerequisite and condition that would reopen it.
Elapsed time or scanner-negative output cannot prove exhaustion or coverage.

A failed attempt applies to its recorded conditions, not all future targets.
Budget stop and low priority remain unresolved, not technical dead ends. New
identity, source, version, state or consumer evidence can reopen a question.
Only the current user turn changes temporary lane exclusions; they do not carry
onto another target or invocation. Off-target discoveries remain passive chain
context until the explicit scope owner admits target work.

## Reading Order: Follow the Question

Read the current facts first. Then read whichever complete method unit answers
the information gap: a deep card, playbook, optional index or several domains.
There is no mandatory summary-card gateway, fixed six-domain table or full-index
opening ritual. Already available material need not be reread; no matching card
does not prevent native reasoning or a bounded discovery experiment.

`knowledge/playbooks/web2-evidence-contracts.md` owns the migrated Web/API method
and evidence contracts: focused route notes, chain examples, evidence/write-back
and stop conditions. Read the relevant complete unit, including prerequisites,
state/order dependencies, success evidence, counterexamples and reopening limits.
Do not execute from an isolated route-table row. The sole method registry remains
`knowledge/capabilities.yaml`; Context Pack exposes its catalog, not a decision.
Shared recall and compaction currentness follow
`skills/runtime-protocol.md#shared-knowledge-recall`.

## Specialist Boundaries and Routing Exceptions

- Surface/host/URL/material questions: `skills/web2-recon/SKILL.md`. Recon may
  choose local collection experiments; global reprioritization returns here.
- A public repository or readable source: `skills/whitebox-audit/SKILL.md` answers
  the bounded source question; `/source-hunt --source-file PATH` preserves selected originals;
  native Read/Grep follows entry → transformations → guards → sink. Bind revision,
  file:line, call/data flow, attacker control, preconditions and contrary evidence.
  Check deployed version/configuration separately; source reachability alone is
  not runtime exploitability. Preserve unresolved edges as partial/blocked. The
  retired JS reader stays retired; no extraction wrapper is needed.
- A real login form: `skills/credential-attack/SKILL.md` for baseline review,
  source/preparation and the decision whether credential execution is warranted.
  It does not silently trigger password guessing; its command owns preflight,
  lockout/rate/stop controls. Token, recovery and callback reasoning can combine
  the relevant Web/API method directly.
- Explicit Android/iOS, CI/CD, contract or token questions: `mobile-pentest`,
  `cicd-security`, `web3-audit` or `meme-coin-audit`. Experts select local methods,
  not the global target agenda; they can return unknowns or counterevidence.
- Candidate proof and report/no-report method: `triage-validation`; technical
  assessment, delivery eligibility and Action resolution remain separate owner
  commands. Specialist self-report cannot confirm a Finding or complete Action.
- Shared execution/owner lookup: `docs/tool-index.md#execution-contract-lookup`.

## Real Delegation and Execution Handoff

Ordinary same-session reading needs no delegation envelope, role switch or
synthetic receipt. For a real cross-agent/execution boundary pass:

- Input: target/scope references, current facts and evidence bindings, the question,
  competing explanations, missing conditions, allowed actions and write boundary.
- Output: answer and unknowns, raw evidence increment, explanations supported and
  refuted, remaining conditions, the next discriminating check and changes proposed
  for owner acceptance. Actual execution includes attempt/operation/claim receipts;
  pure analysis invents none.

The main session checks current Scope/Auth and compatibility of actor, target,
revision and session state, accepts useful results and writes through the domain
owner. Do not rerun completed evidence collection merely to make it your own, or
splice incompatible sessions to manufacture a chain. Experts propose global
pivots; the main session decides them.

## Evidence, Memory and Hard Owners

Raw observations and receipts go to existing evidence/Store owners. Save important
conditional experience and unresolved intent at stable conclusions and handoffs,
not each thought or every observation. At pause, target switch, compaction or exit,
preserve explicit structured `next_intent`, conditions and observation references
through the existing handoff owner; natural-language explanation does not replace
those recovery bindings. Budget exhaustion stops new work, not evidence recovery,
cleanup, terminal heartbeat and required closure. Unknown work remains unknown.

`rules/red-lines.md` governs side effects; `rules/hunting.md` holds hunt semantics;
`rules/coverage-gate.md` governs completion; `rules/tool-ai-boundary.md` separates
AI judgments from tool facts. Current Bootstrap, Scope/Auth, claim/token/actor,
CAS, terminal heartbeat and evidence integrity are mandatory when applicable.
Reading advice never weakens execution constraints. Tools preserve facts; they do
not choose hypotheses or make semantic judgments. Save private target details
only in the target layer; transferable knowledge uses the reviewed `/distill`
promotion path, never automatic sharing of credentials or one-target failures.
