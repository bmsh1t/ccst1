---
name: bug-bounty
description: Cross-stage bug bounty coordinator for target isolation, Skill routing, chain handoff, validation, and report preparation. Use when work spans recon, learning, hunting, validation, or reporting; use a narrower Skill for a single well-defined lane.
---

# Bug Bounty Workflow Coordinator

Coordinate `Recon -> Learn -> Hunt -> Validate -> Report` without duplicating the
methods owned by narrower Skills, Rules, Cards, or deterministic tools.

## Canonical Owners

- Target/session memory and write-back: `skills/runtime-protocol.md`.
- Hunting semantics and value-first coverage: `rules/hunting.md`.
- Coverage/completion: `rules/coverage-gate.md`.
- Hypothesis selection and rotation: `skills/bb-methodology/SKILL.md`.
- Finding validity: `skills/triage-validation/SKILL.md` and `/validate`.
- Report presentation: `skills/report-writing/SKILL.md`; reporting checks and
  scoring calibration: `rules/reporting.md`.

## Cross-Stage Loop

1. Read the current target state and bounded Context Pack; keep one target and
   auth context active.
2. Honor live runtime waits and resume owner-selected Queue/Candidate work before
   inventing another route.
3. Ask `skills/bb-methodology/SKILL.md` for the next hypothesis when selection or
   rotation is unclear.
4. Load one narrower Skill plus only the Cards/references selected by current
   evidence.
5. Execute the bounded action through the existing tool/MCP path and preserve raw
   target-owned evidence.
6. Write Leads, Signals, Candidates, actions, and coverage through their canonical
   owners; then refresh state before choosing another stage.
7. Send report-ready Candidates through validation and reporting. Bare primitives
   remain chain leads or dead ends.

## Skill Routing

| Need | Route |
|---|---|
| Session strategy, hypothesis choice, rotation, stopping | `skills/bb-methodology/SKILL.md` |
| Scope, hosts, endpoints, JS/source and recon evidence | `skills/web2-recon/SKILL.md` |
| Web/API vulnerability-family testing | `skills/web2-vuln-classes/SKILL.md` |
| Concrete technique detail | Use the model's general knowledge; read `skills/security-arsenal/SKILL.md` only for project-specific evidence and owner rules |
| Validity, report/no-report, chain precedence | `skills/triage-validation/SKILL.md` |
| Report drafting and triager-facing wording | `skills/report-writing/SKILL.md` |
| Android/iOS | `skills/mobile-pentest/SKILL.md` |
| CI/CD and supply-chain workflows | `skills/cicd-security/SKILL.md` |
| Web3/wallet/token/smart contracts | The matching Web3/token Skill |

## Target Isolation

- The active command target set is the execution surface unless the user changes
  it. Off-target discoveries stay external chain context.
- Temporary focus/skips are per-current-target and per-current-invocation only;
  they do **not** replay onto the previous target or a future target.
- Only the current user turn can set or clear a temporary lane exclusion.
- Never promote target domains, credentials, one-time answers, or target-specific
  test inputs into reusable project knowledge.

# Methodology Boundary

Hypothesis selection, evidence-driven rotation, and stopping live in
`skills/bb-methodology/SKILL.md`; this Skill handles cross-stage routing and handoff.

## Evidence-Selected Handoffs

Choose the narrower Skill from the stage and evidence. Before a boundary-specific
action, apply `skills/runtime-protocol.md#shared-knowledge-recall`; use the returned
card paths instead of maintaining a coordinator-side card map. A handoff keeps
the target/auth context, evidence references, and the concrete question to answer.
The selected Skill and card own the detailed branch and evidence requirements.

## Chain Coordination

Record a chain as `primitive -> connector -> victim/asset path -> impact`.
Start from an observed Signal, preserve baseline and changed evidence, and create
one bounded next action with a kill condition. A concrete but unproven connector
remains chain-required; a bare primitive is not report-ready. Do not copy full
chain tables here; `skills/triage-validation/SKILL.md` owns precedence.

## Validation And Report Handoff

- Exploration may preserve useful Leads/Signals. Candidate promotion requires
  the lifecycle and evidence dimensions owned by `rules/coverage-gate.md`.
- An evidence-ready Candidate enters validation before optional severity
  expansion. Run write/sibling expansion only when validation identifies a
  missing proof dimension or its bounded result can change reportability or
  severity.
- `/triage` and `/validate` apply the canonical report/no-report decision. This
  coordinator does not duplicate the seven-question gate, severity table, or
  never-submit list.
- A validated finding routes to `skills/report-writing/SKILL.md` and
  `rules/reporting.md`; raw reproducible evidence and actual impact control the
  claim and severity.
- Never auto-submit a report.

## Finish / Write-Back

1. Persist raw evidence references and unresolved actions through their owners.
2. Refresh coverage and checkpoint state; do not infer completion from prose or
   scanner-negative output.
3. Write target-specific leads, next actions, dead ends, and reopen conditions to
   the target layer.
4. Recommend project-level promotion only for transferable route gaps, evidence
   gates, seeds, stop conditions, or de-noising regressions.
