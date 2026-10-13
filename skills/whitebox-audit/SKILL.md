---
name: whitebox-audit
description: Answer source, JavaScript and dependency questions about reachable inputs, trust boundaries, authorization guards and sinks, with exact source bytes and explicit deployment uncertainty.
---

# Whitebox Audit — Question-Bound Source Investigation

Answer the delegated question; `skills/src-hunting/SKILL.md` retains the global
hypotheses, priorities and stop decision. Blackbox evidence can select a source
path and source evidence can propose a runtime comparison. Neither direction is
mandatory, and this Skill does not start a repository-wide audit or a controller.

## Inputs and Method

Use the current target/scope, facts and evidence references, question, competing
explanations, missing conditions and allowed actions/write boundary from the
investigation core. Add available source/material refs, working-tree/build
context and known deployed version/configuration. Ordinary same-session reading
needs no handoff form. Unknown revision or deployment correspondence is valid
input, not permission to invent it.

Read the complete method in
`knowledge/cards/information-disclosure-source-config.md#源码问题方法可达性守卫与运行桥接`.
The card owns entry-to-sink reasoning, counterexamples and stopping conditions;
`knowledge/playbooks/web2-evidence-contracts.md` owns migrated Web/API evidence
gates. These are methods, not automatic execution plans. Select only the method
needed for this question; no keyword match or full-index ritual is required.

## Reading and Original Evidence

- Native Read/Grep reads already available source and cached JS. Follow actual
  registration/import/call edges, not only search hits or function names. Preserve
  missing generated code, dynamic dispatch and absent middleware as unknown edges.
- `/source-hunt --repo-path PATH --source-file RELATIVE_PATH` can preserve selected
  current UTF-8 bytes. Repeat `--source-file` for the entry, guard and sink needed
  for the question. Read its `repo_source_meta.json/source_capture` and the saved
  originals, not a later live working tree. Use the returned artifact + SHA256 +
  original relative path + line range. HEAD supplies version context only.
- Existing CI originals live under `repo_workflows/`; do not recollect them merely
  to change ownership. Existing source-map/JS originals can be used directly with
  their provenance and a checked content binding. `deep_js_packer` is only for a
  concrete missing bundle/chunk/source-map signal, not a default read wrapper.
- Capture is bounded to selected files, not whole-repository coverage. Missing,
  oversized, non-UTF-8 or unsafe paths remain explicit `partial`; failed snapshots
  are not evidence of absence. Source updates require new snapshots and references,
  never silent replacement of the earlier proof.
- Unavailable tools or source do not trigger installation, downloads, dependency
  scripts, application startup or broader network access. Return the usable
  material and precise missing expansion path. Reading source is not executing it.

## Answer and Handoff

Return a compact answer with these facts (natural language is sufficient):

1. **Question and answer:** supported, contradicted or unresolved, with the
   competing explanation that survives. Separate directly observed code from
   inferred call/data-flow relationships.
2. **Source binding:** repository/material origin, actual artifact/SHA256, revision
   or unknown, original file:line ranges, relevant build/dependency context and
   deployed correspondence: matched, mismatched or unknown with supporting refs.
3. **Path:** input/actor control → routing/call edges → transformations → guards →
   sink/affected asset. For each uncertain edge say why; classify reachable under
   named conditions, blocked by a demonstrated guard, or unknown. Include the
   strongest counterexample, not only a vulnerable-looking function.
4. **Bridge:** blackbox observation refs supporting or conflicting with the source
   explanation; actor, tenant, version, feature/config and timing conditions must
   agree before combining them. Version match alone does not prove configuration.
5. **Next distinction:** one smallest check that would separate the remaining
   explanations, its prerequisite and stop condition; it is a proposal, not an
   Action or command authorization. Keep missing/unread regions and their exact
   expansion refs visible when partial, blocked or stopped by budget.
6. **Owner acceptance:** proposed evidence/experience or Candidate only. Attach
   actual attempt/operation/claim receipts if execution occurred; pure reading
   invents none. Main session accepts results and chooses explicit owner writes.

Before `triage-validation`, a source-derived Candidate must carry **file:line +
source-byte binding + data flow + preconditions + counterevidence**. Incomplete
material is partial/blocked, not tested-clean. A source candidate, a conditional
reachable path, a runtime observation, a technical assessment and a delivery
eligibility decision are different claims. Pure-source impact may be submitted
to the existing assessment owner with its exact limited scope; do not fabricate
runtime verification or automatically promote it to a Finding.

`rules/red-lines.md` and current Scope/Auth still govern proposed experiments.
`skills/runtime-protocol.md` owns continuity/write-back; `triage-validation` owns
proof readiness and `report-writing` owns expression of accepted results. This
Skill cannot close Action/Coverage, confirm a Finding or submit a report.
