---
description: Review an evidence-backed finding for a higher-impact connector. Selects the next bounded chain question without prescribing payloads, protocol runners, or a fixed A-to-B-to-C route. Usage: /chain
---

# /chain

Review whether a validated primitive has an evidence-backed connector to a
meaningful victim, asset, authorization, or execution boundary.

## When to Use This

Use after a Signal or Candidate has a concrete replayable artifact and the
current validation result says a connector is required or could change impact.
A theory, scanner match or static clue still needs evidence before becoming a Finding.

## Inputs

- Canonical finding ID and its validation summary
- Target-bound artifact references and observed baseline/delta
- Current actor, role, object, workflow, and prerequisite context
- The intended impact and the smallest safe next evidence action

## Method and Handoff

Read the complete [connector review](../skills/src-hunter/modules/triage-validation.md#evidence-bounded-connector-review).
It owns connector questions, per-hop evidence and stop/reopen rules. This command
supplies the selected context; it owns no payload catalog, runner or second lifecycle.
Return evidence and the next question to the parent for canonical writes. The parent
consumes single-step validation receipts; deferred text or a new delivery need uses /report.

## Output

```text
CHAIN: [finding ID -> connector -> impact] | STATUS: [CONFIRMED / NEXT_ACTION / STOP]
EVIDENCE: [artifact refs and observed deltas]
PREREQUISITES: [reachable conditions and scope]
ACTION: [one bounded next evidence action or parent validation/publication handoff]
WRITE_BACK: [canonical finding/queue/evidence owner update]
```
