---
description: Review an evidence-backed finding for a higher-impact connector. Selects the next bounded chain question without prescribing payloads, protocol runners, or a fixed A-to-B-to-C route. Usage: /chain
---

# /chain

Review whether a validated primitive has an evidence-backed connector to a
meaningful victim, asset, authorization, or execution boundary.

## When to Use This

Use after a Signal or Candidate has a concrete replayable artifact and the
current validation result says a connector is required or could change impact.
Do not use this command to turn a theory, scanner match, or static clue into a
finding.

## Inputs

- Canonical finding ID and its validation summary
- Target-bound artifact references and observed baseline/delta
- Current actor, role, object, workflow, and prerequisite context
- The intended impact and the smallest safe next evidence action

## Decision Tree

Choose the branch with the clearest information gain, highest plausible value,
and lowest reversible cost. These are alternatives, not an execution order:

| Observed primitive | Connector question | Typical evidence gate |
|---|---|---|
| Identity or object boundary | Does a different actor, tenant, role, or object cross the protected boundary? | Reproducible actor/object differential |
| Server-side fetch or callback | Does the server reach a controlled internal or downstream boundary? | Raw fetch plus a second controlled signal |
| Redirect, token, or session behavior | Does a legal flow bind the token/code/session to the wrong party? | Controlled account/session transition |
| Parser, upload, or deserialization behavior | Does a downstream consumer produce data, state, or controlled execution impact? | Read-back or bounded consumer evidence |
| Schema, source, or configuration exposure | Does the exposed material unlock a reachable protected action? | Proven ownership, reachability, and least-impact action |
| Workflow, race, or quota primitive | Does a bounded replay change a protected state or limit? | Repeatable state delta on a test resource |
| WebSocket, gRPC, GraphQL, or LLM/RAG signal | Does the observed channel cross an identity, object, or tool boundary? | Target-bound frame/RPC/query/tool artifact and impact delta |

The table is a set of common shapes, not an allowlist. Select another connector
when current evidence supports it, or stop at the primitive when no connector is
testable.

## Chain Contract

Record each hop as:

```text
validated finding ID -> connector hypothesis -> prerequisite -> replayable artifact -> observed delta -> impact
```

Every hop must keep the same target identity and actor context, reference an
existing artifact, and change one meaningful boundary at a time. The model may
choose the protocol, input, and tool path that fits the evidence; `/chain` owns
neither payloads nor a second runner.

Before reporting, either each linked finding passes the canonical validation
gates or the complete path is proven end to end. Independent findings remain
separate reports; combine only when the impact genuinely requires the linked
path.

## Evidence-Bounded Transition Rules

```text
If the next hop is not confirmed after a bounded evidence batch or its progress fingerprint repeats, preserve the next evidence action and return to the parent
finding's normal lifecycle.
If the connector is confirmed, stop expanding when the claimed impact is proven;
do not search for an additional hop merely to make the narrative longer.
If a prerequisite is unavailable or out of scope, record it and keep the chain
open only when a concrete reopen condition exists.
```

The progress fingerprint includes hypothesis, surface, actor/state, observation
kind, and evidence reference. Repeated fingerprints with no evidence delta are
a rotation/stop signal, not a reason to widen inputs.

## Output

```text
CHAIN: [finding ID -> connector -> impact] | STATUS: [CONFIRMED / NEXT_ACTION / STOP]
EVIDENCE: [artifact refs and observed deltas]
PREREQUISITES: [reachable conditions and scope]
ACTION: [one bounded next evidence action, or /validate -> /report]
WRITE_BACK: [canonical finding/queue/evidence owner update]
```
