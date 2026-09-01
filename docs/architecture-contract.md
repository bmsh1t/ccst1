# AI-Native Architecture Contract

This is the authoritative architecture contract for the file-backed, Linux-first, single-operator runtime. It defines logical boundaries; it does not require a directory migration or a new framework.

## Five Planes

```text
Intelligence -> AI Decision -> Deterministic Kernel -> Execution
                                      |                 |
                                      +---- owners <----+
                                      ^
                               Projection views
```

### Intelligence plane

`rules/`, on-demand `skills/`, and governed `knowledge/` provide constraints, decision branches, ROI signals, evidence expectations, and stop/rotate conditions. They do not own target progress, action status, coverage, findings, report readiness, or closure. Skills preserve model choice: they are decision trees and evidence contracts, not fixed test sequences, input catalogues, or duplicated tool manuals.

### AI decision plane

The inline model chooses hypotheses, route, ROI, and runtime test inputs from bounded owner-backed projections. It requests work through the existing `tools/action_queue.py` activation metadata (`activation_contract_projection()`); no parallel intent schema is permitted. The model cannot write owner files or declare lifecycle finality.

### Deterministic kernel

The kernel enforces Scope/Auth, red lines, budgets, queue lifecycle, Runtime/Case state, canonical evidence, Finding lifecycle, locks, and recovery. Durable owners remain separate:

- Scope/Auth context: scope and credential boundaries
- Runtime State: non-derivable execution and wait state
- Action Queue: admitted work and action lifecycle
- Case State: actor/object/business context
- Evidence Ledger and raw operation evidence: replay-backed observations
- Finding Index: finding identity, provenance, and final validation status
- Target Memory and history owners: narrowly scoped advisory/episodic context

Each owner has one schema and mutation API. Cross-owner atomicity is not implied by file locking; coordination must be explicit, idempotent, and reconcilable.

### Execution plane

Reusable HTTP, browser, MCP, subprocess, source, and validation capabilities execute admitted actions. Execution returns the canonical validation-runner summary and raw evidence shape already consumed by the Evidence Ledger and Finding Index. A protocol name alone (WebSocket, gRPC, GraphQL, or LLM/RAG) does not justify a dedicated runner; add one only when an existing execution boundary cannot provide deterministic, reproducible, budgeted, evidence-linked behavior reusable across targets.

### Projection plane

Surface, Coverage, Checkpoint witness, Resume, Context Pack, Autopilot views, and Report are projections or generated artifacts. They may write only their own rebuildable cache/artifact and may request an owner mutation through that owner's public API. They must never write another owner's file, become a second lifecycle reducer, or turn advisory prose into finality. Deleting and rebuilding a projection must leave canonical Runtime, Queue, Case, Evidence, and Finding facts unchanged.

## Existing Boundary Contracts

| Boundary | Contract | Authority |
|---|---|---|
| AI -> kernel | versioned activation metadata | `tools/action_queue.py` |
| execution -> evidence | canonical runner summary plus raw operation material | `tools/validation_runner.py` |
| evidence -> finding | provenance and finality checks | `tools/finding_index.py` |
| target -> storage | canonical target and storage-key helpers | `tools/target_paths.py` |
| knowledge -> context | registry-backed selection and budgets | `tools/knowledge_registry.py` / `tools/context_pack.py` |

Do not introduce a universal `RuntimeStore`, a second result/intent schema, or a second lifecycle owner. Existing public imports, CLI defaults, schemas, and direct-script compatibility remain constraints.

## Change Classification

| Change | Default surface | Validation |
|---|---|---|
| reasoning, ROI, routing, stop condition | Skill/Knowledge/Rules | focused governance or recall test |
| reusable knowledge | card + registry | `knowledge_audit --strict` and recall test |
| deterministic execution | existing executor/runner and evidence adaptation | focused executor/evidence test |
| projection/view behavior | projection owner and own-cache tests | focused projection test |
| lifecycle, schema, or invariant | one named durable owner plus consumers/migration | owner, cross-owner, and recovery tests |

An ordinary capability change should not touch a durable owner. If it does, the requirement must name the invariant that changed and explain every owner crossing. File count is a review signal, not a correctness gate.

## Memory Contract

Memory is retention and recall policy, not a universal state owner.

| Layer | Authority | Recall/retention boundary |
|---|---|---|
| working context | Context Pack and bounded views | disposable; rebuild from owners |
| operational facts | Runtime, Queue, Case, Observation, Evidence, Finding | canonical; restart-safe |
| target episodic memory | `tools/target_memory.py` | goals, hypotheses, leads/dead ends, next intent, handoff; advisory |
| cross-target experience | sanitized Knowledge candidates | evidence-linked and reviewed before promotion |
| semantic memory | Skills, Knowledge, Rules | governed, on-demand, bounded by registry |
| audit memory | journal/audit JSONL | append-only and rotated; not default context |

`hunt-memory/targets/<target>.json` is a compatibility/read projection. It cannot authorize validation, report readiness, coverage closure, or global completion. New features must not add duplicate finding, tested-endpoint, or lifecycle facts to it. Target-specific secrets, credentials, tokens, personal data, and customer data never enter cross-target or semantic memory. Retrospective output may propose a Knowledge candidate, Skill change, or Rule change, but only the existing review/lifecycle owners can promote it.

## Admission and Evolution

A new runner/lane is admitted only when the model cannot express the deterministic operation through an existing execution boundary, the behavior requires reproducibility/recovery/budget/evidence write-back, it is reusable across targets or routes, it has one owner and a focused regression, and it creates no competing finding/coverage/checkpoint truth.

Large modules are not split by line count. Extract one real boundary at a time only for duplicated owner logic, a stable pure policy with at least two consumers, or a proven CLI/persistence seam. A wave that finds no such boundary records a no-production-change result.

The optimization program is independently revertible: baseline cleanup, architecture/governance, memory authority, projection reconciliation, runtime-root/CI reproducibility, one-hotspot extraction, then ten-change adoption measurement. Each wave must leave the repository releasable.

### Projection reconciliation result

The initial Wave 3 audit found no production reverse writes: Surface, Context
Pack, Resume, and Report write only their own rebuildable artifacts; Checkpoint
and Autopilot coordinate durable owners through their public APIs. This is a
verified no-production-change result, not permission to add a generic
projection framework.

### Hotspot selection result

The first post-contract hotspot review found no pure policy with duplicated
consumers and no stable CLI/persistence seam that can be extracted without a
new compatibility boundary. Large modules remain unchanged until normal work
proves one of those conditions.

## Prohibited by This Contract

No database/service migration, physical directory rewrite, generic adapter framework, protocol-specific automatic chain, fixed model test sequence, payload catalogue in core Skills, or second lifecycle owner is introduced by architecture work alone.
