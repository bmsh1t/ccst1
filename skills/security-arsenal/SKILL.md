---
name: security-arsenal
description: Project-specific decision and evidence contract for selecting and recording security validation work. Use after a target signal exists; the model supplies general technique knowledge and chooses the concrete test input.
---

# SECURITY ARSENAL - AI-FIRST CONTRACT

This Skill is an integration contract, not a technique encyclopedia. General
security knowledge, syntax, tool usage, and protocol mechanics belong to the
model. This file records only project-specific selection, evidence, lifecycle,
and red-line rules.

## Trigger

Use after a target-owned signal identifies a surface, identity boundary,
parser, workflow, protocol, or possible impact connector. Do not load this
Skill as a generic checklist and do not create work from a class name alone.

## Decision Tree

Choose the next question from current evidence:

1. **Identity:** authenticated -> compare owned actors, roles, tenants, and
   object ownership first; anonymous -> establish the unauthenticated boundary
   and only then consider input or parser hypotheses.
2. **Surface:** browser, HTTP/API, file/import, proxy/cache, asynchronous job,
   or custom protocol. Use the medium that preserves the observed state.
3. **Technology:** use observed framework, serializer, query, template, cloud,
   or protocol signals to select a hypothesis. Do not infer a stack from a
   status code or generic error page.
4. **Function:** prioritize authentication, payment, account recovery, private
   object access, export, admin/configuration, and state-changing workflows.
5. **Boundary:** change one dimension at a time: actor, object, method, path,
   header, body shape, content type, encoding, state, cache key, origin, or
   transport framing.
6. **Learning:** select the action with the clearest expected observation and
   a decidable stop condition. The model may skip, combine, or invent a route
   when the evidence supports it.

## ROI Selection

Prefer the smallest action that can establish a meaningful boundary:

- authentication, recovery, session, and account-linking flows;
- payment, credit, quota, coupon, and other value/state transitions;
- private objects, exports, tenant boundaries, and admin/configuration paths;
- server-side fetch, upload/import, rendering, job, and integration edges;
- browser, API, GraphQL, realtime, RPC, and LLM tool boundaries when observed.

Do not spend the budget on broad class enumeration when a high-value workflow,
fresh structural signal, or actor/object comparison is available.

## Phase Switch

Continue when evidence changed, uncertainty fell, or a bounded connector became
testable. Rotate when the progress fingerprint repeats, the action budget is
exhausted, a prerequisite is permanently unavailable, or several bounded
actions produce no information. Record the reopen condition before leaving a
blocked lane. A scanner-negative result never closes an untested branch.

## Execution Boundary

- Establish a normal baseline and preserve the exact target, method, headers,
  body, session, and response context.
- Use the existing generic replay, browser, raw sender, diff, timing, or OOB
  boundary selected by the model; this Skill does not require a specialist
  runner for a protocol or bug class.
- Keep requests bounded, target-owned, and reversible. A changed status,
  reflection, timeout, or transport response is a signal until the relevant
  backend, content, identity, or state differential is shown.
- Let the model choose the concrete test input from its knowledge. Do not add
  local dictionaries, syntax tables, bypass catalogues, or fixed sequences here.

## Stateful Continuity

For dependent steps such as leak -> use, login -> token -> action, multi-round
oracles, browser workflows, or connection-bound protocols, keep all steps in
the same process, socket, or browser context. If a new process is required,
export and explicitly restore the complete session state. Never assume that
memory tokens, cookies, nonces, connection state, or oracle rounds survive a
new shell/tool invocation.

## Evidence Gate

A Lead or Candidate becomes validation-ready only with target-bound, locatable
evidence containing the operation identity, target identity, request/response
or browser/state transcript, and the observed differential. Status-only
responses, model narration, generic tool output, or a target-memory sentence
cannot establish a finding or a terminal coverage state.

Before promotion, preserve:

- baseline and changed observations;
- actor, object, session, and authorization context;
- the exact replay or browser/frame/state artifact;
- the impact connector and its bounded read-back;
- the stop result, cleanup result, and unresolved prerequisites.

## Canonical Write-Back

Use the existing owners only:

- Action Queue owns executable action lifecycle;
- Evidence Ledger owns evidence records;
- Finding Index owns finding identity and validation status;
- Target Case State owns actor/session/object continuity;
- Surface, Coverage, Checkpoint, and Context Pack are projections or planning
  views and must not create a second finding fact.

Run the existing validation and reporting gates before calling anything
validated or report-ready. Never edit a durable JSON file directly to promote a
finding.

## AI Autonomy and Red Lines

The model may select any technique, sequence, medium, or connector that current
evidence supports, including a route not named by this Skill. It must state
the hypothesis, expected learning, kill condition, and reason for any override.

Do not perform destructive writes, persistence, lateral movement, bulk data
access, real-user enumeration, high-volume credential attempts, or external
resource claims without an explicit current-turn boundary and the existing
red-line checks. Stop or downgrade when the next step would exceed that
boundary.

## Local Knowledge Policy

Generic technique references are intentionally not stored in this Skill. Read
only the matching project knowledge card when it adds a project-specific
trigger, evidence gate, stop condition, or owner/write-back rule. Otherwise use
the model's general knowledge and the existing generic execution boundary.
