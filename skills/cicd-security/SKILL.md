---
name: cicd-security
description: Decision skill for explicitly scoped CI/CD and supply-chain trust-boundary reviews. Selects the next evidence-producing branch; deterministic tools and knowledge cards provide execution detail.
---

# CI/CD Security Decision Skill

This is a commander, not a scanner manual. Choose the next branch from the
observed repository, trigger, permission, runner, artifact, and deployment
context. Keep concrete probe shapes and tool syntax in the model or on-demand
knowledge references.

## Direct Execution Contract

- Entry: Use only when a public repository, workflow, package, artifact, or
  deployment path is explicitly in scope. Require the repository/workflow
  identity, permitted scope, and a bounded read-only or test-branch boundary.
- Evidence: A candidate needs the exact revision and workflow path, trigger and
  untrusted input, permission/secret context, data-flow edge, and a reproducible
  execution or static trace to target impact. Scanner output is a lead only.
- Stop: Stop on scope, revision, or ownership mismatch; on a missing impact
  connector; or when the declared repository and execution budget is exhausted.
  Hand reproducible candidates to `triage-validation`.

## Decision Tree

- No explicit CI/CD asset -> return to `web2-recon` for discovery; do not infer
  a pipeline from branding or a package name.
- Untrusted trigger or editable input is present -> compare the trigger's
  privilege, checkout/ref, expression context, and downstream runner boundary.
- A self-hosted runner, cache, or artifact crosses trust levels -> follow the
  workspace, persistence, and consumer edge before considering execution impact.
- Secrets or OIDC permissions are reachable -> verify subject/audience, branch,
  environment, and release/deploy consumers; a permission flag alone is a lead.
- Internal package or image identity is visible -> route to the dependency-
  confusion branch only when the target build actually depends on the package,
  the resolver/config can fall back to the public registry, and public
  namespace state can be independently established.
- A candidate has a concrete server, cloud, release, or package impact -> hand
  the evidence to validation; otherwise keep it as a lead or informational note.

## ROI Priorities

1. Privileged triggers that accept contributor-controlled input.
2. Self-hosted runners, shared caches, artifacts, and release/deploy jobs.
3. OIDC or secret paths whose trust policy is broader than the workflow scope.
4. Package, image, or action resolution with a proven private-to-public edge.
5. Low-impact lint, pinning, or disclosure signals only after the high-value
   trust edges are exhausted.

## Phase Checkpoints

- Before a branch: record the revision, owner, trigger, privilege, and expected
  target-side effect.
- After each bounded trace: if no new trust edge or impact evidence appears,
  switch to the next ROI branch or stop; do not expand into broad repository
  spraying.
- Before handoff: preserve the smallest reproducible diff or static trace,
  cleanup state, and the unresolved evidence question.

## Evidence Gate and Handoff

The minimum proof is `untrusted input -> workflow context -> runner/credential
or artifact -> target-controlled impact`, with independent evidence for each
edge. A workflow file, `id-token` permission, package 404, masked log value, or
runner command alone does not pass. Use `cicd-trust-boundaries` for cross-layer
signals and route confirmed impact to `triage-validation`.

## Red Lines

Do not execute unknown workflows, read real secrets, publish packages/images,
alter production deployment, or reuse credentials outside the declared test
boundary. The model chooses the hypothesis; existing deterministic tools only
collect bounded evidence and write their normal artifacts.
