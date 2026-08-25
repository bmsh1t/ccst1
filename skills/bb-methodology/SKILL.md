---
name: bb-methodology
description: Use at the start of a bug bounty session, when switching targets, or when progress stalls. Selects the next hypothesis, applies boundary-first reasoning, and decides when to continue, rotate, stop, or reopen a lane.
---

# Bug Bounty Methodology

This Skill answers one question: **what is the most informative hypothesis to test
next?** It is not a lifecycle, coverage, tool, or reporting owner.

## Canonical Boundaries

- Follow `skills/runtime-protocol.md` for target memory and session write-back.
- 按需加载 `rules/hunting.md`; its value-first coverage and
  `rules/hunting.md#high-intensity-hunting-posture` are canonical.
- Use `rules/coverage-gate.md` for coverage/completion.
- Use the Context Pack's selected cards and references. Do not load the full
  knowledge index merely to look for ideas.

高强度 hunt 采用高价值漏洞族覆盖模型，不固定偏向某几个漏洞类别。深度来自证据循环、
角色/对象差异、边界推理和复盘。

## PART 1: MINDSET

### Core Principle

Hunting means proving or killing an attack scenario, not accumulating scanner
matches. Start from the asset and trust boundary, then choose the smallest action
that can change the current belief.

### Phase 0: SESSION START

Before target work, state:

1. **Goal**: target feature or boundary and intended confidentiality, integrity,
   account, execution, or availability impact.
2. **Known facts**: target-owned observations, actors, workflows, source/JS,
   component intelligence, and current coverage gaps.
3. **Hypothesis**: open family/technique, expected learning, and evidence source.
4. **Kill condition**: the result that closes or rotates this path.
5. **Budget and risk**: bounded actions plus the current request budget.

A selected family is a current-session focus, not a persistent exclusion. On a
new target, temporary skips reset; the new target default keeps only the
built-in XSS lane skip unless the current turn or scanner-full path changes it.

## Hypothesis Selection

Choose the first route that has a concrete next evidence action:

1. Resume a running or interrupted owner-selected Action Queue item.
2. Validate a Candidate or high-value Signal with missing proof dimensions.
3. Close a high-impact coverage or actor/workflow gap.
4. Follow a fresh boundary anomaly from browser, JS/source, parser behavior,
   release/component intelligence, or a sibling endpoint.
5. When existing evidence is sparse, generate new evidence on the highest-value
   underexplored surface.

Rank alternatives by expected information gain, plausible impact, evidence
quality, target ownership, reversibility, and cost. Do not prioritize a favorite
bug class or let a scanner-negative result select completion.

## Reasoning Lenses

For the selected hypothesis, ask only the lenses that fit its evidence:

- **Actor/object**: anonymous, owner, peer, lower role, admin, or cross-tenant.
- **Input/parser**: path, parameter, header, body, content type, encoding,
  canonicalization, proxy/backend, serializer, storage, or rendering boundary.
- **Workflow/state**: skipped step, replay, stale token, order, timing, retry,
  cache, worker, or asynchronous consumer.
- **Version/sibling**: old API, mobile path, neighboring endpoint, alternate
  hostname, recent release, or independently implemented feature.
- **Connector**: what turns the primitive into data access, account impact,
  privileged state change, or controlled execution impact?

Developer inconsistencies are useful hypotheses, not proof. Preserve a normal
baseline and change one boundary at a time.

## Signal Routing

| Signal | Next route |
|---|---|
| Hidden SQLi surface after obvious parameters are quiet | `context-pack sqli`; load `knowledge/cards/sqli-hidden-surfaces.md` |
| Hidden login selector, legacy/mobile auth branch, role binder | `context-pack auth-hidden`; load `knowledge/cards/auth-hidden-switches.md` |
| Missing/null/type/schema/validator parameter response | `context-pack missing-param`; load `knowledge/cards/missing-parameter-discovery.md` |
| Target naming pattern or management/config/log surface | `context-pack path-pattern`; load `knowledge/cards/path-pattern-management-exposure.md` |
| Encoding, normalization, parser/proxy, WAF, or view/storage mismatch | Load `rules/playbook-router.md` and the selected boundary card |
| Role/object authorization difference | Route to `skills/web2-vuln-classes/SKILL.md` and actor-pair evidence |
| Blind server-side behavior | Use the shared OAST workflow only when a callback can answer the hypothesis |
| Payload, bypass, sink, or grep detail | Load the specific `skills/security-arsenal/references/` file on demand |

These are evidence routes, not a fixed checklist. Error, timing, OAST, Boolean,
browser, source, and role-diff observations are alternatives, not a
mandatory sequence. Select the one with the clearest expected learning and stop
condition.

Frame untested branches neutrally; do not claim a boundary is harmless or that
impact extends until evidence supports it. State competing branches explicitly
without choosing either as the premise. The next action must be sufficient to
produce its expected learning and make its kill condition decidable; otherwise
narrow or rewrite the action. Do not put an unobserved downstream consumer in a
kill condition: include one bounded consumer check, or stop at the primitive and
leave impact open.

## Evidence-Driven Rotation

After each bounded action compare the current **progress fingerprint** with the
previous one: hypothesis, surface, actor/state, observation kind, and evidence
reference.

- Continue when evidence changed, uncertainty fell, or a bounded connector is
  now testable.
- Stop the lane when its kill condition is met.
- Rotate after homogeneous no-information results, a repeated progress
  fingerprint, an exhausted lane/action budget, or a permanently unavailable
  prerequisite.
- Pivot immediately when a higher-value Candidate or a fresh structural signal
  appears.
- Record a reopen condition when later auth, source, browser, component, or
  workflow evidence could make the lane informative again.

Elapsed time alone is not a reason to continue or rotate. Do not replace owner
budgets and progress state with a model-side timer.

### Boundary Pivot Prompts

When progress stalls, ask:

```text
1. Boundary: browser, backend, auth flow, proxy/parser, worker, cache, or storage?
2. Baseline: what is one normal request/response for the workflow?
3. Hidden surface: what did JS/source/routes/headers/methods/content-types reveal?
4. Primitive: can I prove one role diff, marker, callback, file/config read, or token/session mismatch?
5. Connector: what turns it into data, account, authz, or controlled execution impact?
6. Stop: what observation kills this path, and what later evidence reopens it?
```

Use these prompts to generate target-specific hypotheses. Do not copy flag
paths or challenge assumptions from unrelated examples.

## Close The Decision Loop

Before leaving this Skill, produce one of:

- **continue**: hypothesis, next evidence action, expected learning, kill condition;
- **rotate**: reason, replacement hypothesis, preserved evidence reference;
- **stop**: kill evidence and any concrete reopen condition;
- **handoff**: narrower Skill/Card/tool route and the question it must answer.

Write unresolved work through its existing owner or Action Queue. Let
`rules/coverage-gate.md`, Evidence Ledger, Checkpoint, and reporting rules own
lifecycle and completion.
