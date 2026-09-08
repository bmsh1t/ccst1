# Skill and Knowledge Architecture Baseline

Date: 2026-08-26

## Scope

This is the Phase 1 capability and complexity snapshot for the current
Claude Code CLI route. It records existing measurements before any further
architecture phase changes. It does not change runtime behavior, target
state, the installed runtime, or the Skill/card inventory.

The root `SKILL.md` is reported separately as a legacy direct-install
compatibility entry. It is not counted as the modular Context Pack route.

## Complexity Snapshot

| Asset | Lines |
|---|---:|
| Root legacy `SKILL.md` | 1,293 |
| All modular `skills/*/SKILL.md` files | 4,878 |
| Root plus all modular Skills | 6,171 |
| `CLAUDE.md` resident contract | 127 |
| `skills/runtime-protocol.md` shared contract | 278 |
| `rules/context-loading.md` loading contract | 139 |

The working tree already contained one unrelated, uncommitted duplicate-line
deletion in `CLAUDE.md` before this report was added (`wc -l` is 127 in the
working tree and 128 at `HEAD`). The snapshot records the working-tree value;
the deletion is not part of this phase.

Modular Skill inventory at this snapshot:

| Skill | Lines |
|---|---:|
| `bb-methodology` | 153 |
| `bug-bounty` | 145 |
| `cicd-security` | 387 |
| `credential-attack` | 128 |
| `meme-coin-audit` | 294 |
| `mobile-pentest` | 329 |
| `report-writing` | 512 |
| `security-arsenal` | 856 |
| `triage-validation` | 368 |
| `web2-recon` | 768 |
| `web2-vuln-classes` | 388 |
| `web3-audit` | 550 |

## Capability Snapshot

The existing read-only governance command reports:

```text
catalog=12 disk=12 primary=6
capabilities=63 documents=61 errors=0 warnings=0
value-review cards=57/57
lifecycle events=105 active=57 errors=0
```

The catalog route-mode split is `primary=6`, `direct-only=4`,
`reference-only=1`, and `report-only=1`. Trigger collisions remain advisory
and do not change route selection.

## Default-Load Probe

For the synthetic probe `target=TARGET focus=SAMPLE`, the existing Context Pack
returned three `must_read` entries, one primary Skill recommendation, and one
knowledge-card recommendation. The selected Skill and card were not copied
into `must_read`; no full Skill/card tree was loaded. `CLAUDE.md` remains the
resident platform contract outside the Context Pack.

## Acceptance Artifacts

Run these existing project-native checks from the repository root:

```bash
python3 tools/capability_governance.py --strict
python3 tools/knowledge_audit.py --strict
python3 tests/skill-validator/web2_vuln_ab_eval.py \
  --report /tmp/skill-knowledge-baseline-ab.md
python3 -m pytest -q \
  tests/test_skill_ab_evaluation.py \
  tests/test_skill_boundaries.py \
  tests/test_context_pack_docs.py
```

The snapshot results are:

| Check | Result |
|---|---|
| Capability governance | PASS; 12/12 catalog, 6 primary, 63 capabilities, 61 documents, 57/57 value review |
| Knowledge audit | PASS; 63 capabilities, 61 documents, 0 errors, 0 warnings |
| Deterministic Web2 A/B | 10 cases; baseline 42/53, enhanced 53/53, delta +11 |
| A/B, Skill-boundary, and Context Pack docs regression | 22 passed |
| `git diff --check` | PASS; no whitespace errors |

The deterministic A/B is a loaded-context signal check, not a live model
accuracy claim. Its acceptance guard is: enhanced signal coverage remains
complete, route/card gaps remain empty, and the recorded line count is
recomputed whenever the Skill changes. Existing focused tests remain the
behavior guard; no duplicate baseline test is needed.

## Phase Boundary And Rollback

This phase changes documentation only. Reverting this report restores the prior
tree without touching product behavior, state owners, or installed files. No
install parity check is required for this
snapshot because no installed Skill, command, or mapping changed. Any later
phase that changes those assets must use a staged `HOME` and
`XDG_CONFIG_HOME`, then compare the staged tree with `runtime_doctor`.
