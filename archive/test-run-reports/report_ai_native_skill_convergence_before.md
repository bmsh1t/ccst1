# AI-native Skill Convergence Before Baseline

Date: 2026-08-31

## Scope

This is the pre-change baseline for the runtime protocol, Web2 Recon guidance,
and progress-rotation convergence. It measures context and decision contracts;
it does not claim that a deterministic signal score is live model accuracy.

## Revision And Runtime

| Field | Value |
|---|---|
| Git revision | `ef8ca231bb5179dd34cc2259c61106a2553f1042` |
| Case file SHA-256 | `sha256:1acc11d7d963fbc48fa5846882d1959fd4e0139cccd7008f4e58b1562666b759` |
| Claude CLI | `2.1.251 (Claude Code)` |
| staged HOME | `/tmp/ai-native-staged-home` |
| staged runtime doctor | clean; critical_clean=true; drift_count=0 |
| install.sh SHA-256 | `sha256:675dcecb53baed623404cc6de38b25172024d6718b59ec2573459c7a24a7fa12` |
| staged settings SHA-256 (authenticated rerun) | `sha256:9a79d41ee72f08d8bcd5239eb56a01e7320adc8f97b9b7988571848fb4984f1d` |

## Context Footprint

| Asset / field | Before |
|---|---:|
| `skills/runtime-protocol.md` lines / bytes | 278 / 12,267 |
| `skills/web2-recon/SKILL.md` lines / bytes | 768 / 33,424 |
| `skills/bb-methodology/SKILL.md` lines / bytes | 210 / 10,838 |
| `skills/triage-validation/SKILL.md` lines / bytes | 368 / 15,650 |
| Context Pack `must_read` entries for `TARGET`/`SAMPLE` | 3 |
| Context Pack selected Skill recommendation | 1 |
| Context Pack knowledge cards | 1 (budget <= 2) |
| Context Pack deferred cards | 0 |
| Context Pack required checks | 1 |

The selected Skill and card are advisory and were not included in `must_read`.

## Deterministic Control Group

Command: `python3 tests/skill-validator/web2_vuln_ab_eval.py --report ...`

| Cases | Baseline | Enhanced | Delta |
|---:|---:|---:|---:|
| 10 | 42/53 | 53/53 | +11 |

This is the non-regression control for the on-demand `web2-vuln-classes` Skill;
it is not a Recon or phase-rotation quality measure.

## Direct Live Decision Baseline

Case file: `tests/skill-validator/cases/ai_native_skill_convergence_ab.jsonl`

The collector ran 8 cases, both `skills_off` and `skills_on`, one repetition,
with identical tools/settings and staged runtime. All 16 rows returned
`unknown` because the staged Claude runtime reported `Not logged in · Please
run /login`. Strict scoring therefore produced 0 valid rows and did not infer
accuracy, TPR, FPR, or behavior metrics. The rows and manifest are retained in
`/tmp/ai-native-before-2.jsonl` and `/tmp/ai-native-before-2.manifest.json`.

## Checks

- Existing routing, boundary, Context Pack, hunting-posture, and live-artifact
  regression tests: 161 passed.
- Fixed decision-case integrity test: 1 passed.
- Capability governance: PASS (12/12 catalog, 63 capabilities, 57/57 cards).
- Knowledge audit: PASS (63 capabilities, 61 documents, no errors/warnings).
- Staged runtime doctor: PASS (commands, agents, and skills drift=0).

The live login requirement is an evaluation blocker. Until a valid staged
before/after pair exists, later results may claim structural/context reduction
and deterministic compatibility only, not improved model decision quality.

### Authenticated rerun

At the operator's request, the same `/root/.claude/settings.json` configuration
was copied into an isolated staged HOME (SHA-256 shown above; the file is not
tracked). The old guidance runtime was reconstructed from `HEAD` for the
installed files, and the same eight cases were run with the same settings.

The authenticated before rows are retained in `/tmp/ai-native-before-auth.jsonl`
with manifest `/tmp/ai-native-before-auth.manifest.json`. All 16 rows were
valid. `skills_off` scored 8/8; `skills_on` scored 6/8, with false positives on
`A05_repeated_progress` and `A08_residual_inventory`. An independent doctor
check against the reconstructed `HEAD` source tree reported
`commands=39`, `agents=11`, `skills=20`, `drift=0`.
