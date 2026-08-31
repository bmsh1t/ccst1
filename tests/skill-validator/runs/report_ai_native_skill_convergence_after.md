# AI-native Skill Convergence After Report

Date: 2026-08-31

## Scope

This is the post-change report for the runtime protocol, Web2 Recon guidance,
and progress-rotation convergence. It measures context and decision contracts;
it does not claim live model accuracy when the staged Claude oracle is
unavailable.

## Revision, Case, And Runtime

| Field | Value |
|---|---|
| Git revision used by collector | `ef8ca231bb5179dd34cc2259c61106a2553f1042` |
| Working-tree patch SHA-256 (affected files) | `sha256:1f1b62d44983773681850ab15a0229a8d16c068b700d118d6d4859496ef59a18` |
| Case file | `tests/skill-validator/cases/ai_native_skill_convergence_ab.jsonl` |
| Case file SHA-256 | `sha256:1acc11d7d963fbc48fa5846882d1959fd4e0139cccd7008f4e58b1562666b759` |
| Claude CLI | `2.1.251 (Claude Code)` |
| staged HOME | `/tmp/ai-native-staged-home` |
| staged runtime | `/tmp/ai-native-staged-home/.claude` |
| install.sh SHA-256 | `sha256:675dcecb53baed623404cc6de38b25172024d6718b59ec2573459c7a24a7fa12` |
| staged settings SHA-256 | `sha256:9a79d41ee72f08d8bcd5239eb56a01e7320adc8f97b9b7988571848fb4984f1d` |
| runtime doctor | clean; critical_clean=true; drift_count=0 |

The authenticated live collector manifest is
`/tmp/ai-native-after-auth.manifest.json` and rows are
`/tmp/ai-native-after-auth.jsonl`. It used `skills_off` and `skills_on`, one
repetition, CLI-default model, user settings, auto permission mode, empty tool
override, `max_turns=20`, no model budget override, and a 600-second per-case
timeout. The authenticated before run used the same settings and configuration
hash with the old installed Skill files. The earlier isolated run without this
staged settings file is retained at `/tmp/ai-native-after-2.jsonl` and is not
used for model-quality scoring.

## Context Footprint

| Asset / field | Before | After | Delta |
|---|---:|---:|---:|
| `skills/runtime-protocol.md` lines / bytes | 278 / 12,267 | 155 / 7,845 | -123 / -4,422 |
| `skills/web2-recon/SKILL.md` lines / bytes | 768 / 33,424 | 218 / 11,506 | -550 / -21,918 |
| `skills/bb-methodology/SKILL.md` lines / bytes | 210 / 10,838 | 215 / 11,194 | +5 / +356 |
| `skills/triage-validation/SKILL.md` lines / bytes | 368 / 15,650 | 374 / 16,215 | +6 / +565 |
| Context Pack `must_read` entries for `TARGET`/`SAMPLE` | 3 | 3 | 0 |
| Context Pack selected Skill recommendation | 1 | 1 | 0 |
| Context Pack knowledge cards | 1 (budget <= 2) | 1 (budget <= 2) | 0 |
| Context Pack deferred cards | 0 | 0 | 0 |
| Context Pack required checks | 1 | 1 | 0 |

The selected Skill and card remain advisory and outside `must_read`; the
reduction is therefore resident-context reduction rather than removal of the
on-demand route.

## Deterministic Control Group

Command: `python3 tests/skill-validator/web2_vuln_ab_eval.py --report ...`

| Cases | Before baseline | Before enhanced | After baseline | After enhanced | Enhanced delta |
|---:|---:|---:|---:|---:|---:|
| 10 | 42/53 | 53/53 | 42/53 | 53/53 | 0 |

The control group for `web2-vuln-classes` retained all 53 enhanced signals and
all route/card checks. This is a deterministic non-regression result, not a
live Recon or phase-rotation quality measure.

## Direct Live Decision Comparison

The authenticated before and after runs each used the same eight fixed cases in
both arms. The before run had 16/16 valid rows; the after run had 15/16 valid
rows because `A08_residual_inventory/skills_off` exited non-zero. Strict
scoring therefore used the seven complete pairs for the within-run resource
delta and per-case comparison.

| Arm | Before | After | Valid cases | Notes |
|---|---:|---:|---:|---|
| `skills_off` | 8/8 (100%) | 6/7 (85.7%) | 7 | after A04 was a false negative; A08 was unknown |
| `skills_on` | 6/8 (75%) | 7/8 (87.5%) | 8 | A05/A08 changed to correct; A04 became a false negative |

Across the eight `skills_on` cases, two cases improved (`A05`, `A08`), one
regressed (`A04`), and five were unchanged. The one-repetition live sample is
stochastic and the `skills_off` control also drifted, so this is diagnostic
evidence only, not a statistically reliable model-quality lift. Paired
`skills_on` accuracy moved from 6/8 to 7/8; TPR moved from 1.0 to 0.75 and FPR
from 0.5 to 0.0.

The earlier pre-change and post-change runs without staged settings returned
`unknown` for all 16 rows because Claude reported `Not logged in · Please run
/login`; those rows remain an isolation diagnostic and are excluded from the
authenticated comparison.

The valid claims are the context footprint reduction, preserved deterministic
routing, clean staged runtime provenance, and the limited per-case observations
above. A higher-repetition live evaluation is still required before claiming a
general model decision improvement.

## Checks

- Runtime/Recon/phase focused checks before this final gate: 217 passed.
- Recon/phase documentation checks: 25 passed.
- Capability governance: PASS.
- Knowledge audit: PASS.
- Deterministic Web2 A/B: 42/53 baseline, 53/53 enhanced, unchanged after.
- Staged runtime doctor after sync: PASS (39 commands, 11 agents, 20 skills; drift=0).
- Authenticated live A/B: 15/16 valid after rows; `skills_on` 7/8 correct;
  strict runner exit `2` only because one control row was non-zero.
- Full repository suite: 3652 passed.

The full repository suite remains the final required gate; any environment or
pre-existing dependency failure is recorded separately rather than converted
into a product regression.

## Residual Scope And Rollback

WebSocket, gRPC, and LLM/RAG protocol-specific execution chains remain
deliberately deferred. The model can select existing tools under the shared
contract, but this task adds no protocol runner, new state owner, scanner
breadth, or evidence schema. Each documentation phase can be rolled back by
reverting its corresponding file changes; no runtime-state migration is
needed.
