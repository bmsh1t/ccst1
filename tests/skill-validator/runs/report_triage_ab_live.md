# Skill A/B Live Evaluation — Triage Verdict + Severity

## What this measures

Does an agent that **reads `skills/triage-validation/SKILL.md` first** produce
more accurate bug-bounty triage decisions than a security-competent agent that
answers from its own knowledge with **no skill file**?

Unlike `tests/test_skill_ab_evaluation.py` (a deterministic context-pack routing
check), this is a **live LLM A/B**: real subagents answered the same 14 cases in
two arms.

- Case set: `tests/skill-validator/cases/triage_ab_cases.json` (14 cases)
- Ground truth: NEVER SUBMIT list + CONDITIONALLY VALID chain table + Q7
  precedence + CVSS 3.1 quick reference in `skills/triage-validation/SKILL.md`
- Arms: **baseline** (no file access, tool_uses=0) vs **enhanced** (reads the
  skill, tool_uses=1)
- Reps: 3 per arm (variance estimate)
- Scoring: verdict exact match + severity exact match, 2 points per case

## Case design (anti-ceiling)

Cases were chosen so that the answer depends on the skill's precedence rules,
not on generic knowledge. Six cases are "obvious" (T02, T04, T06, T09, T12,
T14). Eight target the exact places practitioners disagree:

- Standalone vs chained same primitive: T01 (open redirect alone) vs T02
  (proven OAuth chain) vs T03 (chain-eligible, unbuilt).
- CORS without creds (T07) vs CORS with credentialed exfil (T08).
- SSRF DNS-only (T05) vs SSRF metadata read-back (T06).
- Severity calibration: T10 (IDOR read = Medium) vs T11 (IDOR write/delete =
  High), where "it sounds bad" over-rating is the common error.

## Raw results

Ground truth then each arm (all three reps were identical within each arm this
run, so one column each):

| Case | Truth verdict | Truth sev | Baseline verdict | Baseline sev | Enhanced verdict | Enhanced sev |
|---|---|---|---|---|---|---|
| T01 | DO_NOT_REPORT | None | DO_NOT_REPORT | None | DO_NOT_REPORT | None |
| T02 | REPORT | Critical | REPORT | Critical | REPORT | Critical |
| T03 | CHAIN_REQUIRED | None | CHAIN_REQUIRED | None | CHAIN_REQUIRED | None |
| T04 | DO_NOT_REPORT | None | DO_NOT_REPORT | None | DO_NOT_REPORT | None |
| T05 | DO_NOT_REPORT | None | **CHAIN_REQUIRED** | None | DO_NOT_REPORT | None |
| T06 | REPORT | Critical | REPORT | Critical | REPORT | Critical |
| T07 | DO_NOT_REPORT | None | DO_NOT_REPORT | None | DO_NOT_REPORT | None |
| T08 | REPORT | High | REPORT | High | REPORT | High |
| T09 | DO_NOT_REPORT | None | DO_NOT_REPORT | None | DO_NOT_REPORT | None |
| T10 | REPORT | Medium | REPORT | **High** | REPORT | Medium |
| T11 | REPORT | High | REPORT | **Critical** | REPORT | High |
| T12 | REPORT | Critical | REPORT | Critical | REPORT | Critical |
| T13 | REPORT | High | REPORT | High | REPORT | High |
| T14 | DO_NOT_REPORT | None | DO_NOT_REPORT | None | DO_NOT_REPORT | None |

Bold = deviation from ground truth.

## Scores

| Metric | Baseline | Enhanced | Delta |
|---|---:|---:|---:|
| Verdict accuracy | 13/14 = 92.9% | 14/14 = 100% | +7.1 pts |
| Severity accuracy | 12/14 = 85.7% | 14/14 = 100% | +14.3 pts |
| Fully-correct cases (both) | 11/14 = 78.6% | 14/14 = 100% | +21.4 pts |

Within-arm variance this run: **0** for both arms (3/3 reps identical each).

## Where the skill actually helped

Only 3 of 14 cases separated the arms. The other 11 showed a **ceiling effect** —
the base model already knows them, so the skill adds no value there. The real
gains:

1. **T10 severity (IDOR read PII): baseline High → correct Medium.** Without the
   CVSS reference table the model over-rates "read any user's PII" to High. The
   skill's `IDOR read PII, auth required = 6.5 Medium` row corrects it.
2. **T11 severity (IDOR delete): baseline Critical → correct High.** Same
   over-rating pattern; skill's `IDOR write/delete = 7.5 High` row corrects it.
3. **T05 verdict (SSRF DNS-only): baseline CHAIN_REQUIRED → correct
   DO_NOT_REPORT.** This is the most debatable case. Baseline reasoned "SSRF is
   always chain-eligible." The skill's Q7 precedence (`no concrete next hop →
   DO NOT REPORT`) plus the explicit NEVER SUBMIT entry `SSRF DNS callback only`
   pushed the enhanced arm to the stricter, correct call. A reasonable human
   triager could argue either way here; count this as a soft win.

## Honest limitations

- **Single run, zero observed variance.** Earlier work
  (`report_fix_and_variance.md`) saw baseline verdict instability across reps;
  this run did not reproduce that — all reps were identical in both arms. So the
  headline value **this run** is accuracy (mainly severity calibration), not
  variance reduction. Do not over-generalize either way from one 3-rep run.
- **The clearest, least-debatable win is severity calibration.** The base model
  systematically over-rates severity by one tier when the class "sounds bad";
  the CVSS quick-reference table is what fixes this. This matches the article's
  thesis: a skill's value is highest where the base model is *confidently wrong*,
  not where it lacks knowledge.
- **Small N (14 cases, 1 skill).** This validates `triage-validation`, not the
  whole plugin. Routing/coverage skills are already covered by the deterministic
  suite (`test_skill_ab_evaluation.py`, 2 passed; `test_context_pack.py`, 68
  passed).
- Cases are synthetic and contain no target-specific data, credentials, or lab
  URLs.

## Verdict

For triage decisions, reading `triage-validation/SKILL.md` moved the agent from
78.6% → 100% fully-correct on a deliberately hard, anti-ceiling case set. The
gain is concentrated and explainable: **severity calibration via the CVSS
reference table** (T10, T11) and **strict Q7 no-next-hop routing** (T05). On the
11 ceiling-effect cases the skill neither helped nor hurt. This is real,
measurable improvement, honestly bounded to where it occurs.
