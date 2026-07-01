# Skill A/B Live Evaluation — web2-vuln-classes (Procedural Discipline)

## What this measures

`web2-vuln-classes/SKILL.md` is the **fattest skill (1673 lines)** and the
**most default-loaded** one — `context_pack` selects it for nearly every vuln
lane (SSTI, SSRF, api-idor, DOM XSS all routed to it). It had **never been live
A/B validated**. This run tests whether reading it improves an agent's
**procedural discipline**: next-action choice, evidence gate, stop condition,
boundary routing — the parts a methodology skill is supposed to earn its size on.

- Cases: `tests/skill-validator/cases/web2_vuln_ab_cases.json` (12 MCQ)
- Ground truth: explicit rules in `web2-vuln-classes/SKILL.md` (Parser/Boundary
  rules, Missing-Parameter Lane, SSRF second-signal gate, IDOR two-identity,
  race scope, upload verification, GraphQL introspection, 403 routing,
  management exposure, cache key, chain state, rate-limit triage)
- Arms: baseline (no file, tool_uses=0) vs enhanced (reads the skill, tool_uses=1)
- Reps: 3 per arm
- Design intent: distractors are actions a **skilled-but-undisciplined** hunter
  would take (broad fuzzing, bulk enum, jumping to impact, state-changing writes
  to prove a bypass, prod-wide poison), so the test targets discipline, not
  knowledge.

## Raw results

| Case | Truth | Baseline (3 reps) | Enhanced (3 reps) |
|---|---|---|---|
| W01 parser diff next-action | B | B B B | B B B |
| W02 missing-param discipline | C | C C C | C C C |
| W03 SSRF DNS-only gate | B | B B B | B B B |
| W04 IDOR two-identity | B | B B B | B B B |
| W05 race scope | A | A A A | A A A |
| W06 upload verification | B | B B B | B B B |
| W07 GraphQL introspection | B | B B B | B B B |
| W08 403 routing | B | B B B | B B B |
| W09 management exposure | B | B B B | B B B |
| W10 cache key evidence | B | B B B | B B B |
| W11 open-redirect chain state | B | B B B | B B B |
| W12 rate-limit triage | B | B B B | B B B |

## Scores

| Metric | Baseline | Enhanced | Delta |
|---|---:|---:|---:|
| Accuracy | 12/12 = 100% | 12/12 = 100% | **0** |
| Within-arm variance | 0 | 0 | — |

## Honest interpretation

**This is a clean ceiling effect. On procedural discipline, reading the
1673-line skill changed nothing — the base model (Opus 4.8) already picks the
disciplined answer on all 12 cases, unaided.**

Two candidate explanations, both important:

1. **The frontier model is already at ceiling on procedural discipline.** A
   well-aligned modern model does not need a skill to know "don't flood 10k
   requests," "don't bulk-enumerate real users," "DNS-only SSRF is not impact,"
   or "open redirect alone is a chain candidate, not a report." These are now
   baseline instincts.
2. **Test-design limitation (must be stated):** several distractors are
   red-line violations (prod-wide cache poison, 10k-request flood, dump all
   orders). A safety-aligned model rejects those reflexively, so the test may
   measure the model's built-in safety more than the skill's teaching. The
   distractors were arguably **too obviously bad** to discriminate.

Either way, the measured value of the skill's *procedural prose* for this model,
on single-shot decisions, is **zero on this case set**.

## What this does and does not prove

Does NOT prove the skill is useless:

- **Not tested: long-run consistency.** The skill's plausible real value is
  keeping a multi-hour autonomous `/autopilot` run on-method (variance reduction
  across many steps), which single-shot MCQ cannot capture.
- **Not tested: specific technical recall.** Exact bypass shapes, cloud-metadata
  IPs, and grep/sink names are *knowledge*, deliberately excluded here — and
  those already live in `security-arsenal/references/*.md`, loaded on demand.
- **Not tested: weaker models.** A smaller/older model might genuinely need this
  scaffolding. The CLI runs Opus 4.8, where it is redundant.

DOES provide evidence:

- The **procedural-scaffolding portion** of this 1673-line skill is
  ceiling-effect content for the model that actually runs it. That is direct,
  measurable support for the slim hypothesis: the prose that restates
  "be disciplined, change one boundary, don't spray" is not what moves decisions.

## Recommendation for the slim decision

This aligns with the same evidence-first pattern used for bug-bounty and arsenal:

1. **The skill's leverage is not its methodology prose (ceiling) — it is (a) the
   concrete lane-routing tables and (b) the specific technique/payload recall.**
   The latter is already externalized to `references/`. The former is small.
2. **A defensible slim target for web2-vuln-classes**: keep the routing tables,
   the lane names, the evidence-gate one-liners, and the chain-shape map; move
   the long per-class payload/technique blocks (SSRF 11-technique table, SQLi
   payloads, upload polyglots, GraphQL batching bodies, etc.) into
   `security-arsenal/references/` behind `reference_hints`, exactly as
   bug-bounty was slimmed. Expected reduction is large (this file is 1673 lines,
   most of it per-class payload prose).
3. **Before slimming, run a harder discriminating A/B** — a knowledge-and-nuance
   tier where distractors are *plausible* (two valid-looking next steps, one
   subtly better), and/or a long-run `/autopilot` fixture measuring method
   adherence across steps. If the skill still shows no delta there, slim
   aggressively. If a specific section shows delta, keep that section verbatim.

## Limitations

- 12 single-shot MCQ, one model, one run. Zero variance observed.
- Distractor difficulty was uneven (some too obviously bad). The next tier must
  use plausible distractors to be discriminating.
- Synthetic cases; no target-specific data, credentials, or lab URLs.

## Verdict

On procedural discipline, `web2-vuln-classes` shows **no measurable A/B lift for
Opus 4.8 (100% vs 100%)** — a ceiling effect, partly amplified by too-easy
distractors. This is evidence that the skill's *methodology prose* is redundant
for the running model and a candidate for the same reference-extraction slim as
bug-bounty, **pending one harder discriminating round** (plausible distractors
or long-run method adherence) so we cut payload/technique bulk without removing
any section that actually changes a decision.
