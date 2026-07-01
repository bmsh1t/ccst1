# Skill A/B Live Evaluation — web2-vuln-classes Round 2 (Plausible Distractors)

## Why this round

Round 1 (`report_web2_vuln_ab_live.md`) hit 100% vs 100% — a ceiling effect,
but partly because distractors were red-line violations any aligned model
rejects reflexively. This round removes that confound: every case offers a
**plausible, defensible alternative** that a strong hunter without this skill
would reasonably pick. The "correct" answer depends on the skill's SPECIFIC
text (ordering, routing, evidence-gate wording), not generic good judgment.

- Cases: `tests/skill-validator/cases/web2_vuln_ab_hard_cases.json` (12 MCQ)
- Arms: baseline (no file, tool_uses=0) vs enhanced (reads the 1673-line skill, tool_uses=1)
- Reps: 3 per arm
- Trap examples: H01 rotate-to-avoid-spiral (normally good discipline), H02
  use a second identity (normally correct auth testing), H03 probe a confirmed
  callback, H11 test the highest-impact payment race first.

## Raw results

Ground truth: H01=B, H02=A, H03=B, H04=A, H05=A, H06=A, H07=A, H08=A, H09=A,
H10=A, H11=A, H12=A.

| Case | Truth | Baseline (3 reps) | Enhanced (3 reps) |
|---|---|---|---|
| H01 SQLi hidden-surface (don't stop at visible) | B | B B B | B B B |
| H02 GraphQL sibling-field-first | A | A A A | A A A |
| H03 blind SSRF unmapped callback | B | B B B | B B B |
| H04 OAuth missing-PKCE probe | A | A A A | A A A |
| H05 object-auth same-path-different-verb | A | A A A | A A A |
| H06 second-order store+trigger evidence | A | A A A | A A A |
| H07 one-assumption-at-a-time raw replay | A | A A A | A A A |
| H08 least-noisy boolean confirmation | A | A A A | A A A |
| H09 own-mailbox email-linking boundary | A | A A A | A A A |
| H10 WAF/backend mismatch, baseline first | A | A A A | A A A |
| H11 non-payment race target first | A | A A A | A A A |
| H12 GraphQL node() bypasses REST object-auth | A | A A A | A A A |

## Scores

| Metric | Baseline | Enhanced | Delta |
|---|---:|---:|---:|
| Accuracy | 12/12 = 100% | 12/12 = 100% | **0** |
| Within-arm variance | 0 | 0 | — |

## Interpretation — the ceiling is real, now replicated

With genuinely plausible distractors, the unaided model still picked the
skill-aligned answer on all 12, including the subtle-ordering cases (H02
sibling-field-first, H08 boolean-before-time, H12 node()-bypasses-REST) that
were designed to separate "read the skill" from "generically competent."

This replicates Round 1 on a harder, better-designed case set. Two rounds, 24
distinct cases, 6 reps each arm: **zero measurable A/B lift for Opus 4.8 on
web2-vuln-classes procedural decisions, zero variance.**

The honest reading: the procedural + methodological knowledge in this skill —
what to test next, in what order, with what evidence gate, when to stop — is
**already internalized by the frontier model that runs the CLI.** The skill is
restating things the model reliably does unaided.

## What the skill's real (untested-here) value could still be

1. **Exact technical recall**, not decisions: precise SSRF bypass strings, the
   11 open-redirect techniques, cloud-metadata IPs per provider, DBMS error
   fingerprints. This is knowledge, already externalized to
   `security-arsenal/references/*.md` — and it is where a methodology file
   genuinely can't be replaced by model priors.
2. **Long-run consistency** across a multi-hour `/autopilot` session (method
   adherence over 100+ steps), which single-shot MCQ cannot measure.
3. **Weaker/older models** that lack these priors. The CLI runs Opus 4.8.

None of these justify keeping 1673 lines of *methodology prose* in a
default-loaded skill.

## Slim decision for web2-vuln-classes: PROCEED, same pattern as bug-bounty

Evidence across two rounds supports the same reference-extraction slim already
proven on bug-bounty and validated for arsenal:

**Keep in SKILL.md (decision layer — small):**
- Lane list + routing tables (Parser/Boundary Differential Signals, Object-Level
  Auth Matrix, Transport/Parser Diff)
- The lane-flow one-liners and evidence-gate/stop-condition sentences (e.g.
  "DNS-only = informational; need second signal", "second-order: record store +
  trigger step", "boolean before time/OOB")
- Chain Shapes map and the knowledge-card pointers (sqli-hidden-surfaces,
  auth-hidden-switches, missing-parameter-discovery)

**Move to `security-arsenal/references/*.md` (loaded via reference_hints):**
- Per-class payload bodies and technique tables: SSRF 11-technique IP-bypass
  table, SQLi payload/type/confirmation blocks, OAuth 11 open-redirect
  techniques, GraphQL batching/query bodies, upload polyglots/SVG XSS, SSTI
  bodies. These are exactly the ceiling-effect-irrelevant-but-recall-useful
  bulk that belongs behind on-demand hints.

**Expected outcome:** 1673 → target ~500-650 lines (routing + gates + chain
map), with payload/technique bulk behind `reference_hints`, mirroring the
bug-bounty result. Net effect: the most default-loaded skill stops spending
~1000 lines of context on prose the model already knows, while every concrete
payload stays retrievable on evidence.

**Guardrails (unchanged from prior slims):**
- No section that changes a decision may be deleted — only relocated. The 12
  Round-2 cases become a regression: after slimming, re-run the A/B; enhanced
  must still be 12/12 (proves no routing/gate/ordering was lost).
- No target-specific data, lab URLs, or credentials introduced.
- Run `quick_validate.py`, `test_context_pack.py`, `test_skill_boundaries.py`
  after the move.

## Limitations

- Two single-shot MCQ rounds, one model. Long-run method adherence not measured.
- A frontier model's zero-delta does not generalize to weaker models.
- Cases synthetic; leak-scanned clean.

## Verdict

Replicated ceiling effect (100% vs 100%, 24 cases, plausible distractors). The
methodology prose in web2-vuln-classes adds no measurable decision value for
Opus 4.8. Proceed with the bug-bounty-style reference-extraction slim: relocate
payload/technique bulk to `references/`, keep routing/gates/chain map, and gate
the change on the 24 A/B cases + boundary tests staying green. This is the
highest-value remaining optimization identified, and it is now evidence-backed
rather than assumed.
