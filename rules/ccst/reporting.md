# Reporting Rules

This file owns cross-cutting evidence, delivery and publication checks.
The complete 6k `rules/vuln-report-format.md` owns default SRC severity, reportability,
prose, language, chapters and layout; read it with its runtime adapter.
Explicit destination alternatives follow the report-writing module without changing evidence or verdicts.
`skills/src-hunter/modules/triage-validation.md` owns validation verdicts;
`skills/src-hunter/modules/report-writing.md` binds authored bytes to existing owners.
Do not maintain another default format, title formula or word budget here.

---

## 1. RUN 7-QUESTION GATE BEFORE WRITING

Apply Q1-Q7 and the four gates in `skills/src-hunter/modules/triage-validation.md` before
reporting. That module owns REPORT, CHAIN_REQUIRED, DOWNGRADE, and DO_NOT_REPORT
precedence; this file does not redefine the verdict.

## 2. ALWAYS INCLUDE PROOF OF CONCEPT

The PoC must prove real impact, but it should use the lowest-risk evidence that
answers the triager's question. Do not hard-ban stronger proof: when minimal
proof is not enough to establish impact, escalate deliberately and document why.

Use the proof choices in `skills/src-hunter/modules/triage-validation.md` Q6.
For Secret / CI/CD / cloud evidence, prove ownership and usable permissions with
the least sensitive action; stronger proof requires necessity and the controls
in `rules/ccst/red-lines.md`.

Escalated proof requirements:

1. Explain why lower-risk proof is insufficient.
2. Keep scope to test accounts, test resources, non-sensitive metadata, or the
   smallest necessary data sample.
3. Preserve exact request/response or workflow evidence.
4. Record cleanup or rollback steps when state changes are involved.

An unproven impact remains an evidence gap; report drafting cannot promote it.
Avoid unnecessarily invasive proof.

## 3. CVSS IS OPTIONAL EXTERNAL DELIVERY METADATA

CVSS does not gate discovery, validation, evidence, Finding, Queue, or local
report generation. When a destination platform requires it, preserve any
recorded `cvss.version`, `cvss.score`, and `cvss.vector` unchanged. Legacy CVSS
records remain readable, but prose, templates, and model estimates must not
recalculate or overwrite a stored result. If none was recorded, supply only
the destination's required report field under its current rules, without writing
canonical validation state.

When the destination requires CVSS, use observed preconditions and demonstrated
impact to select metrics; do not infer severity from a bug-class name or scanner label.

## 4. SEPARATE EVIDENCE GAPS FROM DESTINATION EXCLUSIONS

Use the evidence pitfalls and Q7 destination checks in
`skills/src-hunter/modules/triage-validation.md`. A policy rejection cannot refute technical
evidence; an unsupported impact cannot become valid because a destination pays.

## 5. VERIFY DATA ISN'T EXPECTED PUBLIC

Before submitting an information disclosure finding, check whether the data is
genuinely intended to be public — public reachability is not the same as
expected exposure:

1. Open the target in an incognito browser (not logged in)
2. Can you see the same data without authentication?
3. If yes, do NOT stop there: check business expectation — object ownership,
   role design, whether the same data is shown in any authenticated UI, docs,
   or API contract. Data that should be private (other users' records,
   internal config, tokens) reachable anonymously is a finding even though it
   "is visible without login".
4. Only conclude not-a-bug when the data is intended to be public by design.

## 6. TWO TEST ACCOUNTS FOR IDOR

A cross-identity claim needs independently attributable actor and victim-object evidence.
Two controlled accounts provide the clearest comparison when available; a second account
is not a universal execution prerequisite. Preserve any missing ownership/baseline evidence
as uncertainty, never call access to one's own public object IDOR.

For an identity-boundary claim, report must show the smallest reproducible
actor/object differential, for example: Account A's session reached Account B's
private object. Use an equivalent artifact when the boundary is not HTTP.
