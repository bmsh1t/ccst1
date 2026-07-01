# Web2 Vuln Classes Slim Validation

## Summary

`skills/web2-vuln-classes/SKILL.md` was slimmed from a default-loaded encyclopedic bug-class reference into a compact decision layer.

| Metric | Before | After | Change |
|---|---:|---:|---:|
| `web2-vuln-classes/SKILL.md` lines | 1673 | 380 | -1293 (-77.3%) |
| `security-arsenal/references/*.md` total lines | 353 | 491 | +138 |
| Deterministic A/B baseline | 38/53 | 42/53 | +4 |
| Deterministic A/B enhanced | 50/53 | 53/53 | +3 |
| Route/card gap cases | W03, W05 | none | fixed |

## What Changed

Kept in `SKILL.md`:

- Runtime contract and four-layer memory hooks.
- CTF-Web inspired boundary router.
- API object/auth matrix.
- Access-control, missing-parameter, management-exposure, SQLi, and hidden-auth lanes required by boundary tests.
- Compact lane cards with trigger, first safe action, evidence gate, stop condition, chain path, and reference pointer.
- Global stop conditions for high-impact or irreversible actions.

Moved or consolidated into on-demand references:

- SSRF, redirect, upload, path traversal, host/proxy, and WAF/router bypass shapes -> `bypass-patterns.md`.
- SQLi, GraphQL, SSTI, command injection, XXE, SAML/XML, deserialization, CRLF, and smuggling probe families -> `payload-families.md`.
- DOM/source sinks and server-side RCE/deserialization sink leads -> `sink-and-grep-patterns.md`.
- Recon tooling, cloud/storage checks, subdomain takeover fingerprints, and SAML tooling notes -> `recon-tool-usage.md`.

## W03 / W05 Gap Handling

- W03 `upload_execution`: fixed by treating upload + execution/RCE wording as upload-to-execution instead of parser-only. Current route: `upload-to-execution + controlled-rce-impact`.
- W05 `sql_nosql_hidden_surface`: fixed focus parsing so spaced `SQL injection` and `hidden parameter` route to `sqli-hidden-surfaces` alongside `nosql-query-injection`.

Current deterministic report:

```text
Cases: 10
web2-vuln-classes lines: 380
Baseline score: 42/53
Enhanced score: 53/53
Delta: +11
Cases still missing enhanced signals: none
Route/card gap cases: none
```

## Validation Commands

```bash
python3 /root/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/web2-vuln-classes
python3 /root/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/security-arsenal
python3 tests/skill-validator/web2_vuln_ab_eval.py --report tests/skill-validator/runs/report_web2_vuln_classes_ab.md
python3 -m pytest tests/test_skill_boundaries.py tests/test_context_pack.py tests/test_skill_ab_evaluation.py tests/test_web2_vuln_ab_evaluation.py tests/test_autopilot_cadence.py -v
```

Results:

```text
Skill is valid!
Skill is valid!
93 passed
```

## Live A/B Guardrail

Existing Claude CLI live A/B guardrails were preserved as test artifacts:

```text
tests/skill-validator/cases/web2_vuln_ab_cases.json
tests/skill-validator/cases/web2_vuln_ab_hard_cases.json
tests/skill-validator/runs/report_web2_vuln_ab_live.md
tests/skill-validator/runs/report_web2_vuln_ab_hard.md
```

They still document the pre-slim live observation: 24/24 baseline and 24/24 enhanced for procedural decisions. This local Codex run did not re-run Claude CLI live A/B, so it does not claim a new live lift; it claims deterministic route/signal regression safety.

## Leak Check

The changed tracked files and web2 live A/B artifacts were checked for known target-specific domains, credentials, one-time token patterns, and lab-only account markers. No matches were found.

## Decision

Slim accepted locally: the default-loaded skill is now compact, route/card gaps are fixed, deterministic enhanced coverage is complete, and details remain available through on-demand references. Do not push without explicit user confirmation.
