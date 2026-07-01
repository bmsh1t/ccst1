# Web2 Vuln Classes A/B Evaluation

## Scope

Deterministic local A/B for `skills/web2-vuln-classes/SKILL.md`.
This measures loaded-context signal availability, not live model accuracy.

## Summary

- Cases: 10
- web2-vuln-classes lines: 380
- Baseline score: 42/53
- Enhanced score: 53/53
- Delta: +11
- Cases with Skill-only signal: W01, W03, W04, W05, W06, W08, W09, W10
- Cases still missing enhanced signals: none
- Route/card gap cases: none

Reference hints observed:

- `skills/security-arsenal/references/bypass-patterns.md`
- `skills/security-arsenal/references/payload-families.md`
- `skills/security-arsenal/references/sink-and-grep-patterns.md`

## Per-case results

| Case | Lane | Selected Skill | Baseline | Enhanced | Delta | Skill-only checks | Route/card gap | Enhanced missing |
|---|---|---|---:|---:|---:|---|---|---|
| W01 | ssrf | web2-vuln-classes | 4/5 | 5/5 | +1 | dns_only_not_enough | - | - |
| W02 | ssti_command_rce | web2-vuln-classes | 5/5 | 5/5 | +0 | - | - | - |
| W03 | upload_execution | web2-vuln-classes | 5/6 | 6/6 | +1 | safe_verification | - | - |
| W04 | deserialization | web2-vuln-classes | 4/5 | 5/5 | +1 | integrity_boundary | - | - |
| W05 | sql_nosql_hidden_surface | web2-vuln-classes | 3/5 | 5/5 | +2 | baseline_confirmation, type_classification | - | - |
| W06 | graphql_api_auth_matrix | web2-vuln-classes | 3/5 | 5/5 | +2 | field_level_auth_matrix, introspection_not_enough | - | - |
| W07 | jwt_oauth_sso | web2-vuln-classes | 5/5 | 5/5 | +0 | - | - | - |
| W08 | smuggling_cache_proxy | web2-vuln-classes | 4/5 | 5/5 | +1 | cache_key_workflow | - | - |
| W09 | race_business_logic | web2-vuln-classes | 3/5 | 5/5 | +2 | parallel_replay, toctou_state_transition | - | - |
| W10 | browser_realtime_boundary | web2-vuln-classes | 6/7 | 7/7 | +1 | stop_conditions | - | - |

## Interpretation

- If baseline and enhanced both pass a signal, that signal already lives in compact cards/references.
- If only enhanced passes, the compact Skill still carries a decision-layer signal that has not been duplicated into references.
- If enhanced misses a signal or a route/card gap appears, fix cards/seeds/routes before claiming the slim is safe.
- A future live LLM A/B can reuse the same case file; this report is the deterministic post-slim regression baseline.
