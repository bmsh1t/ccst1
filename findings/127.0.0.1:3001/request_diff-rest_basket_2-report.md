# BOLA: cross-actor basket read on /rest/basket/2

## Summary

GET http://127.0.0.1:3001/rest/basket/2 with a peer account returns the owner's basket (UserId=2) byte-identically to the owner's own request (200, 557B, sha16 31262b59e2439e92). Only the Authorization header differs (single-variable replay, operation runner:af8b2578caf483db455b70f1). Anonymous requests get 401 — the missing control is object ownership, not authentication.

## Relation to other witnesses

Same root cause as the validated witness on /rest/basket/4 (claim_fb02b676f9a7) and the baskets 1-6 matrix in AQ-0002's report. This finding is the owner-bound witness for basket/2.

## Impact

Any authenticated user can enumerate baskets and read other users' baskets (products, account binding). CVSS 5.3 (AV:N/AC:L/PR:L/UI:N/VC:L/VI:L).

## Evidence

- Runner: evidence/127.0.0.1:3001/validation/request_diff-rest_basket_2/20260912T152313246935Z-97f2841b/summary.json
- Anonymous deny: tested_clean, GET /rest/basket/6 x IDOR
- Matrix: findings/127.0.0.1:3001/AQ-0002-report.md
