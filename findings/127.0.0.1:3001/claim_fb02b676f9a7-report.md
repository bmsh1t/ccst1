# BOLA: cross-actor basket read on /rest/basket/<id> (witness /rest/basket/4)

## Summary

GET http://127.0.0.1:3001/rest/basket/4 with a peer account returns the owner's basket (UserId=11) byte-identically to the owner's own request (200, 558B, sha16 7d65b98323ce8b29). Only the Authorization header differs between the two requests (single-variable replay, operation runner:ab956a74a97db7e4c72bb0f2). Anonymous requests are correctly denied with 401, placing the missing control at object-ownership rather than authentication.

## Generalization

Baskets 1-6 are readable cross-actor in both directions (owner->peer and peer->owner); see findings/127.0.0.1:3001/AQ-0002-report.md for the full matrix. This finding is the single-URL owner-bound witness for that generalized claim.

## Impact

Any authenticated user can enumerate sequential basket ids and read other users' baskets including product contents and account binding. Confidentiality impact on user data; CVSS 5.3 (AV:N/AC:L/PR:L/UI:N/VC:L/VI:L).

## Evidence

- Owner/peer request-diff: evidence/127.0.0.1:3001/validation/claim_fb02b676f9a7/20260912T151730276783Z-1bb5c4ed/summary.json
- Anonymous deny (401): recorded tested_clean, GET /rest/basket/6 x IDOR actor gap
- Generalization matrix: findings/127.0.0.1:3001/AQ-0002-report.md
