# Bug Bounty Report Summary — 127.0.0.1:3001

Generated: 2026-09-14 01:39:33

Total findings: 6

| # | Severity | Type | Title | URL |
|---|----------|------|-------|-----|
| auth_bypass_001 | MEDIUM | auth_bypass | Candidate Authz on http://127.0.0.1:3001/rest/bask | http://127.0.0.1:3001/rest/basket/6 |
| misconfig_001 | MEDIUM | Authz | Candidate Authz on http://127.0.0.1:3001/rest/bask | http://127.0.0.1:3001/rest/basket/2 |
| misconfig_002 | MEDIUM | Authz | Generalized bidirectional BOLA on /rest/basket/<id | http://127.0.0.1:3001/rest/basket/4 |
| auth_bypass_002 | MEDIUM | Authz | Candidate Authz on http://127.0.0.1:3001/api/Baske | http://127.0.0.1:3001/api/BasketItems/1 |
| auth_bypass_003 | MEDIUM | Authz | Candidate exposure on http://127.0.0.1:3001/api/Us | http://127.0.0.1:3001/api/Users |
| auth_bypass_004 | MEDIUM | auth_bypass | BOLA: cross-actor basket read on /rest/basket/<id> | http://127.0.0.1:3001/rest/basket/1 |
