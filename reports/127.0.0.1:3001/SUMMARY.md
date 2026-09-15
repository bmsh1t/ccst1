# Bug Bounty Report Summary — 127.0.0.1:3001

Generated: 2026-09-15 05:24:27

Total findings: 8

| # | Severity | Type | Title | URL |
|---|----------|------|-------|-----|
| sqli_001 | CRITICAL | sqli | Unauthenticated SQL Injection — Full Database Read | http://127.0.0.1:3001/rest/products/search?q= |
| auth_bypass_001 | MEDIUM | auth_bypass | Candidate Authz on http://127.0.0.1:3001/rest/bask | http://127.0.0.1:3001/rest/basket/6 |
| misconfig_001 | MEDIUM | Authz | Candidate Authz on http://127.0.0.1:3001/rest/bask | http://127.0.0.1:3001/rest/basket/2 |
| misconfig_002 | MEDIUM | Authz | Generalized bidirectional BOLA on /rest/basket/<id | http://127.0.0.1:3001/rest/basket/4 |
| auth_bypass_002 | MEDIUM | Authz | Candidate Authz on http://127.0.0.1:3001/api/Baske | http://127.0.0.1:3001/api/BasketItems/1 |
| auth_bypass_003 | MEDIUM | Authz | Candidate exposure on http://127.0.0.1:3001/api/Us | http://127.0.0.1:3001/api/Users |
| auth_bypass_004 | MEDIUM | auth_bypass | Candidate Authz on http://127.0.0.1:3001/rest/bask | http://127.0.0.1:3001/rest/basket/1 |
| auth_bypass_005 | MEDIUM | auth_bypass | Unauthenticated /ftp/ access-control bypass | http://127.0.0.1:3001/ftp/package.json.bak |
