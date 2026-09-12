# User enumeration and PII disclosure via /api/Users

## Summary

GET http://127.0.0.1:3001/api/Users with any authenticated customer token returns the complete user table: 24 accounts including admin email addresses (admin@juice-sh.op, bjoern.kimminich@gmail.com), role assignments, deluxeToken fields, and lastLoginIp values. Owner and peer tokens receive byte-identical responses (200, 6920B) — the collection is not restricted per user. Anonymous requests get 401 (operation runner:8375c1bb66b9dc256c9d97e7).

## Impact

Any registered user can enumerate all platform accounts with emails, roles, and last-login IPs. This enables targeted phishing (admin identities known), credential stuffing preparation (valid email list), and internal information exposure. CVSS 5.3 (AV:N/AC:L/PR:L/UI:N/VC:L).

## Evidence

- Owner/peer request-diff: evidence/127.0.0.1:3001/validation/users-enumeration-1/20260912T175051084009Z-a8d893c0/summary.json
- Anonymous 401 observed in the same session
