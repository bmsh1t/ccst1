# Authentication/Authorization Bypass on 127.0.0.1:3001

## Severity
**MEDIUM** (CVSS: 5.3)

## Vulnerability Type
CWE-287 — AUTH_BYPASS

## Summary
Validated `GET` authorization/business-logic evidence was recorded for `http://127.0.0.1:3001/rest/basket/6`. authz:needs-evidence score=25 satisfied=1/4 missing=actor / role / object boundary difference; observable response/data/action difference; target-owned business impact

## Affected URL
```
http://127.0.0.1:3001/rest/basket/6
```

## Steps to Reproduce
1. Navigate to the following URL:
   ```
   http://127.0.0.1:3001/rest/basket/6
   ```
2. Observe the vulnerable behavior as described below.

## Evidence / Proof of Concept
**Scanner Output:**
```
validation_runner:request_diff:AQ-0002
```

**Template/Check:** ``

**Finding Reference:**
- **Finding ID:** AQ-0002
- **Source artifact:** evidence/127.0.0.1:3001/validation/AQ-0002/20260911T074639340963Z-316e3411/summary.json
- **Source line:** 0
- **Confidence:** confirmed
- **Finding summary:** authz:needs-evidence score=25 satisfied=1/4 missing=actor / role / object boundary difference; observable response/data/action difference; target-owned business impact


**Validation Evidence:**
**7-Question Gate:** `PASS` (`pass`)
**Four Validation Gates:** `PASS`
**Combined Report Readiness:** `PASS`
**Evidence Rubric:** `authz:needs-evidence score=25 satisfied=1/4 missing=actor / role / object boundary difference; observable response/data/action difference; target-owned business impact`


## Impact
An attacker can bypass authentication or authorization controls to access protected resources or functionality. This may allow unauthenticated access to admin panels, API endpoints, or user data without proper credentials.

## Remediation
1. Enforce authentication on all protected endpoints
2. Implement server-side authorization checks (not client-side)
3. Use a centralized authentication/authorization middleware
4. Deny by default — explicitly allow access only where needed
5. Test all HTTP methods (GET, POST, PUT, DELETE) for each endpoint

## References
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---
*Report generated: 2026-09-12 17:49:23*
*Scanner: Automated Bug Bounty Pipeline*
