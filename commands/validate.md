---
description: Validate a report candidate — runs the 7-Question Gate + 4-gate checklist. Rejects weak candidates before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /validate
---

# /validate

Run full validation on the current finding before writing a report.

## Use When

- A Lead/Signal has become a real Candidate
- You are preparing to write or queue a report
- You need a strict PASS / KILL / DOWNGRADE decision instead of more exploration

## Do Not Use When

- You are still broad-hunting and only have weak hypotheses
- You need recon, ranking, or enrichment rather than report gating
- The only evidence is code reading or intuition without a replayable request

## Inputs

- Candidate endpoint, vuln class, impact claim, and reproduction details
- Exact request/response or browser/OOB evidence when available
- `findings/<target>/findings.json` and `--finding-id` linkage when present
- Current target/runtime context from repo-local config and disk artifacts

## Outputs

- Validation decision and reasoning
- `validation-summary.json`
- Updated finding linkage/status when launched from `findings.json`
- Updated runtime state so `/pickup` / `/surface` / autopilot know validation progress

## Artifacts Written

- `findings/<target>/validation-summary.json` or equivalent report-local summary
- `findings/last-validate.json`
- `findings/<target>/findings.json` status updates when applicable
- `state/<target>/session.json`

## Resume Source

- Structured finding linkage from `findings/<target>/findings.json`
- Latest validation summary if this finding was already partially validated
- PASS cases hand off to `/report`; non-PASS cases hand off back to hunt with a
  concrete next evidence step

## Candidate Evidence Rubric

`/validate` now reads the candidate evidence rubric when launched from
`findings.json`. The rubric is a soft evidence upgrade gate: it does not block
Claude from exploring, but it tells the agent what proof is still missing before
the issue should be treated as report-ready.

Core rubric families:

- **Authz / IDOR / business logic** — actor/role/object diff, exact request,
  observable response/action delta, concrete business impact.
- **SQLi / NoSQLi** — baseline vs single-variable perturbation, stable
  differential signal, reproducibility, bounded read-only impact proof.
- **SSRF** — controlled callback or server-side fetch proof, server-side
  context, safe internal/metadata/target-owned impact path, exact request.
- **RCE / SSTI / command injection / deserialization** — inert marker or safe
  calculation, execution/evaluation context, exact trigger request, bounded
  non-destructive impact proof.
- **Upload / parser / file-flow** — upload accepted, storage/parser/render path,
  impact transition, harmless bounded artifact.
- **Secret / key exposure** — type/source/line, ownership context,
  validity/usability or safe-verification blocker, concrete impact path.
- **XXE / LFI / traversal** — controlled read-only proof, baseline diff,
  target-owned boundary/impact, exact request.
- **Known software / CVE** — exact component/version, advisory affected range,
  reachable feature/precondition, safe applicability PoC.

When the rubric says `needs-evidence` or `signal-only`, continue with the
smallest suggested evidence step instead of writing a report. When it says
`candidate-ready`, still run the normal 4 validation gates and CVSS/report
quality checks.

Use `/validate` when a Lead or Signal has become a Candidate, or when preparing
`/report`. It is a strict pre-report/pre-submit gate, not a hunt-phase
kill-switch for raw leads, anomalies, hypotheses, or chain seeds.

## Deterministic Evidence Runners

Before treating a lead as candidate-ready, prefer a small reproducible evidence
runner when the lane fits. This keeps Claude focused on hypothesis choice and
impact reasoning while tools handle replay, diff, raw evidence, and ledger
format.

```bash
# Anonymous admin/config exposure: body-backed marker required for tested_finding
python3 tools/validation_runner.py authz-public-exposure \
  --target <target> \
  --url <exact-url> \
  --browser-observed

# SQLi/NoSQLi-style read-only result diff: injection-shaped variant + stable diff
python3 tools/validation_runner.py sqli-result-diff \
  --target <target> \
  --url '<exact-url-with-param>' \
  --param <name> \
  --baseline-value '' \
  --variant-value '<single controlled perturbation>' \
  --repeat 2 \
  --browser-observed

# RCE/SSTI/template/command-injection style safe proof:
# replay the exact operator-provided request and require an inert marker
python3 tools/validation_runner.py marker-replay \
  --target <target> \
  --url '<exact-url>' \
  --expect-marker '<inert-marker>' \
  --vuln-class RCE \
  --repeat 2 \
  --browser-observed

# IDOR/Authz: generate the two-actor bundle; fill with owner/peer evidence
python3 tools/validation_runner.py idor-actor-pair \
  --target <target> \
  --url '<same object/action URL>' \
  --owner-header 'Authorization: Bearer <owner-token>' \
  --peer-header 'Authorization: Bearer <peer-token>' \
  --expect-marker '<owner-private-marker>' \
  --repeat 2 \
  --browser-observed

# If the second actor/session is not ready yet, generate the evidence skeleton
python3 tools/validation_runner.py idor-skeleton \
  --target <target> \
  --endpoint <exact-endpoint>
```

Runner output is not a replacement for `/validate`. Use it as the evidence
plane: it writes `evidence/<target>/validation/<finding-id>/`, records the
Evidence Ledger unless `--no-ledger` is set, and returns `ai_next` /
`stop_condition` for Claude to decide the next hypothesis.

## Target-Driven Validation

Validation uses the supplied target as the active target record. External
bounty metadata is optional context, not an execution gate. For local / CTF /
lab targets, use challenge/lab rules and observed behavior, keep validation
moving when external program metadata is absent, and treat write-up quality fields
as report controls rather than execution blockers.

If `config.json` sets `ctf_mode: true`, keep Gate 2 fully relaxed and do not
reintroduce external program confirmation for this run.

## What This Does

1. Runs the 7-Question Gate (one wrong answer = reject the report path)
2. Checks against the always-rejected list
3. Runs 4 pre-submission gates
4. Calculates and records validation context where applicable
5. Outputs: PASS (write the report), KILL (do not report), or DOWNGRADE (impact not strong enough)

## Usage

```
/validate
```

## Browser-State Priority

During validation, prove that a real user can reproduce the behavior in the
current state:

- Prefer chrome-devtools MCP for live browser/network evidence.
- Prefer playwright MCP for automated interaction and snapshots.
- Use `tools/browser_evidence.py` / `playwright-cli` only when MCP is unavailable or a scriptable fallback is needed.
- Import MCP artifacts with `python3 tools/browser_mcp_import.py --target <target> --network-json <file> --url <page-url>` so `recon/<target>/browser/`, `/surface`, `/checkpoint`, `/autopilot`, and validation summaries can reuse the same observed browser API surface.
- Exact non-browser requests can use `curl` / `urllib` / local helpers for lightweight replay.
- Burp/Caido history is auxiliary replay and comparison context; missing Burp/Caido should not block validation.

Reproducibility and evidence quality matter here; external policy text and
metadata still remain optional report-writing context, not execution blockers.

When a scanner finding index exists, use the finding id from
`findings/<target>/findings.json` to prefill the interactive validation context:

```bash
python3 tools/validate.py --findings-dir findings/target.com --finding-id sqli_abc123
```

For a quick candidate list, read `findings/<target>/findings.json` directly or
rebuild it with:

```bash
python3 tools/finding_index.py findings/target.com
```

When validation finishes, `validation-summary.json` keeps the linkage back to
the scanner candidate when available:

- `finding_id`
- `finding_source_file`
- `finding_summary`

This lets `/report`, `/remember --from-validate`, and later review steps trace
the validated issue back to the original scanner evidence without reparsing the
raw finding files.

The matching item in `findings.json` is also updated with `validation_status`
and `validation_summary` when validation was launched with `--finding-id`.
Subsequent `/surface` or direct `findings.json` review shows the
validation/report status for each structured candidate.

Describe the finding when prompted. Include:
- The endpoint
- The bug class
- What the PoC shows
- The target program
- The exact request/response evidence if available

If you already ran `/validate` and it passed, `/report` can use the latest validation summary as report context.

## The 7-Question Gate

Answer each. ONE wrong answer = STOP the report path.

### Q1: Can I demonstrate this step-by-step RIGHT NOW?

Write this out:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body]
3. Result:  Response shows [exact data / action completed]
4. Impact:  Real consequence is [account takeover / PII exposed / money stolen]
5. Effort:  Preconditions are [auth/no-auth/role/object ID], with [single request / multi-step flow]
```

If step 2 is "I need to look at the code more" → do not report it yet.

### Q2: Is the impact clearly demonstrated?

Use observed exploitability, reproduced behavior, and practical impact. Public
accepted-impact lists are optional context, not a validation gate.

### Q3: Is the vulnerable asset tied to the supplied target context?

Use the provided target, IP, CIDR, primary-domain batch list, or exact URL as the working
target context. External policy notes are optional context, not validation gates.

### Q4: Does it need admin or privileged access that an attacker can't get?

"Admin can do X" → DO NOT REPORT.
"Regular user can do X that only admin should" → valid.

### Q5: Is this known or documented behavior?

Search disclosed reports + changelog + API docs.

### Q6: Can you prove impact beyond "technically possible"?

- XSS → actual cookie value in exfil request, not just alert()
- SSRF → response body from internal service, not just DNS callback
- IDOR → actual other-user's private data in response, not just 200 status

### Q7: Is this on the never-submit list?

```
Missing headers, GraphQL introspection alone, clickjacking without PoC,
self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, banner disclosure,
rate limit on non-critical forms, missing cookie flags alone...
```

If yes → do not report it unless you have a proven chain.

## Check: Conditionally Valid?

If it's on the never-submit list, can you chain it?

| You Have | Chain Available? |
|---|---|
| Open redirect | + OAuth code theft → ATO? |
| SSRF DNS-only | + internal service data? |
| Clickjacking | + sensitive action + PoC? |
| CORS wildcard | + credentialed data exfil? |
| Prompt injection | + IDOR → other user's data? |

If no chain → do not report it. If chain confirmed → report the proven chain.

## 4 Gates — All Must Pass

**Gate 0 (30 sec):**
```
[ ] Confirmed with real HTTP requests (not just code reading)
[ ] Tied to the supplied target context
[ ] Reproducible from scratch
[ ] Evidence captured
```

**Gate 1 — Impact (2 min):**
```
[ ] Can answer "What does attacker walk away with?"
[ ] More than "sees non-sensitive data"
[ ] Real victim exists
[ ] No unlikely preconditions
```

**Gate 2 — Dedup (5 min):**
```
[ ] Searched HackerOne Hacktivity for endpoint + bug class
[ ] Searched GitHub issues
[ ] Read 5 most recent disclosed reports
[ ] Not in changelog as known issue
```

**Gate 3 — Report quality (10 min):**
```
[ ] Title formula: [Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps have exact HTTP request
[ ] Evidence shows actual impact
[ ] CVSS calculated
```

## Output

**PASS:** "All 7 questions pass. All 4 gates pass. Proceed to /report."

**KILL:** "Q[N] fails because [reason]. Do not report this candidate. Reason: [explanation]. Move on or demote with the next evidence action."

**DOWNGRADE:** "Q6 only shows technical possibility. Downgrade from High to Medium. Requires showing actual data exfil in PoC."

<!-- Adversarial self-review (`--self-review` on `agent.py`, B12c) is a
     local-Ollama runtime extension; see `agent.py` + `tools/self_review.py`
     + `tools/red_team_worker.py` for the runtime contract. -->
