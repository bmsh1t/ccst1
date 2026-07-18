---
description: Validate a report candidate — runs the 7-Question Gate + 4-gate checklist. Rejects weak candidates before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /validate
---

# /validate

Run full validation on the current finding before writing a report.

## Use When

- A Lead/Signal has become a real Candidate
- You are preparing to write or queue a report
- You need a strict REPORT / CHAIN_REQUIRED / DOWNGRADE / DO_NOT_REPORT decision instead of more exploration

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
- 当前 finding 独占的 `<artifact-key>.validation-summary.json`
- Updated finding linkage/status when launched from `findings.json`
- Updated runtime state so `/pickup` / `/surface` / autopilot know validation progress

## Artifacts Written

- 报告同目录的 `<artifact-key>.validation-summary.json`
- 报告同目录的 `<artifact-key>.submission-notes.md`
- `findings/last-validate.json`（仅为最近一次运行的 convenience pointer）
- `findings/<target>/findings.json` status updates when applicable
- `state/<target>/session.json`

## Resume Source

- Structured finding linkage from `findings/<target>/findings.json`
- canonical finding 行中 `validation_summary` 指向的摘要（如果该 finding 已部分验证）
- PASS cases hand off to `/report`; non-PASS cases hand off back to hunt with a
  concrete next evidence step

Use `/validate` when a Lead or Signal has become a Candidate, or when preparing
`/report`. It is a strict pre-report/pre-submit gate, not a hunt-phase
kill-switch for raw leads, anomalies, hypotheses, or chain seeds.

## Target-Driven Validation

Validation uses the supplied target as the active target record. External
bounty metadata is optional context, not an execution gate. For local / CTF /
lab targets, use challenge/lab rules and observed behavior, keep validation
moving when `scope_snapshot.json` is absent, and treat write-up quality fields
as report controls rather than execution blockers.

If `config.json` sets `ctf_mode: true`, keep Gate 2 fully relaxed and do not
reintroduce external scope/program confirmation for this run.

## What This Does

1. Runs the 7-Question Gate and routes each non-pass by its meaning
2. Checks against the always-rejected list
3. Runs 4 pre-submission gates
4. Calculates and records validation context where applicable
5. Outputs: REPORT, CHAIN_REQUIRED, DOWNGRADE, or DO_NOT_REPORT

Before deciding, load `skills/triage-validation/SKILL.md` and treat its Q7
precedence, PRE-SEVERITY GATE, and RETRACTION DISCIPLINE as authoritative. The
condensed checklist below must not override those rules.

`tools/validate.py` records the 7-Question Gate in the current finding's
`<artifact-key>.validation-summary.json`.
If Claude/operator already made an explicit Q1-Q7 judgment, save it as JSON and
pass `--seven-question-json <file>`; otherwise the script stores a coarse
`derived_from_4_gates` audit block so the report path remains reviewable.

## Usage

```
/validate
```

## Non-TTY Claude CLI

`claude -p` has no interactive stdin. Do not let EOF answer a gate and never
edit `findings/<target>/findings.json` directly. Bind a complete machine decision
to the existing canonical finding instead:

```bash
python3 tools/validate.py --target <target> --finding-id <canonical-id> \
  --decision-json /tmp/validate-decision.json --json
```

`--target` resolves only `findings/<target-key>`; `--findings-dir` is the
equivalent explicit path. The decision JSON must use `schema_version: 1` and
include `target`, `finding_id`, `endpoint`, `vuln_class`, `method`, `impact`,
four explicit `gates.gate1..gate4.passed` booleans with notes, complete Q1–Q7
statuses/bases in `seven_question_gate.questions`, `cvss.score`/`vector`, an
`evidence.summary` plus non-empty existing `evidence.refs`, and
`report.path`/`report.content`. The target, ID, endpoint and class must match
the canonical row before any write occurs; the report path stays below that
row's `findings/<target>/` directory.

The tool writes the summary, ledger/queue handoff and canonical status through
their existing owners. `finding_index` also records a target-scoped owner
mutation event, so a later runtime check can distinguish an owner mutation from
an untracked JSON edit. Each canonical row records the actual
`validation_summary` path and its `validation_summary_sha256`; do not reconstruct
the filename in a caller. `findings/last-validate.json` is only a latest pointer
and is never canonical evidence. Omit `--decision-json` only from a real TTY session;
non-TTY calls fail closed without creating report, finding, queue or runtime state.

## Browser-State Priority

During validation, prove that a real user can reproduce the behavior in the
current state:

- Prefer chrome-devtools MCP for live browser/network evidence.
- Prefer playwright MCP for automated interaction and snapshots.
- Use `tools/browser_evidence.py` / `playwright-cli` only when MCP is unavailable or a scriptable fallback is needed.
- Import useful MCP artifacts with `tools/browser_mcp_import.py --target <target> --network-json <file> --url <page-url>` so `/surface`, `/checkpoint`, `/autopilot`, and validation summaries reuse the same observed API surface.
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

When validation finishes, the returned per-finding validation summary keeps the
linkage back to the scanner candidate when available:

- `finding_id`
- `finding_source_file`
- `finding_summary`

This lets `/report`, `/remember --from-validate`, and later review steps trace
the validated issue back to the original scanner evidence without reparsing the
raw finding files.

The matching item in `findings.json` is also updated with `validation_status`,
the exact `validation_summary` path, and its content digest when validation was
launched with `--finding-id`.
Subsequent `/surface` or direct `findings.json` review shows the
validation/report status for each structured candidate.

Describe the finding when prompted. Include:
- The endpoint
- The bug class
- What the PoC shows
- The target program
- The exact request/response evidence if available

If you already ran `/validate` and it passed, `/report` must use the selected
finding's recorded summary path (or the path returned by that exact invocation),
not a repo-global latest pointer from another finding.

Optional deterministic replay/diff helpers live in `docs/evidence-runners.md`.
Use them when they make evidence reproducible, but keep `/validate` as the
report-readiness gate: Claude still decides impact, preconditions, and whether
the issue is worth reporting.

## Case-State-First Validation

Target case state is runtime memory that feeds deterministic evidence runners:
actors, sessions, objects, private markers, hypotheses, and validation backlog.
It is not a substitute for `/validate`, not a scope gate, and not a reason to
reject a replayable candidate. Use it only when it improves continuity or
reduces header/object drift.

Useful paths:

```bash
python3 tools/target_case_state.py summary --target <target> --json
python3 tools/target_case_state.py next --target <target>
python3 tools/target_case_state.py complete-backlog --target <target> --id <id> --result <tested_clean|tested_finding|blocked>
```

If case state suggests a backlog item, validate the underlying evidence with
the same 7-question gate below. If live evidence is stronger than the cached
backlog, state the AI override and continue with the stronger proof path.

## The 7-Question Gate

Answer each. A non-pass stops the current claim; apply the authoritative routing
rules from `skills/triage-validation/SKILL.md` instead of collapsing every
outcome into a generic failure.

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
target context. External policy notes are optional context, not validation
gates.

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

**REPORT:** "All 7 questions pass. All 4 gates pass. Proceed to /report."

**CHAIN_REQUIRED:** "Q7 has a concrete connector, but the end-to-end chain is not yet proven. Keep the Candidate and collect [exact missing evidence]."

**DO_NOT_REPORT:** "Q[N] fails because [reason]. Do not report this candidate. Move on or demote only with a concrete next evidence action."

**DOWNGRADE:** "Q6 only shows technical possibility. Downgrade from High to Medium. Requires showing actual data exfil in PoC."

<!-- Adversarial self-review (`--self-review` on `agent.py`, B12c) is a
     local-Ollama runtime extension; see `agent.py` + `tools/self_review.py`
     + `tools/red_team_worker.py` for the runtime contract. -->
