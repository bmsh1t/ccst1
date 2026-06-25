---
description: Action-first autonomous hunt loop — load state, refresh recon only when needed, rank surface, optionally enrich, hunt, validate candidates, and report validated findings. Usage: /autopilot target.com [--paranoid|--normal|--yolo|--quick|--deep] or /autopilot targets.txt
---

# /autopilot

Invocation arguments: `$ARGUMENTS`

Parse the invocation arguments first. The first non-flag argument is the target
or primary-domain batch list. `--deep` activates the Deep Mode rules in this
command. If no target is present, ask for the exact target instead of guessing.

Autonomous Claude CLI hunt loop. Same capabilities as the manual chain, fewer prompts:

```text
LOAD -> /recon(if needed) -> /surface(RANK) -> optional enrichment -> /hunt -> /validate(if candidate) -> /report(if validated) -> checkpoint
```

Evidence drives order. Do not rerun usable recon, and do not validate/report without a Candidate/Validated Finding.

## Four-Layer Automation

`/autopilot` is the primary automated entrypoint for the four-layer system. Do
not create a separate workflow command for normal use.

At startup, use the four-layer context in this order:

```text
target memory -> skill routing -> knowledge cards -> red-line / coverage checks
```

Automatic behavior:

1. **Target memory** — read `memory/goals/active.json` and
   `memory/goals/targets/<target>.json` when present. Active leads, next
   actions, dead ends, and handoff summaries should influence the next lane.
2. **Skill routing** — use `skills/runtime-protocol.md` to choose the main
   Skill for the next step: recon, surface ranking, Web2 vuln class testing, or
   validation.
3. **Knowledge cards** — use `knowledge/index.md` and load only the 1-2 cards
   matching current evidence, such as `api-idor`, `graphql`, `upload-parser`,
   `ssrf-url-fetch`, or `race-conditions`.
4. **Checks** — apply `rules/red-lines.md` before any high-volume or
   state-changing action, and apply `rules/coverage-gate.md` before checkpoint
   or finish.
5. **Write-back** — checkpoint useful leads, next actions, dead ends, and
   handoff notes through target memory. Use `/retrospect` at finish to decide
   whether experience should be promoted to knowledge, Skills, or Rules.

## Next Action Consumption Loop

`/autopilot` must consume queued next actions before finishing. A checkpoint or
surface summary that contains `Next Actions`, `next_action_queue`, target-memory
next actions, high-value coverage gaps, or actor-matrix gaps is not a final
answer by itself.

Startup sequence:

```bash
python3 tools/context_pack.py --target target.com
python3 tools/autopilot_state.py --target target.com
python3 tools/checkpoint.py --target target.com --json
```

Then choose the first safe item from `recommended_executable_action`,
`next_action_queue`, or `Memory action queue` and execute the smallest
evidence-producing step. After the step:

1. Record the result as tested-clean, blocked, dead-end, Candidate, or
   Validated Finding.
2. Rebuild or inspect coverage when the action touched a high-value endpoint.
3. Rerun checkpoint and consume the next queued action unless a stop condition
   is met.

Stop conditions:

- A red-line rule blocks the next action and no lower-risk evidence path exists.
- Required auth/session/material is missing and cannot be derived safely through
  login-flow construction, existing artifacts, or the controlled Credential
  Lane.
- A Candidate needs operator-provided credentials, business context, or manual
  validation.
- If every tracked live host is cooling down or locked by request guard, do not
  stop as "done" and do not recommend IP rotation, WAF evasion, or social
  engineering. Automatically pivot to cached recon/browser/JS/source evidence,
  `/context-pack`, `/checkpoint`, coverage updates, and target-memory write-back
  until a safe live path exists.
- `--normal` has completed a related batch and checkpoint explains remaining
  gaps.
- `--deep` has completed the Deep Exhaustion Checklist.
- The operator stops the run.

Exit discipline:

- If coverage is near 0% or high-value gaps remain, do not end with only
  "saved to target memory" or "continue later". Continue consuming the queue or
  state the concrete blocker.
- Do not pad progress with repeated scans. A consumed action must add, confirm,
  disprove, block, or record target evidence.
- Apply target memory only when the operator wants automatic write-back:
  `python3 tools/checkpoint.py --target target.com --apply-target-memory`.

`python3 tools/context_pack.py --target <target>` is the Claude CLI context
navigator for this startup sequence. Run it before broad reading so the session
loads one main Skill, 1-2 knowledge cards, red-line checks, coverage checks, and
write-back targets instead of loading every Skill or raw log.

`python3 tools/autopilot_state.py --target <target>` includes target memory
when available. Use context-pack first, then this state output, before deciding
whether to recon, surface, enrich, hunt, validate, or checkpoint.

## Authorization Posture

Before recon/scanning/hunting, treat the supplied target, IP, CIDR, or
primary-domain batch list as this run's active authorized test scope. Do not
pause to re-ask for authorization, ownership proof, or public-program
confirmation before routine recon, scanning, or evidence-driven hunting.

Pause only for ambiguous target identity, unavailable credentials that cannot
be derived through the controlled Credential Lane, report submission, a new
out-of-surface target, or explicit unsafe/state-changing actions.

## Run This First

Single target:

```bash
python3 tools/context_pack.py --target target.com
python3 tools/autopilot_state.py --target target.com
python3 tools/surface.py --target target.com
```

If state/surface says recon is missing, incomplete, stale, or thin:

```bash
python3 tools/hunt.py --target target.com --recon-only
python3 tools/surface.py --target target.com
```

When ready for broad coverage:

```bash
python3 tools/hunt.py --target target.com --scan-only
```

`/autopilot target.com --normal` means checkpoint after related candidates / validation batches, not after every routine branch.

For focused high-value targets where shallow scanner results are not enough:

```text
/autopilot target.com --deep --normal
```

For the broad Bash scan step inside that Claude CLI loop:

```bash
python3 tools/hunt.py --target target.com --scan-only --scanner-full
```

`--deep` increases Claude CLI persistence and high-impact lane rotation. It
does not change target semantics and does not opt in to unsafe/state-changing
actions. Do not add `--agent` unless you explicitly want the legacy local
`agent.py` / Ollama runtime.

## Batch List Targets

Readable file = primary-domain batch, one root/primary domain per non-comment line.

```bash
BBHUNT_BATCH_SIZE=5 python3 tools/hunt.py --target targets.txt --recon-only
```

`unwaf` origin discovery is disabled by default because it is slow on large
lists. Enable it only for a focused origin-bypass pass:

```bash
BBHUNT_ENABLE_UNWAF=1 python3 tools/hunt.py --target target.com --recon-only
```

After batch recon, read `recon/<list-stem>/{batch_summary.md,ai_handoff.md,surface_ranking.txt,high_value_targets.json}` and continue on selected completed domains:

```text
/autopilot selected-domain.com --normal
/surface selected-domain.com
/hunt selected-domain.com
```

`recon/<list-stem>/<domain>` is only a grouped browsing link back to
`recon/<domain>` so different list files stay readable. Do not hunt
`recon/<list-stem>/` as an aggregate target.

## Decision Loop

1. **LOAD** — autopilot state, target memory, `/pickup` if useful, `/surface`, structured findings, guard hints.
2. **RECON** — only missing/thin/stale. Recon already collects API docs/leaks, SwaggerSpy/Postman/postleaksNg, waymore, emailfinder, LeakSearch, cloud_enum.
3. **RANK** — use `/surface`; do not manually summarize every recon file first. Use target-memory dead ends to avoid repeated low-value lanes.
4. **ENRICH** — only when it changes the next test:
   - JS → `python3 tools/js_reader.py --target target.com`, then `js-reader` on `findings/<target>/js_intel/materials.json`.
   - source/routes/auth → `python3 tools/source_intel.py --target target.com [--repo-path <repo>]`.
   - browser SPA/login/XHR → browser/playwright capture, then rerun `/surface`.
   - exposure/API leak/cloud identity → read `recon/<target>/exposure/...` before broad scanning.
5. **HUNT** — scanner for breadth or exact local probe for one hypothesis; prefer role/object/method/version/body diffs. After any scanner run, rerun `/surface target.com` before deciding the target is exhausted.
   If the target exposes a credible login surface and normal high-value lanes
   have stalled, evaluate the Credential Lane below before stopping only because
   no authenticated session exists.
6. **VALIDATE** — Signal → Candidate → Validated Finding only with exact replay, A/B role diff, impact proof, evidence.
7. **REPORT** — draft only validated findings; never auto-submit.
8. **CHECKPOINT** — run `python3 tools/checkpoint.py --target target.com`
   to generate decisive evidence, dead lanes, next P1/P2, coverage gaps,
   target-memory write-back proposals, and retrospective prompts.

Before checkpoint or finish, rebuild and inspect the coverage matrix:

```bash
python3 tools/coverage_matrix.py rebuild --target target.com
python3 tools/coverage_matrix.py find-gaps --target target.com
python3 tools/checkpoint.py --target target.com
```

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | meaningful findings or strong partial signals | new targets |
| `--normal` | related candidates / validation batches | systematic coverage |
| `--yolo` | surface exhaustion or handoff moments | familiar targets |

Mode controls checkpoint cadence only. It must not change target semantics, inherit old skip lists, or force every stage to run.

## Deep Mode

`--deep` is a value-first comprehensive depth flag, not a checkpoint mode. It
can be combined with `--normal` or `--yolo`.

Claude CLI behavior: `--deep` raises the prompt-level persistence floor. Do not
finish until enough substantive actions have changed the evidence state, the
Deep Exhaustion Checklist is explicit, or the operator stops the run.
Substantive actions are actions that add, confirm, disprove, block, or record
target evidence; do not pad the run with repeated scans or cosmetic steps.
`--deep --yolo` still cannot use yolo as a shortcut around that persistence
floor.

Legacy local-agent behavior: only `python3 tools/hunt.py --target <target>
--agent --deep` enters `agent.py` and enforces the 60 step / 4h default budget
when the operator did not request a larger budget. Do not add `--agent` from
Claude CLI unless the operator explicitly asks for the legacy local/Ollama
runtime.

In deep mode:

- Do not stop after shallow scanner-negative results or one dead lane.
- Treat scanner-negative results as the start of manual, AI-guided deep work,
  not as a conclusion.
- Assume a hidden high-value path may still exist until budget is exhausted,
  the attack surface is genuinely exhausted, or evidence gaps are explicit.
- Use `rules/hunting.md#high-intensity-hunting-posture` and the value-first
  coverage model: prioritize by practical impact, exploitability, evidence
  strength, affected data/workflow, validation safety, and coverage gaps.
- Rotate through high-value vulnerability families before declaring exhaustion;
  do not lock onto authz/IDOR or any other fixed favorite class. Cover evidence
  routes for access/identity, injection/RCE, server-side/file/network,
  client-side, business workflow, and infrastructure/supply-chain bugs.
- Browser-observed APIs, JS/source-derived routes, recon output, errors,
  parameters, workflows, and target memory are evidence sources. They can point
  to SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection, unsafe
  deserialization, LFI/RFI/path traversal, upload/parser chains, XSS/DOM XSS,
  OAuth/JWT/CSRF, race/state-machine bugs, secrets/CI/CD/cloud exposure, or
  authz/IDOR/business logic.
- Convert failures into next questions: sibling expansion, bypass attempt,
  role/object diff, enrichment, or lane rotation.
- Start with basic techniques, then escalate to advanced parser mismatch,
  state-machine, cross-boundary, source-informed, browser-observed, and
  chain-building techniques when standard methods fail.
- Chain aggressively: when A is plausible, look for B/C that proves stronger
  business impact through siblings, role differences, old API versions,
  exports/downloads, admin render paths, callbacks, or source-confirmed sinks.
- Focus on demonstrable business impact: data exposure, auth/tenant boundary
  break, privileged action reachability, account/session compromise path,
  internal-service reachability, or source/secret-backed pivot.
- Use a bug-bounty mindset: one reward-worthy, high-impact finding is worth
  more than many info-level observations. Do not spend deep-mode energy
  polishing low-impact issues unless they support a stronger chain.
- If a candidate looks unlikely to be reward-worthy on its own, keep hunting or
  chain it into stronger impact: data exposure, cross-tenant access,
  account/session compromise, privileged workflow reachability, or meaningful
  internal pivot.
- When login is the only realistic path to account/session compromise, RCE,
  privileged workflow reachability, or deeper authenticated surface, evaluate
  controlled credential testing instead of marking auth as a blocker.
- Prefer evidence-driven depth over random tool spray, but do not be timid. Use
  `run_vuln_scan full=true`, `run_zero_day_fuzzer deep=true`,
  `run_js_analysis`, `run_secret_hunt`, equivalent helpers, or small custom
  probes when the target is high-value, the surface is broad, a lane plateaus,
  or partial evidence suggests the extra cost may pay off.
- Complete a Deep Exhaustion Checklist before finish: recon/state and `/surface`
  consulted; coverage matrix rebuilt; Evidence Ledger / actor matrix reviewed;
  scanner-negative results received manual follow-up; JS/source/browser/
  exposure context used or explicitly ruled out; sibling/bypass/role-diff/
  parser/chain-building attempts made where applicable; high-value vuln-family
  directions tested, blocked, not applicable, or listed with reasons.
- Before finish, run or inspect:
  ```bash
  python3 tools/coverage_matrix.py rebuild --target target.com
  python3 tools/coverage_matrix.py find-gaps --target target.com
  python3 tools/evidence_ledger.py summary --target target.com
  python3 tools/checkpoint.py --target target.com
  ```
- Finish with concrete evidence gaps, not a generic "no findings" conclusion.

Deep mode still preserves live-action boundaries: payment/funds/order lifecycle
writes, unsafe methods, report submission, and state-changing mutations require
explicit current-turn operator intent.

## Credential Lane

Credential testing is not a red line when it is bounded and evidence-driven.
`/autopilot` may select `/wordlist-gen -> /breach-check -> /osint-employees ->
/spray` when all of these are true:

- Login endpoint, target host, success/failure signal, username source, and
  password source are concrete.
- Other high-value lanes are blocked, tested-clean, or lower value for the
  current target state.
- The password set is target-derived, ranked, and bounded; never use a broad
  generic dump as the live attempt list.
- A dry-run/pre-flight is possible and the live run has delay, jitter, lockout
  expectation, audit log, and stop-on-hit discipline.
- On first valid credential, stop spraying and pivot to minimal authenticated
  validation through `/hunt`, `/surface`, or exact replay.

If any precondition is missing, write a target-memory next action instead of
silently dropping the lane or launching guesses.

## Tool Failure Discipline

A failed tool is not a failed hypothesis. When a helper errors, times out, or
returns partial data:

1. Read the error and classify it: missing tool, bad arguments, timeout/rate
   limit, auth/session issue, target-format problem, network/proxy issue, or
   genuine negative signal.
2. Retry once with corrected arguments when the fix is obvious.
3. Otherwise use an equivalent helper, `curl`/Python/Playwright custom probe,
   cached artifact, or partial output to keep the lane alive.
4. If the lane cannot be completed, record the exact evidence gap and rotate to
   the next best high-impact test instead of silently killing the path.

## Agent Handoff Contract

When spawning a specialist Task/agent, pass a compact handoff packet in the
same message. Do not rely on prior chat history or long tool output being
available to the child agent.

Required handoff fields:

- **Target identifier**: exact `URL`, `IP:Port`, domain, API base, or artifact
  path to analyze.
- **In-scope boundary**: what hosts, paths, protocols, files, or cached
  artifacts are allowed for this task.
- **Known facts**: top 5-10 confirmed facts only, including recon/surface
  ranking, auth state, important status/body diffs, and relevant files.
- **Single objective**: one narrow task for this specialist, such as semantic JS
  read, disclosed-pattern transfer, chain fit, candidate validation, or report
  draft review.
- **Do not repeat**: explicit duplicate work to avoid, e.g. no full recon, no
  broad URL enumeration, no list-stem target hunting.
- **Expected output**: short verdict plus evidence paths, replay commands or
  requests, open evidence gaps, and the recommended next action.

If any required field is missing, complete local context first instead of
spawning a vague "continue" task. For primary-domain batch lists, select a
completed domain from `recon/<list-stem>/surface_ranking.txt` and hand off that
domain, not the list index.

## Tool Index

Before non-default helpers, scan `docs/tool-index.md` once per session. It is quick-pick context, not a state machine; the Bash commands above remain the Claude CLI fast path.

## Step 0: Business Model Read

Before first fresh recon on a new target, ensure `evidence/<target>/business_model.md` exists and is fresh. This points to the `agent.py` system prompt directive; read it if present, otherwise write a short free-text note and continue.

## Step 0.5: Target Fingerprint

Read/write `hunt-memory/targets/<target>/fingerprint.md` before active hunting: stack, business vertical, closest precedent, public PoC keywords, known anti-patterns.

## Step 0.6: Stack Recall

Name stack from evidence and recall relevant families before HUNT: OAuth redirect/state/PKCE, SAML signature/XSW, GraphQL `node(id)` and field auth, IIS `~1` shortname, Node prototype pollution, `__NEXT_DATA__` / source-map leaks, MFA response substitution / rate limits.

## Reflection Cadence

### After every tool result

Emit one compact line before the next non-read tool call:

```text
[H] hypothesis alive? [N] next_question? [P] sibling/bypass/chain?
```

### After a primary finding is validated

Check 3-5 siblings in the same namespace; use `tools/sibling_generator.py` when path shape is regular.

### On 403 / 404 / 406 from an exposure candidate

Try a tiny stack-specific bypass set before killing the lane: Apache trailing `;`, nginx off-by-slash, IIS `~1` shortname, Node/Express `X-Forwarded-For`.

Transport hint: send raw path payloads literally with `curl --path-as-is` or Burp Repeater so clients do not normalize dot segments.

### On 3 consecutive identical-status responses on the same hypothesis

Write `[STALL] <diagnosis>`, re-read fingerprint/intelligence, then `pick_next_lane` conceptually: rotate vuln class, endpoint, or role. In Claude CLI, choose the next P1/P2 or concrete Bash probe; do not wait for a literal `pick_next_lane` tool.

### On auth-gated target (302 to /login, 401 from API)

Prompt-only path first: fetch login HTML, regex CSRF, then build `GET login → extract token → POST` before auth-file automation.

### After `run_vuln_scan`

Immediately rerun `python3 tools/surface.py --target target.com`. If Workflow
Leads include `unsafe-skipped`, read
`findings/<target>/manual_review/unsafe_skipped.txt`, checkpoint, and state that
these lanes were not tested-clean. Do not auto-run `ALLOW_UNSAFE_HTTP_TESTS=1`;
only the current operator turn can opt in.

## Question -> Tool Reference (advisory, not routing)

Lookup only. Concrete CLI commands are preferred; legacy local-agent aliases remain for discoverability.

| Question | Cheapest tool / route |
|---|---|
| Different data for user_A vs user_B? | `tools/role_diff.py` |
| JS secrets / hidden endpoints? | `run_js_read` legacy alias → `python3 tools/js_reader.py --target <target>` + `js-reader` |
| Source/recon IDOR or auth-bypass logic? | `run_source_intel` legacy alias → `python3 tools/source_intel.py --target <target>` |
| 403 header/path/method bypass? | `bypass-403` skill / `bash tools/bypass_403.sh ...` |
| OAuth callback redirect/state/session? | manual OAuth/OIDC; `tools/h1_oauth_tester.py` only for H1-compatible flows |
| Blind SSRF/XXE/RCE/SQLi callback? | `tools/oast_listen.py` |
| Race condition? | manual review; `tools/h1_race.py` only with explicit current-turn opt-in |
| Subdomain takeover? | `takeover` skill |
| Sibling endpoints / path pattern? | `tools/sibling_generator.py` |
| High-value cells untested? | `tools/coverage_matrix.py find-gaps` |
| Recent changes? | `tools/fresh_code.py` |
| Same/similar disclosed patterns? | spawn `disclosed-researcher` Task |
| JS semantic read? | spawn `js-reader` Task |
| Natural-language ranking review? | spawn `recon-ranker` Task |
| A→B chain fit? | spawn `chain-builder` Task |
| Candidate ready? | spawn `validator` Task |
| Report draft ready? | spawn `report-writer` Task |

## Finish Condition

Finish on state, not tool checklist:

- `working_hypothesis` resolved, killed, or converted to Candidate.
- Blind tests drained: `oast_listen` checked when OAST was used.
- No unresolved `unsafe-skipped` lead remains from `findings/<target>/manual_review/unsafe_skipped.txt`; if present, checkpoint instead of finishing.
- No high-value matrix gap remains: run `python3 tools/coverage_matrix.py rebuild --target target.com` and then `python3 tools/coverage_matrix.py find-gaps --target target.com`; an absent or empty matrix is not proof of coverage.
- `evidence/<target>/intelligence.md` / exposure / JS / source context consulted when available.
- `rules/coverage-gate.md` has been satisfied: covered, blocked, unknown,
  candidates, dead ends, and next actions are explicit.
- Target memory has a useful handoff or next action when the target is not
  genuinely exhausted.
- A checkpoint proposal exists: run `python3 tools/checkpoint.py --target target.com`
  and apply target memory only when the operator wants automatic write-back.

## Advanced Mode Flags

Compatibility flags: `--parallel`, `--max-parallel`, `--parallel-hypotheses`, `--vision`, `--self-review`, `--calibrate-patterns`. Use only when the current run explicitly needs fanout, screenshots, red-team review, or pattern calibration.

## Auth / Stateful Runs

```bash
python3 tools/hunt.py --target target.com --recon-only --auth-file .private/auth.json
python3 tools/hunt.py --target target.com --scan-only --auth-file .private/auth.json
BBHUNT_COOKIE='session=REDACTED' python3 tools/hunt.py --target target.com --scan-only --auth-from-env
```

Environment auth also supports `BBHUNT_AUTH_HEADER`; auth propagates into Python helpers and the shell recon / scanner toolchain where supported.

## Live-Action Boundaries

- Reports are never auto-submitted.
- Standard/quick scanner skips XSS by default; live script/HTML injection is current-turn opt-in.
- Password brute force, default credential checks, and password spray are not
  absolute red lines. They are controlled high-risk actions; `/autopilot` may
  choose them under the Credential Lane rules, with rate/lockout controls,
  audit logging, bounded inputs, and stop-on-hit.
- Payment, billing, refund, credit, wallet, coupon, cart, checkout, and fund-transfer surfaces are valid high-value lanes; avoid only real money movement or irreversible lifecycle changes unless explicitly intended.
- Order/fulfillment/delivery/shipment/booking lifecycle write actions are Leads only; do not click, replay, race, or call them from `/autopilot`.
- Mutation/state-changing operations require explicit current-turn operator intent.
- Request guard, rate limits, and cooldowns are advisory telemetry. When all
  tracked hosts are tripped, `/autopilot` must switch to `guard_safe_pivot`:
  cached evidence analysis, JS/source review, context packing, checkpointing,
  and coverage accounting. It must not suggest residential IP rotation, WAF
  evasion, or social engineering as default next steps.

## Finish Output

Use `Outcome → Key Evidence → Verification → Next Step`. Surface only decisive files, commands, status/body diffs, callbacks, candidate IDs, and evidence gaps.
