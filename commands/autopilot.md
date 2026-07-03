---
description: Action-first autonomous hunt loop — load state, refresh recon only when needed, rank surface, enrich, hunt, validate candidates, report validated findings, and checkpoint. Usage: /autopilot target.com [--paranoid|--normal|--yolo|--quick|--deep] or /autopilot targets.txt
---

# /autopilot

Invocation arguments: `$ARGUMENTS`

Parse the invocation first. The first non-flag argument is the target or primary-domain batch list. If no target is present, ask for the exact target instead of guessing. `--deep` activates the Deep Mode section below.

Advanced runtime flags are supported when the CLI/runtime exposes them: `--parallel`, `--max-parallel`, `--worker-timeout-secs`, `--vision`, `--self-review`, `--calibrate-patterns`, `--parallel-hypotheses`.

`--parallel-hypotheses` may run multiple evidence-backed hypotheses in bounded parallel when supported; it does not bypass red-line or queue resolution.

Autonomous Claude CLI hunt loop:

```text
LOAD -> RANK -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT
```

Evidence drives order. Do not rerun usable recon, do not validate/report without a Candidate/Validated Finding, and do not finish while queued high-value next actions remain unresolved.

## Four-Layer Automation

`/autopilot` is the primary automated entrypoint for the four-layer system. Do not create a separate workflow command for normal use.

Startup context order: target memory + target case state -> skill routing -> knowledge cards -> red-line / coverage checks.

Minimal startup sequence:

```bash
python3 tools/context_pack.py --target <target>
python3 tools/context_pack.py --target target.com
python3 tools/autopilot_state.py --target target.com
python3 tools/target_case_state.py summary --target target.com --json
python3 tools/case_state_seed.py --target target.com --json
python3 tools/checkpoint.py --target target.com --json
python3 tools/action_queue.py ingest-checkpoint --target target.com
python3 tools/action_queue.py next --target target.com
```

- Target memory: active leads, next actions, dead ends, and handoffs influence the next lane.
- Target case state: actors, sessions, objects, private markers, active hypotheses, and validation backlog keep multi-step validation continuous.
- Skills: route through `skills/runtime-protocol.md`; load only the Skill that matches the current evidence shape.
- Use context-pack first. Knowledge: load `knowledge/index.md` plus only the 1-2 knowledge cards selected by context-pack; follow `reference_hints` only when evidence needs on-demand references, not fixed execution order.
- Checks: `rules/red-lines.md` and `rules/coverage-gate.md` are canonical. Red-line checks are narrow safety checks, not broad permission gates. HTTP method alone is not a red line; block or downgrade only the concrete destructive, irreversible, high-pressure, persistent-payload, or real-business side effect.
- Write-back: use checkpoint target-memory write-back proposals after meaningful progress; apply target memory only when the operator wants automatic write-back. Use `/retrospect` to promote reusable experience.

## Case-State First, Not Case-State Only

When checkpoint exposes `case-state-validation` or `case-state-enrichment`, prefer that actor/session/object action before generic coverage gaps because it preserves continuity across context windows.
This is a priority rule, not a restriction: empty, stale, or incomplete case state must not block discovery, recon, browser/source enrichment, ranked-surface hunting, or AI-generated chain pivots.
Use `tools/target_case_state.py next --target <target>` to inspect the backlog; run the exact `--from-case-state` replay when ready, collect missing evidence when not ready, or extend/supersede it with `add-actor` / `add-session` / `add-object` / `add-hypothesis` / `add-backlog`.
If cached artifacts show object IDs but case state is empty, run `tools/case_state_seed.py --target <target> --json` and review the suggested seed commands.
Case state is runtime memory, not a scope gate, permission gate, fixed bug-class selector, or reason to ignore non-IDOR lanes; state the AI override reason when fresher evidence should take priority.

## Actionable Evidence Continuation Contract

`/autopilot` must not turn an evidence-backed next step into a passive TODO. Concrete signals with obvious next verification questions must be executed, resolved, or precisely blocked.

This applies broadly, including known product/CMS/plugin/theme/library versions, exposed routes, browser-observed APIs, JS/source paths, hidden parameters, authz/IDOR, SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection, deserialization, LFI/RFI/path traversal, upload/parser, XSS/DOM XSS, OAuth/JWT/CSRF, race/state-machine, cloud/CI/CD/secret, business-logic leads, and login surfaces that justify Credential Lane preflight.

Decision shape:

1. Normalize evidence: exact host/path/component/request, artifact, behavior, confidence, boundary.
2. Choose the smallest safe action: lookup, replay, diff, sibling expansion, browser/source/JS enrichment, parameter discovery, CVE applicability, OAST, credential preflight, or lane rotation.
3. Execute and update state to `tested`, `dead-end`, `blocked`, `lead`, `signal`, or `candidate`.
4. If live probing is unsafe/unavailable, pivot to cached recon/browser/JS/source artifacts and record the blocker.

Do not overfit this contract into a fixed checklist. The point is to preserve AI reasoning pressure while `tools/action_queue.py` preserves state across context windows.

## Discovery / Exploitation / Validation Modes

Evidence-driven depth does not mean evidence-only testing.

- **Discovery mode**: when evidence is weak, coverage thin, or workflow unclear, actively generate new evidence from browser-observed APIs, JS/source-derived routes, cached recon, API docs/leaks, hidden parameters, path-pattern siblings, component/CVE intelligence, role/object matrices, and workflow mapping.
- **Exploitation mode**: when a concrete host/path/parameter/component/version/behavior exists, convert it into the smallest safe replay, diff, sibling expansion, bypass, OAST, CVE applicability, or chain-building step.
- **Validation mode**: when a Candidate exists, use the lowest-impact proof that establishes practical impact and passes red-line checks before report drafting.

AI override is allowed: skip a default lane, combine knowledge cards, create a new action type, or pivot modes when target evidence supports it. State reason, red-line status, next verification step, and stop condition. Tool recommendations are advisory, not hard rails.

## Run This First

Single target: `context_pack.py`, `autopilot_state.py`, and `surface.py`.
If recon is missing/thin/stale: `python3 tools/hunt.py --target target.com --recon-only && python3 tools/surface.py --target target.com`.
When ready for breadth: `python3 tools/hunt.py --target target.com --scan-only`.

After `run_vuln_scan` or any broad scan, read the surface summary again and review action-gated scanner leads / the legacy `unsafe_skipped.txt` artifact. This means side-effectful scanner templates were not run by default; it does not restrict safe observed-method replay. Entries skipped unless `ALLOW_UNSAFE_HTTP_TESTS=1` are not tested-clean; checkpoint instead of finishing when high-value skipped scanner leads remain. Also spend one secondary sweep on demoted manual-review leads such as `out_of_target_urls.txt` and `standard_public_metadata.txt`: they are not reportable findings by default, but they remain reversible chain/secret intel. For target-specific ad-hoc scripts or high-risk follow-up plans, use `templates/phased-surface-validation-plan.md`: concrete facts stay target-scoped; only abstract gates become global.

For focused high-value targets: `/autopilot target.com --deep --normal`.
For a broad scan inside that Claude CLI loop: `python3 tools/hunt.py --target target.com --scan-only --scanner-full`.

`--deep` raises persistence and high-impact lane rotation. It does not change target semantics or opt into destructive side effects, irreversible mutations, high-pressure traffic, or persistent executable payloads. Do not add `--agent` unless explicitly using the legacy local/Ollama runtime.

## Target / Lab Posture

Use the supplied target, URL, CIDR, localhost/private IP, or list input as the active execution target set. If repo `config.json` enables `ctf_mode`, that config and provided target set are the authoritative lab target record; do not require public-program, written-permission, or ownership-confirmation text as an execution blocker. `request_guard` data is advisory audit/replay telemetry, not a skip gate.

## Business Model Read

Before first fresh recon, follow the existing `agent.py` system prompt directive: ensure `evidence/<target>/business_model.md` exists or write a short business-model note. Do not duplicate the taxonomy here; this command only points Claude to the canonical directive.

## Batch List Targets

Readable file = primary-domain batch, one root/primary domain per non-comment line.

```bash
BBHUNT_BATCH_SIZE=5 python3 tools/hunt.py --target targets.txt --recon-only
```

After batch recon, continue on selected completed domains from `recon/<list-stem>/{batch_summary.md,ai_handoff.md,surface_ranking.txt,high_value_targets.json}`. Do not hunt `recon/<list-stem>/` as an aggregate target.

## Decision Loop

1. **LOAD** — autopilot state, target memory, target case state, `/pickup` if useful, `/surface`, structured findings, guard hints.
2. **RECON** — only missing/thin/stale.
3. **RANK** — use `/surface`; do not manually summarize every recon file first.
4. **ENRICH** — only when it changes the next test:
   - JS: `python3 tools/js_reader.py --target target.com`
   - source/routes/auth: `python3 tools/source_intel.py --target target.com [--repo-path <repo>]`
   - browser SPA/login/XHR: prefer chrome-devtools MCP for live network, playwright MCP for automation/snapshots; fallback to `tools/browser_evidence.py` / `playwright-cli` only when MCP is unavailable or scriptable fallback is needed; import MCP artifacts with `python3 tools/browser_mcp_import.py --target <target> --network-json <file> --url <page-url>` so `recon/<target>/browser/`, `/surface`, `/checkpoint`, and `/autopilot` share the observed API surface.
   - exposure/API leak/cloud identity: inspect relevant artifacts before broad scanning
   - known software/plugin/theme version: enter the Known Software Intelligence Lane
5. **HUNT** — scanner for breadth or exact local probe for one hypothesis; prefer role/object/method/version/body diffs. When actor/object/session state matters, register it in target case state so the next replay can be deterministic.
6. **VALIDATE** — Signal -> Candidate -> Validated Finding only with exact replay, A/B role diff, impact proof, and evidence rubric. If queue contains `case-state-validation`, run the `--from-case-state` runner path; if it contains `candidate-evidence-gap`, fill the missing proof first, then rerun `/validate`.
7. **REPORT** — draft only validated findings; never auto-submit.
8. **CHECKPOINT** — generate next actions, target-memory proposals, coverage gaps, and retrospect prompts.

## Known Software Intelligence Lane

When recon, surface, browser, JS, source, headers, CMS paths, package metadata, or errors reveal a concrete product/plugin/theme/library and version, `/autopilot` must not stop at "needs CVE lookup." This is one specialization of the Actionable Evidence Continuation Contract.

Required flow: normalize component/version, query advisory intelligence, map affected/fixed ranges, confirm reachable feature/route/precondition, run only non-destructive applicability evidence, then record `tested`, `dead-end`, `blocked`, `lead`, `signal`, or `candidate`.

```bash
python3 tools/intel_engine.py --target target.com --tech "wordpress,the events calendar,tribe events" --json
python3 tools/cve_hunter.py target.com
```

If local tools are insufficient, check NVD, GitHub Advisory, WPScan/vulnerability DB, vendor changelog, plugin readme, and nuclei template names. For example, `WordPress Tribe Events 6.16.3` should trigger version/advisory/reachability checks; a recent version is not a reason to stop.

## Checkpoint, Coverage, and Queue

Before checkpoint or finish:

```bash
python3 tools/coverage_matrix.py rebuild --target target.com
python3 tools/coverage_matrix.py find-gaps --target target.com
python3 tools/evidence_ledger.py summary --target target.com
python3 tools/target_case_state.py summary --target target.com --json
python3 tools/case_state_seed.py --target target.com --json
python3 tools/checkpoint.py --target target.com
python3 tools/action_queue.py ingest-checkpoint --target target.com
python3 tools/action_queue.py summary --target target.com
```

If `tools/action_queue.py summary --target <target>` shows active actions, do not claim completion. Execute the next safe item, or resolve it as `blocked` / `dead-end` with evidence. If high-value gaps remain, continue or state the concrete blocker.

After executing a queued action, resolve it explicitly, for example:

```bash
python3 tools/action_queue.py resolve --target target.com --id <id> --status tested --evidence "<short evidence>"
```

## Next Action Consumption Loop

Read `recommended_executable_action` and `next_action_queue` from checkpoint output, then execute or resolve the queue item before stopping. Memory action queue items are state, not prose suggestions. `case-state-validation` and `case-state-enrichment` are high-priority queue items because they encode ready actor/session/object work; they still remain advisory if new evidence justifies an explicit AI override. If coverage is near 0% or high-value gaps remain, do not end with only "Next Actions"; run the next safe step, mark `blocked`/`dead-end` with evidence, or promote `lead`/`signal`/`candidate`.

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | meaningful findings or strong partial signals | new targets |
| `--normal` | related candidates / validation batches | systematic coverage |
| `--yolo` | surface exhaustion or handoff moments | familiar targets |

Mode controls checkpoint cadence only. It must not change target semantics, inherit old skip lists, or force every stage to run.

## Deep Mode

`--deep` is a value-first comprehensive depth flag, not a checkpoint mode. It can be combined with `--normal` or `--yolo`.

In deep mode:

- Substantive actions are actions that add, confirm, disprove, block, or record target evidence; do not pad the run with repeated scans or cosmetic steps.
- Do not stop after shallow scanner-negative results or one dead lane.
- Use `rules/hunting.md#high-intensity-hunting-posture` and the value-first coverage model; rotate across access/identity, injection/RCE, server-side/file/network, client-side, business workflow, and infrastructure/supply-chain directions.
- do not lock onto authz/IDOR or any other fixed favorite class; include SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection, unsafe deserialization, LFI/RFI/path traversal, upload/parser, OAuth/JWT/CSRF, XSS/DOM, race/state-machine, cloud/CI/CD/secret, and business-logic lanes when evidence supports them.
- Browser-observed APIs, JS/source-derived routes, recon, errors, parameters, workflows, and memory are evidence sources for any bug family, not fixed priorities.
- Target case state is one runtime evidence source, not a fixed priority or IDOR-only lane; use it when it carries actor/session/object continuity, then keep rotating by current evidence.
- Convert failures into next questions: sibling expansion, bypass, role/object diff, enrichment, chain-building, or lane rotation.
- Complete a Deep Exhaustion Checklist before finish: recon/state and `/surface` consulted; coverage matrix rebuilt; Evidence Ledger / actor matrix reviewed; scanner-negative results received manual follow-up; JS/source/browser/exposure context used or explicitly ruled out; high-value vuln-family directions tested, blocked, not applicable, or listed with reasons.

Deep mode never overrides Live-Action Boundaries: destructive side effects, real-data mutations, real money/order lifecycle writes, report submission, and active stored XSS payload submission require test-owned/cleanable resources and explicit current-turn operator intent. Method is a signal, not the boundary: browser-observed POST, GraphQL read queries, search/filter POSTs, preview/validate-only flows, and test-owned reversible actions can be valid evidence paths.

## Credential Lane

Password brute force, default credential checks, and password spray are not absolute red lines. Credential testing is a controlled high-risk lane when bounded and evidence-driven.

`/autopilot` may select `/wordlist-gen -> /breach-check -> /osint-employees -> /spray` when it is a high-value route for the current evidence. This is not a requirement that every other lane fails first.

Execution hygiene:

- Login endpoint, target host, success/failure signal, username source, and password source are concrete.
- Password set is target-derived, ranked, bounded, rate-limited, audited, and stop-on-hit.
- Dry-run/pre-flight is possible; live run accounts for delay, jitter, lockout, OTP, CAPTCHA, and user impact.

If hygiene is missing, write a target-memory next action instead of silently dropping the lane or launching guesses.

## Live-Action Boundaries

Canonical source: `rules/red-lines.md`.

- Reports are never auto-submitted.
- Active stored XSS payload submission is current-turn opt-in and must use test-owned or clearly cleanable resources.
- Payment/order/fulfillment/booking/CI/CD/permission surfaces are valid high-value lanes; avoid only real money movement, irreversible lifecycle changes, change real account or permission state, trigger CI/CD/deployment side effects, destructive mutations, and persistent executable payloads unless explicitly intended.
- Otherwise use dry-run, preview, validate-only, inert markers, read-only diffs, or test-owned resources and keep hunting.
- Request guard/rate/cooldown telemetry is advisory. If all tracked hosts are tripped, pivot to cached evidence, JS/source review, context packing, checkpointing, and coverage accounting; do not default to residential IP rotation, WAF evasion, or social engineering.

## Tool Failure Discipline

A failed tool is not a failed hypothesis: classify the failure, retry once when the fix is obvious, use an equivalent helper or cached artifact, and record exact evidence gaps before rotating.

## Agent Handoff Contract

When spawning a specialist Task/agent, pass a compact packet: target identifier, target boundary, known facts, single objective, do-not-repeat list, expected output. If any field is missing, complete local context first.

## Tool Index

Before non-default helpers, scan `docs/tool-index.md` once per session. It is quick-pick context, not a state machine.

For byte-exact proxy/cache/smuggling/desync, inspect `tools/smuggling_executor.py --variant <variant>` and choose sender with `tools/sender_semantics.py --require <capabilities>`.

## Question -> Tool Reference

Advisory, not routing and not a state machine:

| Question shape | First tool/agent |
|---|---|
| Which discovered hosts/routes deserve attention? | `recon-ranker`, `tools/surface.py` |
| What APIs/routes/params are hidden in JS? | `js-reader`, `tools/js_reader.py` |
| Are sibling endpoints likely from a known path pattern? | `tools/sibling_generator.py` for sibling endpoints |
| Was this class reported publicly on similar targets? | `disclosed-researcher` |
| Is fresh code/changelog activity changing risk? | `tools/fresh_code.py` |
| Is the candidate evidence sufficient? | `validator`, `tools/validate.py` |
| Can multiple low/medium signals chain into impact? | `chain-builder` |
| Is a validated finding ready for human review? | `report-writer` |

## Finish Condition

Finish on state, not tool checklist:

- `working_hypothesis` resolved, killed, or carried forward as a concrete next action.
- Candidate validated/rejected or current hypothesis resolved.
- Blind/OAST work drained or explicitly parked: `oast_listen` has no pending callbacks or a callback wait is recorded.
- No unresolved action-gated scanner lead remains without checkpoint.
- Coverage matrix and action queue are clear or remaining matrix gap items are explicitly `blocked`, `dead-end`, `n/a`, `lead`, `signal`, or `candidate`; absent or empty matrix is not proof of coverage.
- `intelligence.md` / advisory context is consulted or explicitly not applicable for concrete component/version evidence.
- `rules/coverage-gate.md` is satisfied: covered, blocked, unknown, candidates, dead ends, and next actions are explicit.
- Target memory has a useful handoff or next action when the target is not genuinely exhausted.

## Finish Output

Use `Outcome -> Key Evidence -> Verification -> Next Step`. Surface only decisive files, commands, status/body diffs, callbacks, candidate IDs, and evidence gaps.
