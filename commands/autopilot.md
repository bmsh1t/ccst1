---
description: Expert Hunter AI-first autonomous hunt loop — recon/cache state, review surface evidence, enrich with browser/source/JS, hunt, validate candidates, report validated findings, and checkpoint useful memory. Usage: /autopilot target.com [--paranoid|--normal|--yolo|--quick|--deep] or /autopilot targets.txt
---

# /autopilot
Invocation arguments: `$ARGUMENTS`

Parse arguments first. The first non-flag argument is the target, URL, IP/CIDR,
or primary-domain batch list. If no target is present, ask for the exact target.
`--deep` activates the Deep Mode section; cadence flags only affect checkpoint
frequency.

Expert Hunter Autopilot for Claude CLI. Claude is the hunter; tools are memory,
evidence, replay, and summary aids.

```text
fresh: TARGET -> RECON -> BUSINESS/CROWN JEWELS -> SURFACE/CONTEXT -> BROWSER/SOURCE/JS TRUTH -> SCANNER QUICK -> WORKFLOW -> HYPOTHESIS -> MINIMAL PROOF -> CHAIN -> VALIDATE -> RECORD/CHECKPOINT
existing: LOAD -> REVIEW EVIDENCE -> ENRICH -> HUNT -> VALIDATE CANDIDATES -> REPORT/CHECKPOINT
```

Super-pentester priority: business impact > workflow evidence > crown-jewel hypothesis > scanner/coverage hints. Scanner quick is a breadth sensor and advisory lead source; scanner-negative is not completion.
## Tool Index
Before unusual/non-default helpers, scan `docs/tool-index.md` once per session.
Canonical runtime references: `skills/runtime-protocol.md`, `rules/red-lines.md`,
`rules/coverage-gate.md`, `rules/hunting.md`, `rules/tool-ai-boundary.md`, `knowledge/index.md`,
`tools/action_queue.py`, `tools/coverage_matrix.py`, `tools/evidence_ledger.py`,
and `docs/evidence-runners.md`. These are navigation aids, not a state machine.
## Four-Layer Automation
Four-layer memory is the external brain, not the steering wheel:

```text
target memory / target case state -> skill routing -> knowledge cards -> checks
```

Fresh target startup is recon-first:

```bash
python3 -c 'from tools.runtime_config import is_ctf_mode_enabled as f; print({"ctf_mode": f(".")})'
python3 tools/hunt.py --target target.com --recon-only
python3 tools/surface.py --target target.com
python3 tools/context_pack.py --target target.com
# If app-like/SPA/auth/workflow/API surface appears, import browser MCP evidence before scanner hints dominate.
python3 tools/hunt.py --target target.com --scan-only --quick
```

Existing target startup is cache-aware:

```bash
python3 -c 'from tools.runtime_config import is_ctf_mode_enabled as f; print({"ctf_mode": f(".")})'
python3 tools/autopilot_state.py --target target.com
python3 tools/surface.py --target target.com
python3 tools/context_pack.py --target target.com
```

Refresh recon only when missing, thin, stale, or contradicted by fresh evidence.
For existing targets, run a closed-state sanity check before executing a
historical `continue_last_focus`, resume target, or `/surface` score hint:

```bash
python3 tools/checkpoint.py --target target.com --no-refresh-coverage
python3 tools/action_queue.py summary --target target.com
```

If checkpoint/action_queue show no executable next action, treat those historical
hints as context rather than commands. Re-open them only when fresh
browser/source/JS/recon evidence or business context contradicts the recorded
closure.
Use `context_pack.py` for compact route hints, `reference_hints`, and
1-2 knowledge cards / on-demand references that match current evidence. Do not let
them drive first contact. `target_case_state.py`, `case_state_seed.py`,
`checkpoint.py`, `action_queue.py`, `coverage_matrix.py`, `evidence_ledger.py`,
and `validation_runner.py` are not a pre-flight checklist; use them only when
they reduce drift, preserve actor/session/object continuity, or produce stable
evidence.

Checkpoint can emit target-memory write-back proposals:

```bash
python3 tools/checkpoint.py --target target.com
```

Review the proposal and apply target memory only when it is useful; stale/noisy
state must not block recon, browser/source enrichment, AI-selected pivots, or a
better live hypothesis.
## Authorization Posture
Treat the supplied target set as the active authorized execution set for this
run. Do not pause for routine recon/scanning/hunting authorization re-checks.
Do not require public-program, written-permission, or ownership-confirmation
text for localhost/private IP/CIDR/list inputs or lab runs; `ctf_mode` is the
authoritative lab target record. External policy stays advisory audit/replay
context, not an execution gate.
Pause only for ambiguous target identity, unavailable credentials needed for the
next step, a new target outside the supplied set, report submission, or concrete
destructive/irreversible/high-pressure side effects.
## Business Model Read
Before recon or immediately after first recon output, write/read
`evidence/<target>/business_model.md`; this points to the `agent.py` system
prompt directive without duplicating a fixed workflow taxonomy.
## Discovery / Exploitation / Validation Modes
Evidence-driven depth does not mean evidence-only testing.

- Discovery mode: when evidence is weak or surface is underexplored, actively generate new evidence from browser-observed APIs, JS/source-derived routes, cached recon, API docs/leaks, hidden parameters, path-pattern siblings, component/CVE intelligence, roles, objects, and workflow mapping.
- Exploitation mode: when a host/path/parameter/component/version/behavior signal exists, turn it into the smallest safe replay, diff, sibling expansion, bypass, OAST, CVE applicability, or chain-building step.
- Validation mode: when a Candidate exists, prove practical impact with the lowest-impact replay/diff and the `/validate` evidence rubric.

AI override is first-class: skip, reorder, combine, or invent the next action
when evidence supports it. State the reason, red-line status, next verification
step, and stop condition. Tool recommendations are advisory, not hard rails.
## Browser / Source / JS Enrichment
Prefer browser-state truth over guessed routes:

1. chrome-devtools MCP for live browser/network/console evidence.
2. playwright MCP for automated interaction and snapshots.
3. `tools/browser_evidence.py` / `playwright-cli` only when MCP is unavailable or a scriptable fallback is needed.
4. Import useful MCP artifacts with `tools/browser_mcp_import.py` so `recon/<target>/browser/`, `/surface`, `/checkpoint`, and `/autopilot` share the same browser-observed API surface.

Use `python3 tools/js_reader.py --target target.com` for JS materials and
`python3 tools/source_intel.py --target target.com [--repo-path <repo>]` for
source/route/auth logic. AI should turn these hints into concrete replay drafts,
not just tool rankings.
For byte-exact HTTP/cache/smuggling/desync work, use
`tools/sender_semantics.py --require <capabilities>` and
`tools/smuggling_executor.py --variant <variant>`; browser evidence cannot prove
wire-level absence.
## Core Decision Loop
1. Load target freshness and existing evidence; fresh targets start with recon, existing targets start with cache/state.
2. Model BUSINESS/CROWN JEWELS: actors, private objects, workflows, admin/config/payment/data flows, trust boundaries.
3. Build a surface/context evidence pack; AI chooses priority.
4. Capture real browser/source/JS/API request shapes when they can change the next test; scanner quick is only a later breadth signal.
5. Hunt one high-value hypothesis with MINIMAL PROOF; then attempt CHAIN EXPANSION through role/object/state/method/parser/cache/source/integration pivots.
6. Promote Lead -> Signal -> Candidate -> Validated Finding only with replayable evidence and practical impact.
7. REPORT/CHECKPOINT only after AI judges stronger validation/chain/coverage actions no longer outrank the pending report; never auto-submit.
## Actionable Evidence Continuation Contract
Claude must not turn an evidence-backed next step into a passive TODO. Use
`python3 tools/action_queue.py ingest-checkpoint --target target.com`,
`python3 tools/action_queue.py next --target target.com`, and
`python3 tools/action_queue.py resolve --target target.com --id <id> --status <state> --evidence <why>`
when a durable queue helps. Applies to known product/CMS/plugin/theme/library versions,
exposed routes, authz/IDOR, SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection,
parser/file/network/client/business lanes. Do not overfit this contract into a fixed checklist.
## Known Software Intelligence Lane
This is one specialization of the Actionable Evidence Continuation Contract:
when a concrete product/plugin/theme/library/version appears, it must not stop
at "needs CVE lookup." Use `python3 tools/intel_engine.py --target target.com`
and `python3 tools/cve_hunter.py target.com`, then check NVD, GitHub Advisory, WPScan/vulnerability DB, vendor changelog, and reachability (for example,
WordPress Tribe Events 6.16.3) before recording tested/dead-end/blocked/lead/signal/candidate.
## Case-State First, Not Case-State Only
If checkpoint exposes `case-state-validation` or `case-state-enrichment`, prefer
it before generic coverage gaps because actor/session/object continuity is high
value. This is not a hard rail: missing, stale, empty, or irrelevant case state
must never block discovery, browser/JS/source enrichment, surface-review hunting,
or AI-generated chain pivots. Case state is not a scope gate, permission gate,
bug-class selector, or IDOR-only workflow; AI override may pursue fresher
business-impact evidence.

Useful commands:

```bash
python3 tools/target_case_state.py summary --target target.com --json
python3 tools/case_state_seed.py --target target.com --json
python3 tools/validation_runner.py idor-actor-pair --target target.com --from-case-state
```
## Evidence Runners
For repeatable replay/diff, use `docs/evidence-runners.md` and keep the AI in
charge of interpretation. Runners should preserve raw baseline/variant evidence,
diff summaries, risk/red-line status, and stop conditions; they must not convert
weak hints into findings.
Runner labels such as `tested_clean` are execution-layer labels, not final truth;
if raw evidence or business/object/role semantics contradict the label, reopen
or upgrade the lead and record why.

```bash
python3 tools/validation_runner.py authz-public-exposure --target target.com --url <url>
python3 tools/validation_runner.py sqli-result-diff --target target.com --url '<url>' --param q --baseline-value test --variant-value '<variant>'
python3 tools/evidence_ledger.py summary --target target.com
```
## After `run_vuln_scan`
Rerun/read surface before declaring exhaustion. Inspect action-gated scanner leads,
including `findings/<target>/manual_review/unsafe_skipped.txt` and
`standard_public_metadata.txt`. Treat weak template hits as `lead`, stable diffs as `signal`,
and exact replay plus practical impact as `candidate`. Side-effect
scanner templates skipped unless `ALLOW_UNSAFE_HTTP_TESTS=1` was set, so they
are not tested-clean. If unresolved action-gated leads remain, checkpoint instead
of finishing.
## Next Action Consumption Loop
Checkpoint and memory queues are candidate sets, not orders:

```bash
python3 tools/checkpoint.py --target target.com
python3 tools/action_queue.py ingest-checkpoint --target target.com
python3 tools/action_queue.py next --target target.com
python3 tools/action_queue.py summary --target target.com
```

Read `recommended_executable_action`, `next_action_queue`, and the Memory action queue.
If coverage is near 0%, do not end with only a report suggestion, stale
queue item, or scanner summary; generate/execute the smallest safe evidence step
or write a precise blocker. Claude may skip, reorder, or override queue items
when browser/source/recon evidence shows a better move.
Final queue statuses are not immutable truth; reopen an item when raw evidence
or business context contradicts an earlier tested/dead-end/n/a label.
## Question -> Tool Reference (advisory, not routing)
This reference is advisory, not routing and not a state machine.

| Question | Cheap route |
|---|---|
| What surface matters most? | AI review over `/surface` evidence pack; `recon-ranker` may assist |
| JS secrets/endpoints/sinks? | `js-reader` Task + `tools/js_reader.py` |
| Candidate evidence enough? | `validator` Task + `/validate` |
| A -> B chain fit? | `chain-builder` Task |
| Report ready? | `report-writer` Task |
| Coverage hints still actionable? | `python3 tools/coverage_matrix.py find-gaps --target target.com` |
| Same disclosed pattern? | `disclosed-researcher` Task or knowledge card source IDs |
| Recent code/changelog activity? | `tools/fresh_code.py` |
| sibling endpoints? | `tools/sibling_generator.py` |
| Blind callback needed? | `tools/oast_listen.py` |
## Deep Mode
`--deep` is a value-first comprehensive depth flag, not a checkpoint mode.
Substantive actions are actions that add, confirm, disprove, block, or record
target evidence; do not pad the run with repeated scans or cosmetic steps.

Use `rules/hunting.md#high-intensity-hunting-posture` and the value-first
coverage model. do not lock onto authz/IDOR or any other fixed favorite class;
rotate by evidence across SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection,
unsafe deserialization, LFI/RFI/path traversal, upload/parser, OAuth/JWT/CSRF,
XSS/DOM, race/state-machine, cloud/CI/CD/secret, business logic, and known
software intelligence. Scanner-negative is only a signal to deepen manual/AI
work.

Deep Exhaustion Checklist: recon/state/surface consulted; browser/source/JS/API
context used or ruled out; scanner leads manually followed; high-value workflow
and crown-jewel hypotheses tried; coverage matrix rebuilt; Evidence Ledger /
actor matrix reviewed; unresolved actions recorded with reasons.

```bash
python3 tools/coverage_matrix.py rebuild --target target.com
python3 tools/coverage_matrix.py find-gaps --target target.com
python3 tools/evidence_ledger.py summary --target target.com
python3 tools/checkpoint.py --target target.com
python3 tools/action_queue.py summary --target target.com
```
## Credential Lane
Credential testing is controlled and evidence-driven, not a default brute-force
habit and not an absolute red line. Use it only with a concrete login endpoint,
success/failure signal, username source, bounded target-derived password set,
rate/lockout discipline, audit log, and stop-on-hit behavior. If registration
for a self-owned lab/authorized test account needs email verification, the local
helper `/root/tool/aitool/zocom/mail_receiver.py` may be used as setup aid; store
only final auth headers in `.private/` or case_state. If hygiene is missing,
record a next action instead of launching guesses or silently dropping the lane.
`/autopilot` may select this lane when evidence supports it; Password brute force, default credential checks, and password spray are not absolute red lines, and it
is not a requirement that every other lane fails first.
## Live-Action Boundaries
Canonical source: `rules/red-lines.md`. Never auto-submit reports. Avoid concrete
destructive, irreversible, high-pressure, persistent-payload, real-money,
permission, CI/CD, or real-business side effects unless explicitly intended in
the current turn. HTTP method alone is not the boundary: browser-observed POST,
GraphQL reads, search/filter POSTs, preview/validate-only flows, and test-owned
reversible actions can be valid evidence paths.
Red-line checks are narrow safety checks, not broad workflow blockers. Controlled
credential testing and OAST are not red lines when bounded; active stored XSS payload,
actions that change real account or permission state, or trigger CI/CD/deployment
side effects require explicit current-turn intent.
## Advanced Mode Flags
Compatibility flags: `--parallel`, `--max-parallel`, `--parallel-hypotheses`,
`--vision`, `--self-review`, and `--calibrate-patterns`. Use them only when
fanout, screenshots, adversarial review, or pattern calibration adds evidence.
## Finish Condition
Finish on evidence state, not a tool checklist:

- `working_hypothesis` is resolved, killed, blocked, or promoted to Candidate / Validated Finding.
- `oast_listen` is checked when blind/OAST testing was used.
- No unresolved high-value action-gated scanner lead remains; otherwise checkpoint instead of finishing.
- No unresolved AI-actionable high-value matrix gap remains after reviewing `python3 tools/coverage_matrix.py rebuild --target target.com`, `python3 tools/coverage_matrix.py find-gaps --target target.com`, checkpoint output, browser/source/JS evidence, and business context; raw matrix gaps are hints, not finish blockers, and absent or empty matrix is not proof of coverage.
- `evidence/<target>/intelligence.md`, browser, JS, source, exposure, and knowledge context were consulted when available.
- Target memory has a useful handoff when the target is not genuinely exhausted.
- A pending report is a closure asset, not a stop signal; continue hunting when stronger live evidence, browser/source leads, or high-value business workflows remain.

End with target, mode, strongest evidence, findings/candidates, blockers/dead
ends, and next best action.
