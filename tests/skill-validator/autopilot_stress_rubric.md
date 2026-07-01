# /autopilot Stress Run Rubric

This rubric turns Phase 4 pressure testing into objective evidence review. A
run is not accepted because it "looks fine"; it passes only when the artifacts
below can be inspected by a human and by `check_autopilot_run.py`.

## Required artifacts

For target `<target>` with storage key `<target_key>`:

- `state/<target_key>/session.json`, `checkpoint.json`, or `autopilot_run.json`
  records context-pack use, selected skill, and route detail.
- `state/<target_key>/action_queue.json` records executable next actions and
  at least one resolved/final item.
- `memory/evidence/<target_key>/ledger.jsonl` records raw request/response,
  capture, or replay evidence references.

## Four hard assertions

1. **Context-pack route is recorded**
   - Evidence must show `tools/context_pack.py` or a structured `context_pack`
     object was used.
   - The same run artifact must expose `selected_skill` and either
     `knowledge_cards` or `reference_hints`.

2. **At least one action is executable**
   - `action_queue.json` must contain at least one item whose `action`,
     `command_hint`, or `recommended_executable_action` is a script/command,
     for example `python3 tools/...`, `curl`, `playwright-cli`, `ffuf`, or
     `semgrep`.
   - Natural-language TODOs alone do not pass.

3. **Evidence path is traceable**
   - `ledger.jsonl` must contain at least one entry with `evidence_ref`,
     `raw_endpoint`, `raw_request_path`, `raw_response_path`, capture path, or
     equivalent raw artifact pointer.
   - A summary without raw evidence does not pass.

4. **Queue resolution and stop condition are explicit**
   - At least one action must be resolved to a final status:
     `tested`, `dead-end`, `blocked`, `validated`, `reported`, or `n/a`.
   - Any high-risk lane item (RCE, SSRF, cache, smuggling, race, upload
     execution, deserialization, command injection, SSTI, XXE) must have a
     non-default `stop_condition`.

## Machine check

Run after each pressure test:

```bash
python3 tests/skill-validator/check_autopilot_run.py --target <target>
```

Optional JSON output:

```bash
python3 tests/skill-validator/check_autopilot_run.py --target <target> --json
```

All four checks must pass before a Phase 4 run can be summarized as an
`/autopilot` chain pass. If any check fails, record the specific gap and return
to Phase 1-3 instead of manually declaring success.
