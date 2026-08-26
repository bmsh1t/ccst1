# Skill A/B Metrics

`ab_runner.py` is the narrow data and statistics layer around the existing
`web2_vuln_ab_eval.py`. It does not invoke a model or create a second evaluator.

Each JSONL row represents one case, arm, and repetition:

```json
{
  "case_id": "CASE",
  "condition": "skills_off",
  "rep": 1,
  "verdict": "safe",
  "oracle_status": "passed",
  "oracle_label": "safe",
  "turns": null,
  "tokens": null,
  "cost_usd": null,
  "duration_ms": null
}
```

`skills_off` and `skills_on` are the only arm names. `oracle_label` is the
case truth; `oracle_status` is the state of the oracle and must be `passed`
for TPR/FPR. Failed, unknown, unavailable, and invalid oracle rows remain in
the invalid report and are excluded from metrics. `rep` pairs only the same
case and repetition across arms.

The scorer is intentionally binary: verdicts must map to the existing safe /
vulnerable aliases. Existing triage or other multi-class evaluators remain
separate and are not silently coerced into TPR/FPR.

Offline fixture summary:

```bash
python3 tests/skill-validator/ab_runner.py \
  tests/skill-validator/cases/ab_metric_fixture.jsonl --json
```

Use `--strict` for a CI/evaluation gate. It returns exit code `2` when rows are
invalid or a case/repetition is missing one arm. Paired resource deltas are in
`paired_metrics` and per-pair `metric_delta` fields; positive values mean the
Skills-on arm used more of that resource.

## Claude CLI collection

`ab_collect.py` is the thin Claude CLI adapter. It uses the native JSON result
and structured-output schema, writes only verdict/metric rows, and stores run
provenance in a sidecar manifest. It never stores the model's full response or
writes project target state. The collector requires a staged HOME so it cannot
silently use the real `~/.claude`:

```bash
python3 tests/skill-validator/ab_collect.py CASES_JSONL \
  --output AB_ROWS_JSONL \
  --home STAGED_HOME \
  --model MODEL \
  --tools "" \
  --repetitions 3

python3 tests/skill-validator/ab_runner.py AB_ROWS_JSONL --strict --json
```

The case file is JSONL with one binary task per line:

```json
{"case_id":"CASE","prompt":"Return the fixture decision.","oracle_label":"safe","oracle_status":"passed"}
```

Both arms share model, tools, settings, permission mode, task, budget, and
repetition. `skills_off` adds only Claude's `--disable-slash-commands` flag;
`skills_on` leaves that flag out. `--dry-run` prints the two argv shapes without
invoking Claude or writing output.

The collector is for binary capability/FP-control cases. It is not a replacement
for the existing deterministic Web2 evaluator or the recorded triage
multi-class A/B reports.
