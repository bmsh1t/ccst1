# Repository-Root Seam Design

## Seam Definition

A module needs work only when runtime behavior directly derives a configuration,
input artifact, private artifact, or mutable output from module-level `BASE_DIR`
and the caller cannot replace that root.

The following do not by themselves require changes:

- adding the source root to `sys.path` for direct script execution;
- an existing explicit `evidence_root`, `recon_root`, `memory_dir`, scratch, or
  output-directory parameter;
- pure formatting of a caller-supplied absolute path.

## Implementation Pattern

Use the existing local style:

```python
def operation(..., repo_root: str | Path = BASE_DIR):
    root = Path(repo_root)
    ...
```

The CLI adds `--repo-root` only if it owns repository-relative path selection
and passes the value into the importable function. Defaults remain `BASE_DIR`.
Do not place a root in global mutable state and do not thread it through helpers
that already receive all required paths.

Likely genuine dependencies include configuration/output behavior in
`cf_solver`, `cve_hunter`, `json_inject_probe`, `remember`, `resume`,
`sibling_worker`, `source_hunt`, `sql_parameter_probe`, `waf_pass_plan`, and
`zero_day_fuzzer`; implementation must confirm each before editing. The remaining
candidates are retained in the classification test to prevent assumption drift.

## Testing

Use synthetic artifacts under `tmp_path`. For each changed public boundary:

1. Seed only the files required beneath the temporary root.
2. Invoke the importable function or CLI with the explicit root.
3. Assert returned references and written files resolve beneath that root.
4. Snapshot relevant source-checkout artifact paths before/after when a write is
   possible.

Avoid a brittle test that merely searches for the text `repo_root`.

## Compatibility And Rollback

Optional parameters are appended or keyword-only. Existing defaults and output
schemas do not change. Each module and its focused test can be reverted
independently.
