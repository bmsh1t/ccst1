# Repository-root seam classification

The candidate list is classified by runtime ownership, not by the presence of
the `BASE_DIR` import bootstrap. A module is `import-only` when the constant
only makes direct script imports work; it is `narrow-root-injected` when the
runtime already accepts the exact output/input root it needs; and it is
`repo-root-dependent` when repository-relative configuration or mutable output
was previously fixed to `BASE_DIR`.

| Candidate | Classification | Runtime boundary | CLI |
|---|---|---|---|
| `browser_evidence` | `narrow-root-injected` | `load_last_browser_evidence(evidence_root=...)` | none |
| `browser_playwright_fallback` | `narrow-root-injected` | `capture_with_playwright(evidence_root=..., recon_root=...)` | existing `--evidence-root` / `--recon-root` |
| `cf_solver` | `repo-root-dependent` | `load_config`, `check_cookie`, `write_output` | `main --repo-root` |
| `cve_hunter` | `repo-root-dependent` | `hunt_cves(repo_root=...)` | `main --repo-root` |
| `hypothesis_worker` | `import-only` | `BASE_DIR` only extends `sys.path` | none |
| `json_inject_probe` | `repo-root-dependent` | `_write_findings(repo_root=...)` and input bindings | `main --repo-root` |
| `remember` | `repo-root-dependent` | validation-summary and default memory resolution | `main --repo-root` |
| `request_guard` | `narrow-root-injected` | `memory_dir` is required by preflight/record/status owners | existing `--memory-dir` |
| `resume` | `repo-root-dependent` | `load_resume_summary` / `load_pickup_summary` runtime artifacts | `main --repo-root` |
| `scanner_pass_writer` | `narrow-root-injected` | `write_scanner_pass(findings_dir, recon_dir, out_path)` | existing explicit paths |
| `sibling_worker` | `repo-root-dependent` | `run_worker(repo_root=...)` recon input | `main --repo-root` |
| `source_hunt` | `repo-root-dependent` | `_exposure_dir` / `run_source_hunt(repo_root=...)` | `main --repo-root` |
| `sql_parameter_probe` | `repo-root-dependent` | `_write_results(repo_root=...)` and cursor/plan paths | `main --repo-root` |
| `vision_browser` | `narrow-root-injected` | `find_latest_screenshot` / `list_screenshots(evidence_root=...)` | none |
| `waf_pass_plan` | `repo-root-dependent` | `_artifact_ref` / `load_plan(repo_root=...)` validation | library only |
| `zero_day_fuzzer` | `repo-root-dependent` | `ZeroDayFuzzer(..., repo_root=...)` findings output | `main --repo-root` |

`hunt.py` and `parallel_workers.py` are adapters rather than candidates. They
retain their existing `BASE_DIR` execution root and pass the selected root to
the new source-hunt and sibling-worker boundaries. No cosmetic `repo_root`
parameter was added to import-only or already-injectable modules.
