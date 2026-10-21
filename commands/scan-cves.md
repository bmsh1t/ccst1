---
description: Select a reachable advisory and invoke upstream Nuclei directly with an explicit template and bounded input. Usage: /scan-cves TARGET_OR_INPUT [--recon RECON_DIR]
---

# /scan-cves

Start from the observed product/version, deployed entry and current advisory sources.
Use /intel when applicability is unknown. Select a reachable CVE/template and its
actual target URLs; a year or severity label does not select an applicable test.

Use the installed upstream CLI directly. Check its local help and selected template,
then retain command/version, exact template, input, raw JSONL, logs and exit status
under the target's findings directory. Shared Scope/Auth and artifact conventions
are in [Direct upstream execution](../docs/tool-index.md#direct-upstream-execution).

After selecting TEMPLATE_PATH, TARGET_URL and a new private RUN_DIR:

```bash
nuclei -u "$TARGET_URL" -t "$TEMPLATE_PATH" -dr -duc -jsonl -o "$RUN_DIR/nuclei.jsonl"
```

Choose rate, concurrency and timeout from the selected target/template. For several
entries prepare an explicit short input list. Updates are explicit maintenance.
Log4j or another specialist scanner is an alternative when it answers the current
question, without an automatic second scan.

An upstream hit is unassessed evidence. Verify affected version, reachability,
controls and practical impact with the smallest discriminating experiment. Preserve
partial output on failure; missing tools, nonzero exits and empty output do not prove
clean coverage. The integrated vuln_scanner.sh entry separately reports its bounded
origin execution and residuals.
