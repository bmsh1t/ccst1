---
description: Prepare public identity materials with an optional OSINT helper or selected upstream tools. Usage: /osint-employees TARGET
---

# /osint-employees

Use existing reviewed usernames when available. For a remaining identity question,
select public sources or one upstream collector such as theHarvester/CrossLinked.
Check installed help, select sources/budget and retain URLs, dates, raw output and
exit status. This command prepares evidence without a login attempt.

The optional `tools/osint_employees.sh` helper retains theHarvester, opt-in
CrossLinked and offline username/pydictor expansion. Its original options remain;
`--emails-file FILE`, `--names-file FILE`, `--skip-harvester` and `--skip-usernames` allow local material
without a collector. `--repo-root` controls the target artifact root and
`--timeout` bounds each stage. Missing optional tools retain other sources with
an unavailable/partial receipt rather than erasing the collected material.
Each `osint/runs/` directory keeps raw collector files, argv, stdout/stderr,
exit status and a dated summary; existing latest material names stay available.
`observed-names.txt` and `inferred-names.txt` distinguish source observations
from email-pattern guesses. Neither confirms an application account.

Keep public observations, inferred names and username permutations separate under
canonical recon/<target-key>/osint/. Native reasoning can derive observed formats;
username-anarchy is optional for selected offline expansion. A public email does
not confirm an application account; its local-part does not establish a person's name.

Use [Direct upstream execution](../docs/tool-index.md#direct-upstream-execution)
for path/Scope conventions. Pass reviewed inputs and confirmed/inferred counts to
the credential decision package; existing /spray contracts handle live authentication.
