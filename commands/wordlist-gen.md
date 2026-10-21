---
description: Prepare a credential candidate pool with optional wordlist helper or upstream tools. Usage: /wordlist-gen TARGET [SEED_FILE]
---

# /wordlist-gen

Prepare candidates when the selected login question warrants them. Use known test
accounts, observed defaults, reviewed seeds or relevant brand/business terms.
Keep source and uncertainty; website, Hashcat, pydictor and HIBP are optional inputs.

Read existing materials natively. Invoke cewler/CeWL only for deliberately selected
in-scope pages; upstream Hashcat --stdout with a chosen seed/rule or pydictor can
provide useful offline variations. Check installed help and bound output cost.
Missing optional tools leave that source unavailable.

`tools/wordlist_engine.sh` remains an optional batch helper with its original
depth/mode/filter/length/rate options. Use `--seed-file FILE --skip-crawl` for
selected local inputs, `--skip-brand` to omit brand expansion, `--skip-hashcat`
to omit mutation, and `--rule-file`
for an explicitly selected Hashcat rule. `--repo-root` fixes output ownership
independently of the current directory; `--timeout` bounds each upstream stage.
The original website/brand recipe is a convenience, not a required method chain.
Each run retains source output, argv, stdout/stderr and exit status under
`wordlists/runs/`; latest files retain compatibility paths and prior bytes are
saved with the run. Exit 2 means empty/unavailable/partial material. `ranked.txt`
is a compatibility alias of the pool, not a ranking or an approved shortlist.

Preserve source-specific output and stable exact deduplication in private files under
recon/<target-key>/wordlists/; compute the key with tools/target_paths.py.
candidate-pool.txt is review material. No synthetic ranking turns it into live input.
Optional /breach-check enriches reviewed candidates and retains unknown counts.

For a selected credential experiment, the AI writes finite spray-shortlist.txt and
matching spray-shortlist.jsonl required by /spray, with reasons/provenance per entry.
Existing shortlist, dry-run, lockout, request, stop and evidence contracts remain in
agents/credential-hunter.md and skills/src-hunter/modules/credential-attack.md.
