# Implementation and verification

1. [x] Review and commit prior product changes as `e7f6b3d`; preserve CRLF and
   exclude the two pre-existing `.trellis/workspace/Codex/` edits.
2. [x] Record reviewed requirements/design and curate spec context.
3. [x] Build a research harness with real Claude CLI 2.1.304, inert synthetic
   commands/hooks, dummy-auth loopback API and filesystem/network isolation.
4. [x] Probe initial body and relative paths; Stop block/release and ordinary next
   turn; native compact/resume; missing/oversize content; native user interrupt.
   Store synthetic evidence and assertions in the isolated temporary directory.
5. [x] Freeze the production integration from proven/unsupported host behavior.
6. [x] Implement entry/recovery/stop through existing owners; update callers and
   remove superseded duplicate guidance in the same diff.
7. [x] Verify owner behavior with isolated assert checks outside `tests/`, including
   unchanged 6k bytes, explicit limits, claims and evidence-only recovery.
8. [ ] Run equivalent local-lab Claude acceptance; review the complete task diff.
9. [x] Update focused contracts, save completed engineering scope and record limitations.

Engineering scope has passed targeted owner/native-host checks and a full diff
review. Fresh and multi-asset recovery live runs each have a successful example;
earlier failures remain recorded. Step 8 remains open for method-consumption
reliability: initial ad-hoc probes/partial reading still occur and are deferred
under the user's practical-priority instruction. Save completed engineering work
without declaring the whole task complete or archiving it.

Run one relevant focused check per change; broaden for actual cross-owner risks.
Never access project `tests/`, real targets or personal settings. The Phase 1 fake
API never forwards traffic. Paid live calls are a later measured acceptance step,
not a product default budget. Preserve the unrelated journals throughout.
