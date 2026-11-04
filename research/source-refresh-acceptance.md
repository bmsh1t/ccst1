# Source refresh acceptance — 2026-11-04

Ordinary source edits no longer require an identical installed Hook digest.
The existing host delivers current complete bodies on entry and through numbered
body commands on continuation. Original target, memory, pending work, start time
and limits are retained; a changed body renews the Stop review identity.

This changes three production modules, with no protocol version, migration table,
new controller or target schema. Hook shape/ownership, session/checkout identity,
snapshot integrity and undelivered entry/frontmatter still receive checks.

## Verification

`python3 -I research/verify_autopilot_continuity.py` passed. It checks real temporary
source changes against an old installed digest, legacy snapshots, complete body
equality, completed/suspended continuation, compact/restart, ordinary questions,
old review invalidation, original limits and memory. Missing Hooks, damaged
snapshots, changed entry configuration and modified/unowned installed resources
are refused. An injected failure after new snapshot publication leaves the old
binding and source usable; retry succeeds without resetting the allocation.

`python3 -I research/native_continuity_acceptance.py` passed with Claude Code
2.1.318: seven phases, 35 scripted local API calls, 23.421 seconds, $0 provider cost.
The harness installs once, then changes only a separately mounted synthetic
runtime-protocol copy before entry, continuation, manual compact, restart and
post-restart continuation. Unique source hashes and full numbered body equality
prevent older history from satisfying the delivery assertions.

| Phase | Complete current source | Stop block / release; result line |
| --- | --- | --- |
| entry | Five current parts in the actual API request | 28 / 35; 36 |
| question | No execution tool; remains completed | release 42; 43 |
| continue | Five body commands returned by Refresh, each checked in its current tool result | 61 / 68; 69 |
| compact | Real manual boundary at line 91 | no Stop; 94 |
| after_compact | Five SessionStart parts and five Refresh body results | 112 / 119; 120 |
| question_restart | Five current SessionStart parts; no execution tool | release 144; 145 |
| continue_restart | Five fresh body command results after a further edit | 163 / 170; 171 |

Evidence is in `/tmp/ccst-native-continuity-c4r1hlm5/`; line numbers above refer to
`visible.jsonl`. `timeline.json` records source changes and delivery, while
`result.json` records phase steps, source digests, retained ownership and provenance.
The 423 staged source files and harness match their manifests after the run; only
the declared synthetic protocol overlay changes. The source is the working-tree
patch over `aec46d4`, not the unmodified commit. The manifest SHA256 is
`db2d1238a1959d0fb770cbb0c26ac206b8c2b958f09bd02247416a0328fcae2c`.

An earlier native attempt exposed Claude's large-output preview when full source
was embedded in state JSON. The final implementation uses the already existing
numbered `body` commands instead. Independent review also identified the snapshot
commit interruption and entry-configuration boundaries; both were fixed and the
final focused review found no further issues in those paths.

## Limits

This verifies real CLI transport and hooks under scripted actions, not autonomous
model decisions. Compression is manual; scripted token usage is not a compression
or billing measurement. No real target, personal runtime, credentials or project
tests were read or changed; no paid model, full test suite or runtime installation
was run. The known CPU/RSS concern is a separate investigation.

Snapshots use immutable content-addressed files so a failed binding write cannot
destroy the previous source. Earlier `context.json` remains readable. This does
not promise a cross-file transaction or power-loss durability, and no snapshot
cleanup service is added.
