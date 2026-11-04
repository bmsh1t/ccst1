# Native continuity acceptance — 2026-11-04

Seven scripted phases passed through the real Claude Code CLI and project hooks.
This proves host transport, Stop enforcement and state/memory continuity for the
specified actions. It does not prove autonomous model judgment or investigation depth.

## Reproduce

Run from the repository, with Python 3, Git, `bwrap`, `setpriv` and `claude` installed:

```sh
python3 -I research/native_continuity_acceptance.py
```

The outer entry stages tracked working-tree source into a temporary directory,
records its manifest and harness hash, and runs the CLI against a scripted
loopback API. It uses a dummy key and makes no paid inference calls. Do not invoke
the internal `--inside` or `--review` entries on the host; they require isolation.

## Recorded run

- Product commit: `8008c73b2c04b546e8e91a5ab180f154929de68e`.
- CLI: Claude Code `2.1.317`; 423 staged source files; staged hashes unchanged.
- Duration: 18.034 seconds; 20 scripted API requests; provider charge: $0.
- Full temporary artifacts: `/tmp/ccst-native-continuity-c0y6g5a7/`.
- [Saved result and event excerpt](native-continuity-result.json) retain source
  provenance, original artifact hashes, phase bindings and decoded Stop outputs.
  Line numbers below refer to that run's `visible.jsonl`, not the saved excerpt.
- [Harness](native_continuity_acceptance.py) is independent of the old research
  helpers and does not use the repository's `tests/` directory.

| Phase | Observed behavior | Stop block / release; result line |
| --- | --- | --- |
| `entry` | Pending local Action prevents `no_worthwhile_work`; a current `scope_boundary` review releases Stop. | 28 / 35; 36 |
| `question` | Scripted explanation uses no execution tool; binding stays completed. | release 42; 43 |
| `continue` | Current prompt's Refresh reopens; old invocation review is rejected; a new review releases Stop. | 51 / 58; 59 |
| `compact` | Same-process manual `/compact` emits a real boundary at line 81; completed stays inactive. | no Stop; 84 |
| `after_compact` | Explicit continuation restores memory, renews invocation and requires a new review. | 92 / 99; 100 |
| `question_restart` | CLI exits and a new process uses `--resume`; scripted explanation stays completed. | release 124; 125 |
| `continue_restart` | Explicit continuation after restart restores memory and rejects the old review. | 133 / 140; 141 |

All four work phases reached step 5, after fresh review and successful release.
Their Stop block/release events have distinct hook IDs. Hook `outcome=success`
alone is insufficient: a block also has that outcome; `stdout.decision` is checked.

Across all phases, the Store binding and revision 9 remain unchanged. The original
start time, `max_seconds=600`, unset Round cap, arguments and target are retained.
Three completed reopens renew only the invocation used to bind the review.
Entry and continuation reads retain the active goal, full `initial-handoff`, its
`conditions`, `reopen_when`, `next_intent`, and the Store source binding. Six newer
notes deliberately push the handoff outside the recent-five window.

## Harness review and corrections

An independent read-only review found two possible future false positives in the
initial harness: a phase could end successfully before reaching fresh review,
and a rejection phrase could be found in older messages. The initial run's real
events nevertheless contained all four fresh blocks and releases.

The saved harness now requires step 5, checks this phase's two Stop events, and
checks the latest API feedback against the current session, invocation and target.
It also asserts the structured memory conditions and records source provenance.
Two intermediate runs failed because the new parser assumed the visible log's
`Stop hook feedback` envelope; the actual API uses `Stop hook blocking error from
command`. Fixing that parser produced the successful run above. Neither failed
run established a product failure.

## Isolation and limits

The run has independent network/PID/IPC namespaces, temporary HOME and `/tmp`,
UID/GID 65534, dropped capabilities, read-only source directories and no MCP or
Chrome. Only synthetic local fixture state is created. Personal runtime,
connection configuration, real target state and workspace journals are not read
or changed. Nothing is pushed or installed into the personal runtime.

The API chooses every action and summary. Consequently this run does not show
that a model distinguishes questions from continuation, selects a useful next
step, interprets memory conditions, judges remaining work, or stops correctly on
its own. The CLI is real; the model behavior is scripted.

Compression was manual (`trigger=manual`), with scripted usage (`pre_tokens=5020`,
`post_tokens=17368`). These values cannot measure compression efficiency or model
billing. Automatic compaction under real context pressure, interruption recovery
and real-model stopping behavior remain unverified in this run. A further paid
sample is pending a new budget; the previous allocation is exhausted.

The earlier 200k trajectory showed one actual Stop rejected for runnable owner
work; several earlier statements merely contemplated ending. That sample does
not establish the cause of the user's first premature stop. No attack methods,
6k routing or product lifecycle logic were changed during this harness work.
