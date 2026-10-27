# Native Claude host findings

Updated 2026-10-27. Host mechanics use Claude Code 2.1.304, dummy authentication
and a never-forwarding loopback Messages API inside filesystem, PID and network
namespaces. Live behavior uses separately bounded, isolated synthetic labs and
the native CLI's existing model connection. Personal configuration/credentials
are never inspected; no real target or personal runtime is modified.

## Current integration evidence

- `/var/tmp/ccst-host-contract-chcaloub/acceptance.json`: 13 focused owner/transport
  groups passed. Includes settings ownership and interrupted-sync recovery,
  Unicode/CRLF and bounded chunks, fresh Recon, current reviews and pending owners,
  exact time/Round limits, body-before-entry and one Bootstrap, source/context
  damage, batch boundaries and resume preserving clock/limits. A real Store and
  Action claim remain usable during a real Recon phase lock plus running marker;
  another same-phase lock is refused. Background notification preserves binding
  bytes both when active and when suspended. The previous `mfudk2u_` run preceded
  this notification check.
- `/var/tmp/ccst-host-mechanics-13otpgh_/acceptance.json`: real CLI with the latest
  production body, hooks and `--max-seconds=20`. Early Stop is refused; native
  compact/restart preserve invocation/start/threshold; actual expiry releases.
  Residual-token form remains insufficient for exhaustion but retains a valid
  boundary stop. Native interrupt bypasses Stop and ordinary messages do not rearm.
- `/var/tmp/ccst-host-mechanics-aqhvu98a/acceptance.json`: current-owner boundary
  stop and compact/restart passed before the time/Round binding addition.
- Earlier native entry parity: `/var/tmp/ccst-host-mechanics-ykzramsw/acceptance.json`
  (Skill) and `/var/tmp/ccst-host-mechanics-74m33z3n/acceptance.json` (Round).
  These are mechanism evidence, not real-model investigation acceptance.
- `/var/tmp/ccst-host-mechanics-53xdvo1p/acceptance.json`: a real background Bash
  completion reaches UserPromptSubmit without suspending active Autopilot; normal
  Stop still requires the owner review, and ordinary later conversation releases.
  Discovery probes `ccst-background-native-4g8mw_g9` and
  `ccst-background-input-z9p314x6` observed the exact reserved task-notification
  envelope; the hook has no separate sender field. Recognition preserves state,
  does not authenticate a sender or revive a suspended invocation.

## Live results and corrections

- `/var/tmp/ccst-autopilot-host-live-nyfxy7wr/acceptance.json`: **failed**.
  All 48 model requests received complete entry bodies; 2 operations, 10 observations,
  2 assessments, 2 formal reports (critical/medium), 2 experiences. CLI ended at
  505 seconds before the stated 720 seconds; 51 turns, reported cost $3.652957.
  Manual reconstruction/replays and shallow method reading remain observed.
  Fixed the missing explicit-limit attainment/binding check. Supervisor duration
  includes idle cleanup and is not model execution time.
- `/var/tmp/ccst-autopilot-host-live-70sraz28/acceptance.json`: **incomplete**.
  All 75 model requests received full bodies; 23 operations, 27 observations,
  2 Finding rows (one wrong-endpoint claim withdrawn), 1 assessment, 1 formal high
  report, 1 experience. Same-execution capture/registration improved. At 843 seconds
  a valid 720-second limit review was saved, but Closure's form-insufficient view
  discarded its termination; repeated stale-digest/handoff calls consumed cleanup.
  The 900-second supervisor killed the run. There was no Stop hook or final CLI
  cost/turn receipt, so this is not an observed Stop rejection. Corrected the
  projection to retain the valid review, while exhaustion stays unavailable.
- `/var/tmp/ccst-autopilot-host-live-39yocc7w/acceptance.json`: **passed with
  limitations**, multi-asset + native interrupt/compact/restart. One Store covers
  the main domain and www/app/billing. All 31 initial requests received full entry
  bodies; all 58 resumed requests received full recovery bodies. Model invoked the
  current resume first and retained invocation/start/720-second binding. It reused
  the three saved requests after restart without sending them again, published
  two validated reports (high/medium), then registered new negative/variant checks.
  Final counts: 8 operations, 8 observations, 4 Finding rows (2 corrected/withdrawn),
  2 assessments, 2 reports, 1 handoff experience. Stop released at 752.991 seconds
  with a valid form-insufficient review and exhaustion false. CLI/supervisor exited
  0; the namespace process and gateway were cleaned up. No container was used.
  Cumulative CLI cost $7.335458; 43 turns before interrupt and 64 after restart.
  Resume restores cumulative cost, so do not add the earlier $2.516832 again.
  Its smaller $9.483168 second-process ceiling was conservative; future harness
  keeps the original total $12 ceiling. This is the CLI receipt, not relay billing.
  Initial unregistered probes, incomplete method reads and a 125-second sleep to
  hit the deadline remain. The snapshot also exposed background-result suspension,
  now fixed by the verified reserved-envelope exemption. The final command states
  that a cap is a ceiling rather than a minimum runtime, without a shell classifier.
- `/var/tmp/ccst-autopilot-host-live-aerf7kf_/acceptance.json`: **incomplete**,
  final-source fresh Juice Shop. All 120 requests received complete entry bodies.
  9 operations, 16 observations, 7 Finding rows, 6 assessments/reports, 5 memories;
  INDEX severities 2 critical / 3 high / 1 medium. At 669.715 seconds the real Stop
  rejected a premature 720-second explicit-limit claim, and the model continued.
  At 729 seconds the separate research `--max-turns=120` returned error_max_turns
  (121 turns, CLI cost $9.518) before normal release. No successful finish is claimed.
  Container/network cleanup passed. The redundant research turn ceiling is removed
  for the fresh rerun; existing $12/900-second supervision remains, not product defaults.
  Artifact hashes match, but some request/status/timestamp files were reconstructed
  after I/O; this does not prove original-wire capture or the correctness of all six
  reports. One model-created product remained until disposable-container cleanup.
- `/var/tmp/ccst-autopilot-host-live-6r623x_2/acceptance.json`: **passed with
  limitations**, fresh Juice Shop without the redundant research turn cap.
  All 100 model requests received complete entry bodies. Final 12 operations,
  38 observations, 7 Finding rows, 5 assessments/reports, 1 handoff; INDEX critical /
  high / high / medium / medium. After initial reports, the model acquired a
  controlled customer account and investigated object and review-write boundaries;
  registered cleanup readback bound the affected mutations. Normal Stop released
  at 731.103 seconds for the exact 720-second entry threshold. Closure retained
  recon residuals with exhaustion false. CLI success: 105 turns, $8.794981 receipt.
  Supervisor exit 0 and own container/network/socket cleanup passed.
  No sleep to fill the remaining limit occurred; early Recon polling still waited.
  All registered artifact bytes/hash bindings passed inspection. Initial ad-hoc
  probes, incomplete method reads and some read-only replay on registration retry
  remain limitations; no claim that all five reports received an independent audit.

Both Juice Shop runs removed their own container/network. The latest user steering
explicitly allows independent evidence-backed investigation during Recon/Scan;
only dependent work waits and final stopping collects the background result.
The earlier blanket "Recon unfinished means no testing" acceptance is superseded.
Small method-reading/format deviations are recorded, not new per-tool gates.

`live_lab.py --prepare-recovery` now runs the existing four-host synthetic lab
under the same isolation, with finite native interrupt → compact → restart/resume
stages. It sends only host/user events, records owner snapshots and full recovery
delivery, and shares the research cost allowance across both processes. It never
writes model evidence/reviews or chooses investigation. Live acceptance remains
open until the actual resulting evidence is reviewed.

Fresh and multi-asset recovery mechanics now have successful real-model examples,
alongside the retained earlier failures. Full method-consumption reliability is
still open. This does not establish comparative depth, recall quality or cost gains.

## Review and remaining boundaries

The final read-only lifecycle review found no further in-scope stop/recovery bug.
Installer review confirmed normal ownership/recovery checks but identified the
external-writer race between its final settings hash check and atomic replacement.
The existing maintenance-window contract now explicitly requires Claude/settings
editors to be quiescent. The installer lock coordinates CCST only; there is no
cross-application compare-and-swap or live-sync guarantee. Do not add a second
configuration manager to conceal this limit.

## Original host discovery

- `/tmp/ccst-host-mechanics-mwn46tut/acceptance.json`: dynamic command entry
  delivers the entire 14,084-character source; separate bounded SessionStart
  outputs deliver every original chunk after native `/compact` and `--resume`.
  The check uses source-specific recovery markers, not text retained by Claude.
  Stop blocks once, accepts the synthetic receipt, then releases. Native interrupt
  receives a successful control response and does not invoke Stop. A later ordinary
  prompt ends without the former binding intercepting it.
- `/tmp/ccst-host-mechanics-2c7dke1n/result.json`: one oversized recovery output
  does not deliver complete source. A preview/path is not complete loading.
- `/tmp/ccst-host-mechanics-dktg3ysw/result.json`: command-frontmatter Stop and
  UserPromptSubmit run; SessionStart does not. Recovery requires settings hooks.
- `/tmp/ccst-host-mechanics-4ho9w2l8/acceptance.json`: a missing dynamic source
  emits local-command-stderr and sends zero Messages requests. Claude still returns
  an empty outer `success` result; success/exit code alone is not a delivery check.

Runs before `2c7dke1n` waited only for compact_boundary rather than the following
result; they are not evidence of exact interrupt/phase ordering. The current
harness waits for result in every phase.

These results prove native transport and events, not model method use. Automatic
compaction under context pressure and managed-policy suppression remain unverified.
The fixture's deletion on every ordinary prompt is deliberately not production
policy: production retains the binding, suspends enforcement and offers an explicit
same-invocation resume before dependent work.
