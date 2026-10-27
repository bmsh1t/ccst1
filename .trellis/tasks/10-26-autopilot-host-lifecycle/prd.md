# Autopilot Claude host lifecycle integration

## Goal

Make the existing parent-session Autopilot receive complete investigation
instructions, recover current work and check a normal stop, without replacing
6k methods or the existing evidence/memory owners.

## Requirements

- Preserve `/autopilot TARGET`, its fixed scope, fresh Recon and prior-work recovery.
- Complete entry/recovery body delivery; descriptions and previews do not qualify.
- Preserve capture/registration, validation/publication and report-then-continue.
- Reports, checkpoints, handoffs and an empty owner list are not stop conditions.
- Preserve user interruption and explicit limits; no default investigation cap.
- Recon may run alongside independent evidence-backed investigation. Wait only for
  dependencies; collect background results before final stopping.
- Prioritize practical continuation, evidence and recovery failures. Record minor
  procedural deviations without making them release-blocking or adding gates.
- Keep one investigation loop and the existing Store/Checkpoint owners.
- Keep natural-language Skill discovery and optional specialist review.
- No 6k edits without separate approval; preserve pre-existing WIP journals.
- No reading/searching/modifying/running `tests/`, real target data, personal
  settings, credentials or prior model conversations; use synthetic fixtures.

## Acceptance Criteria

- [x] Git checkpoint before new implementation: `e7f6b3d`.
- [x] Real installed Claude receives complete content against a loopback fake API,
  with isolated HOME/config/filesystem/network and dummy credentials.
- [x] Native resume/compact, hook scope, size boundaries, normal stopping and
  interruption/new-prompt behavior are demonstrated.
- [x] Entry integration consumes current owner facts; missing host context is
  explicit; no duplicate lifecycle or model loop.
- [x] Known unfinished work prevents false completion; user interruption works.
- [x] Registration recovery does not replay network effects in the tested
  multi-asset restart: three captured requests were reused for validation.
- [ ] Equivalent local-lab runs demonstrate method use, write-back and continued
  investigation across fresh, multiple-asset and recovered contexts.

## Notes

- Architecture reviewed in conversation, approved with “先git保存然后开始”, followed
  by “继续” after task-creation consent was requested.
- Host wiring evidence and live model behavior acceptance remain separate.
- Current evidence: `research/host-findings.md`. Multi-asset restart demonstrated
  saved-request reuse, publication and new registered controls after reports.
  Full method-consumption acceptance remains open; initial unregistered probes and
  incomplete method reading still occur. The user's practical-priority steering
  defers those protocol deviations without adding per-tool gates or editing 6k.
