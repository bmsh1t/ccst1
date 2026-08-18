# Session Journal - Codex (Part 2)

## Session 70: On-demand Intel advisory expansion

**Date**: 2026-08-18
**Task**: Enable on-demand Intel advisory expansion
**Branch**: `main`

### Summary

Kept `intel-review.json` bounded while exposing omitted component groups and a
read-only cursor query over the complete Intel owner. Added representative-first
group review, Queue-owned closure, owner-refresh reactivation, compact Autopilot
routing and operator documentation.

### Git Commits

| Hash | Message |
|------|---------|
| `6a46c93` | feat: enable on-demand intel advisory review |

### Testing

- [OK] 413 related Intel, Autopilot and Checkpoint tests
- [OK] Python compilation and `git diff --check`

### Status

[OK] **Completed and pushed to `ccst1/main`**
