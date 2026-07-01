# Phase 5 Arsenal Load Check

Date: 2026-07-01

## Decision

Do not slim `skills/security-arsenal/SKILL.md` in this iteration.

`autoplan.md` defined Phase 5 as conditional: only slim the arsenal Skill if
`/autopilot` pressure testing shows it is still loaded by default, adds context
cost, or causes routing drift. That trigger did not fire.

## Evidence

`tools/context_pack.py` currently limits automatic `selected_skill` choices to:

```text
bb-methodology
bug-bounty
triage-validation
web2-recon
web2-vuln-classes
```

`security-arsenal` is not in `SKILL_PATHS`, so `context_pack` cannot select
`skills/security-arsenal/SKILL.md` as the default runtime Skill.

Concrete payload/bypass detail now flows through the smaller on-demand
reference hints:

```text
skills/security-arsenal/references/bypass-patterns.md
skills/security-arsenal/references/payload-families.md
skills/security-arsenal/references/recon-tool-usage.md
skills/security-arsenal/references/sink-and-grep-patterns.md
```

These references are emitted only when the focus/evidence lane asks for them.

## Regression guard

Added a focused regression:

```text
tests/test_context_pack.py::test_context_pack_never_defaults_to_security_arsenal_skill
```

The test locks the intended contract:

- arsenal remains an on-demand/manual deep-dive layer
- `/autopilot` default context routing stays compact
- future edits cannot silently add `skills/security-arsenal/SKILL.md` back into
  automatic `selected_skill` routing

## Conclusion

Phase 5 is closed by evidence, not by another refactor. Slimming the arsenal
Skill now would be optimization for its own sake and would not improve the
current `/autopilot` runtime path.
