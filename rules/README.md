# Rule Index

This index is the loading contract for the current project. The rule files are
the source of truth; commands and Skills only route to them.

## Default Read

Claude Code already loads the action-safety rule through `CLAUDE.md`. The
context pack adds only route-specific checks:

- `rules/context-loading.md` — minimal context assembly.
- `rules/coverage-gate.md` — coverage states and completion claims.

`rules/context-loading.md` is loaded by the entrypoint as the assembly contract;
`tools/context_pack.py::_required_checks()` owns the runtime execution checks
and does not repeat the assembly rule.

## On-Demand Read

- Hunt or Autopilot: `rules/hunting.md`.
- Tool orchestration or AI priority decisions: `rules/tool-ai-boundary.md`.
- Evidence-shaped Web signal: `rules/playbook-router.md`.
- Web intelligence or advisory research: `rules/web-intel.md`.
- Candidate validation or report preparation: `rules/reporting.md`.
- Session review or reusable-knowledge promotion: `rules/retrospective.md`.

The entrypoint that starts the workflow must name the on-demand rule before
execution; `/context-pack` must not load `rules/hunting.md` unless the route
explicitly requests it.

## Semantic Owners

Each rule has one semantic owner. Other files may reference or enforce the
contract, but must not redefine it.

| Rule | Owner |
|---|---|
| `context-loading.md` | `tools/context_pack.py` |
| `red-lines.md` | `CLAUDE.md` loads it; `rules/red-lines.md` owns the semantics |
| `coverage-gate.md` | `tools/coverage_matrix.py` |
| `hunting.md` | `rules/hunting.md` |
| `playbook-router.md` | `tools/context_pack.py` |
| `reporting.md` | `rules/reporting.md`; report rendering: `skills/report-writing/SKILL.md` |
| `retrospective.md` | `commands/retrospect.md` |
| `tool-ai-boundary.md` | `rules/tool-ai-boundary.md` |
| `web-intel.md` | `tools/web_intel_artifact.py` |

When a contract changes, update its owner and this index in the same change.
