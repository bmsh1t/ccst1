# Rule Index

This index is the loading contract for the current project. The rule files are
the source of truth; commands and Skills only route to them.

## Default Read

Load these for every complex task or context pack:

- `rules/context-loading.md` — minimal context assembly.
- `rules/red-lines.md` — action side-effect decisions.
- `rules/coverage-gate.md` — coverage states and completion claims.

`tools/context_pack.py::_required_checks()` owns this default list.

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
| `red-lines.md` | `tools/evidence_ledger.py` |
| `coverage-gate.md` | `tools/coverage_matrix.py` |
| `hunting.md` | `skills/bb-methodology/SKILL.md` |
| `playbook-router.md` | `tools/context_pack.py` |
| `reporting.md` | `skills/triage-validation/SKILL.md` |
| `retrospective.md` | `commands/retrospect.md` |
| `tool-ai-boundary.md` | `skills/runtime-protocol.md` |
| `web-intel.md` | `tools/web_intel_artifact.py` |

When a contract changes, update its owner and this index in the same change.
