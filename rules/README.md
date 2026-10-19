# Rule Index

This index is the loading contract for the current project. The rule files are
the source of truth; commands and Skills only route to them.

## Default Read

Claude Code already loads the action-safety rule (`rules/red-lines.md`) through
`CLAUDE.md`; it is resident on every session and takes precedence over the rules
below. The context pack adds only route-specific checks:

- `rules/context-loading.md` — minimal context assembly.
- `rules/coverage-gate.md` — coverage states and completion claims.

`rules/context-loading.md` is loaded by the entrypoint as the assembly contract;
`tools/context_pack.py::_required_checks()` owns the runtime execution checks
and does not repeat the assembly rule.

## On-Demand Read

- Hunt or Autopilot: `rules/hunting.md`.
- Tool orchestration or AI priority decisions: `rules/tool-ai-boundary.md`.
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
| `reporting.md` | `rules/reporting.md`; report rendering: `skills/src-hunter/modules/report-writing.md` |
| `retrospective.md` | `commands/retrospect.md` |
| `tool-ai-boundary.md` | `rules/tool-ai-boundary.md` |
| `web-intel.md` | `tools/web_intel_artifact.py` |

When a contract changes, update its owner and this index in the same change.

Web 方法与信号索引迁至 `knowledge/playbooks/web2-evidence-contracts.md`，按信息缺口读取；不再作为 Context Pack 的公共必读检查。
