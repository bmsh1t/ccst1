# ScopeContext Owner

`tools/scope_context.py` is the single parser and classifier for active Scope
inputs. It accepts legacy text lists and schema-v1 JSON manifests, applies
`out_of_scope` before `in_scope`, and exposes a stable `scope_hash`.

- Reuse `target_paths.url_belongs_to_target()` for existing single-target,
  list, port, scheme, IP, and CIDR semantics; do not copy suffix/CIDR logic in
  active consumers.
- Keep discovered but unlisted network assets as `external-chain-context` or
  `scope-review`; only `in_scope` is executable.
- Invalid manifest/pattern input fails before network I/O. Missing/invalid
  Scope must not fall back to unrestricted matching.
- ScopeContext owns no findings, queue, checkpoint, or report lifecycle.
- Bind authentication to the selected asset and parent Scope; relationship
  evidence alone never transfers credentials or active execution rights.
- Batch child selection may carry `scope_ref/scope_hash`, but parent credentials
  are not automatically copied to sibling targets. A child must load explicit
  private auth material, and redirect handling may replay sensitive headers only
  for origins authorized by that child AuthSession.
- Include `scope_ref` and `scope_hash` in resumable batch/rotation projections;
  a changed hash cannot reuse completion proof for the new asset set.
