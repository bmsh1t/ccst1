# ScopeContext Owner

`tools/scope_context.py` is the single parser and classifier for active Scope
inputs. It accepts legacy text lists and schema-v1 JSON manifests, applies
`out_of_scope` before `in_scope`, and exposes a stable `scope_hash`.

For primary targets, `state/<target-key>/scope.json` is the authoritative Scope
configuration. `scope_context.py` owns validation and durable atomic publication;
it depends only on target parsing and the standard library. `scope_source.py`
provides the runtime adapter and explicit publication CLI. Store initialization
uses the lower-level Scope owner, never the Profile/runtime adapter.

The schema-v1 manifest binds `root_target` to its target and preserves
`in_scope`, `out_of_scope`, `excluded_classes`, optional `notes`/`fetched_at`, and
`recon_rps`, `test_rps`, `breaker_threshold`, `breaker_cooldown`. Unknown fields,
wrong targets, invalid patterns and non-finite/non-positive limits are errors;
the breaker threshold is integral. Low positive rates are preserved, never
silently raised to a minimum. `scope_hash` identifies classification semantics;
the publication receipt's `sha256` identifies every byte, including limits.

Fresh explicit Store initialization publishes a target-only Scope under the
same exclusive target lock before the Store becomes usable. Repeated init
validates the existing Scope and never resets it. A primary target predating
this file requires explicit publication from its reviewed manifest or exported
Profile. Missing, corrupt, wrong-target, non-private or symlinked Scope is an
error; no Profile or target-name fallback is permitted after Store takeover.
Reads create no files and do not change Store revision.

```bash
python3 tools/scope_source.py show --repo-root ROOT --target TARGET
python3 tools/scope_source.py publish --repo-root ROOT --target TARGET --manifest SCOPE_JSON --expected-sha256 CURRENT_SHA256
python3 tools/scope_source.py publish --repo-root ROOT --target TARGET --profile PROFILE_JSON --expected-sha256 CURRENT_SHA256
```

Publication requires an initialized Store and serializes on its target mutation
lock. Omit `--expected-sha256` only when explicitly creating a missing source;
replacement requires the current byte digest. Replaying already-current content
is idempotent. A corrupt regular JSON file can be explicitly repaired using its
current byte digest and a validated saved manifest. Publication uses a private
temporary file, fsync, replace and directory fsync; a pre-replace failure keeps
old bytes. Never repair a missing primary Scope by implicitly generating defaults.

The migration preview reads Scope without writing. Isolated import copies the
source Profile as a manifest-bound input and publishes its Scope separately;
the completed receipt binds `scope_sha256`. Preview publication and promotion
verify this digest before cutover. Source Profile changes are also detected by
the original input manifest. External `HUNT_MEMORY_DIR` Profile input must first
be exported into the isolated source's `hunt-memory`; it is not silently omitted.
After promotion, Profile is historical input and may be unavailable without
changing active Scope. This does not migrate its other legacy responsibilities.

`load_scope_source` first checks the complete Store/fence/receipt boundary.
Fresh targets may derive target-only Scope in memory without creating files or a
Store; an independently published Scope is validated and used as-is. Legacy
Profile input requires explicit import, so its exclusions are never silently
discarded. Preview, damaged fence or missing taken-over database fails closed.
Consumers use `load_scope_context`: Recon relations, Host verification,
Autopilot bootstrap/state, continuations and FFUF rotation share the same source.
Request-diff preflight, shared `request_once` and redirects also read this owner;
anonymous execution is subject to the same exclusions. AuthSession CLI creation,
parameter-discovery inputs/forms and scanner derived active inputs consume saved
Scope. Pass the actual repo root through every caller and preserve any narrower
AuthSession constraint supplied by the caller. Require both target ownership and
Scope permission; native post-hoc evidence registration does not
authorize a new request. External scanner execution retains its own redirect rules.
Explicit batch text/JSON files remain independent Scope inputs. Continuations
bind the parent owner and source ref; a changed classification hash rejects
reuse. FFUF selection applies exclusions before budgeting, and changed Scope
invalidates both result registration and prior completion proof.

`inspect_recon_artifacts` and its fast variant inspect raw materials without
requiring a Store. Current Finding/Action facts still require Store admission;
Surface adds structured Finding counts from its acquired owner projection.
Reading batch Autopilot state never renames legacy state/recon directories.
`migrate_legacy_list_storage` remains an explicit owner operation, used by batch
Recon execution after verifying the list identity.

`request_guard.py` reads this source for advisory telemetry, including all four
limits. Its CLI exclusions may add to, but never replace, source exclusions.
Invalid configured Scope fails before telemetry state is written. Python callers
using external telemetry storage pass `repo_root`; CLI `--repo-root` owns Scope
and the default telemetry directory. Telemetry remains advisory, not active
request admission or a guarantee that every executor enforces the rate.

- Reuse `target_paths.url_belongs_to_target()` for existing single-target,
  list, port, scheme, IP, and CIDR semantics; do not copy suffix/CIDR logic in
  active consumers.
- Keep discovered but unlisted network assets as `external-chain-context` or
  `scope-review`; only `in_scope` is executable.
- Invalid manifest/pattern input fails before network I/O. Missing/invalid
  Scope must not fall back to unrestricted matching.
- Recon relation classification and active Host verification use `ScopeContext`
  for allow/exclude decisions; a target-name fallback must not override an
  explicit exclusion. Bind paged relation candidates to `scope_hash`, and
  reject a stale cursor when either source bytes or Scope changes. Runtime
  readers must reject a published relation summary whose Scope hash no longer
  matches; Surface must not present its stale classification as a current lead.
- ScopeContext owns no findings, queue, checkpoint, or report lifecycle.
- Bind authentication to the selected asset and parent Scope; relationship
  evidence alone never transfers credentials or active execution rights.
- Batch child selection may carry `scope_ref/scope_hash`, but parent credentials
  are not automatically copied to sibling targets. A child must load explicit
  private auth material, and redirect handling may replay sensitive headers only
  for origins authorized by that child AuthSession.
- Include `scope_ref` and `scope_hash` in resumable batch/rotation projections;
  a changed hash cannot reuse completion proof for the new asset set.
