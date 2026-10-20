# CCST 补充：Flight/RSC 对象图恢复

保留此前已积累的方法及来源，不替换原版 deserialization-test.md。

### Flight/RSC object-graph revival and thenable confusion

**Recognize the boundary:** a server-side Flight/RSC decoder accepts externally
supplied multipart fields and reconstructs references between chunks, rather than
merely parsing inert JSON. Establish the actual Server Function decoding path and
its dependency/runtime versions; a React page, a response with Flight-looking
bytes, or an action header alone does not establish this input surface.

**Distinctive chain to trace in the decoder:**

1. A cross-chunk property reference can walk inherited properties instead of only
   allowed own data properties. In the reported chain, this exposes an internal
   Chunk's `then` method and a constructor-derived callable.
2. That internal method is used with a forged receiver whose `status`, serialized
   `value`, and `_response` fields imitate a decoder-owned Chunk. Trace which
   fields decide whether the runtime revives the supplied model; do not treat an
   attacker-supplied status string as proof of a genuine internal object.
3. During nested revival, a blob/form-data reference reaches `_formData.get` with
   a `_prefix`-derived argument. If both the callable and argument come from the
   forged graph, an apparent data lookup can construct code instead of retrieving
   a field. Follow the actual getter and argument, not just the outer JSON parse.
4. Promise/thenable handling can invoke the resulting callable. This automatic
   invocation is the sink to establish; obtaining a function value is not yet
   execution. An error response can occur *after* that invocation.

This is not the `node-serialize` function-string/IIFE mechanism above. Traversing
inherited properties also does **not** by itself prove prototype pollution: this
chain need not write a shared `Object.prototype` property. Keep read-side object
capability confusion distinct from pollution-write → later gadget execution.

**Evidence and controls:** within an explicitly authorized environment, retain the
actual request, session state, decoder version and server-side result. Compare a
known-valid request, a variant that breaks the relevant reference/callable link,
and a known-fixed decoder where available. Execution needs a request-correlated,
server-generated result from the reached sink, not a reflected supplied marker.
HTTP 500, a blank response, `NEXT_REDIRECT`, a digest string, or a thrown parser
error alone is not RCE. An intentionally exposed personal execution sandbox is
not evidence of unauthorized application-server execution. A failed instance does
not invalidate the method; preserve its specific version/path/runtime conditions.

**Repair boundary:** use the framework's and server-component decoder's current
fixed releases, including bundled decoder copies, and verify the same decoding
path after the update. Own-property restrictions, internal-object/type validation
and callable boundaries matter; filtering one header or one field spelling is
not a substitute. This note does not assert that every RSC deployment is affected.

**Source and limits:** the [public case report](https://jameskaois.com/posts/case-study-pre-authentication-rce-in-koacook-order-online-system-cve-2025-55182/)
and its [merged fix PR](https://github.com/KoaCook/order-online-website/pull/2)
(2026-03-21) describe command execution in a local copy of an existing application;
the PR retains the multiline PoC. This is source-reported execution, not an
independent reproduction here. Result screenshots and production exploitation
were not independently verified. The report's broader sandbox-escape, universal
middleware-bypass, persistence and lateral-movement claims are not adopted.

