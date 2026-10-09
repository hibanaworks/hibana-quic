# Open release requirements

The latest published recovery change still has one failed official
handshakeloss case. Exact results and prior successful baselines are recorded
in QUALIFICATION.md; results from different commits are not combined.

Before claiming public release quality:

- Reproduce and diagnose each handshake-loss failure on actual peers. Preserve
  deadlines, loss conditions, authenticity and physical completion semantics.
- Finish repository/documentation cleanup and requalify the exact resulting
  commit, including all 44 candidate case/direction cells.
- Extract TLS into an independent hibana-tls dependency with no QUIC/HTTP3
  backreferences. Its initial building blocks are not a TLS replacement yet.
- Eliminate non-Hibana production dependencies in staged, independently checked
  changes. Preserve no_std, no_alloc, trust checks and proof scope throughout.
- Provide complete application choreography examples for request/reply,
  parallelism, streaming and cancellation. Internal descriptor transport is not
  automatically a network transport or a usable public application SDK.
- Complete target resource and full-path allocation qualification, inspect
  secret handling and constant-time code, and compare complete developer
  workflows rather than claiming usability from shorter snippets alone.
