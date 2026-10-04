# Active implementation: rolled-route runtime

Hibana is pinned to `development/rolled-route-ownership` at `9fbb84cdc932cbd0a81ee995a8689393f322763e`. The current QUIC starting tree is recovery commit d49769c; work is published on `development/rolled-route-runtime`.

## Live control path

- `bounded_tls/protocol.rs` declares actual Client/Server selection, hello/retry, extensions, full-certificate versus PSK branch, Finished and completion.
- `bounded_tls/locals.rs` writes the real owner/input `send`, `recv` and `offer` operations. Numeric borrowing does not choose phases.
- `bounded_tls/operations.rs` contains one-message parsing, certificate checks, transcript hashing and key derivation, with no phase-field dispatch.
- `connection/protocol.rs` composes this receive flow with TX publication, timers and Initial retirement using `par`; publication continues to use rolled routes and actual adapter resolvers.
- `connection/locals.rs` authenticates packets and reconstructs exactly one requested TLS message into the caller's existing RX buffer. The old coarse receive phase loop and crypto-result resolver were removed.
- `runtime.rs` runs fixed caller-pinned tasks; the host reactor uses actual epoll/eventfd wake and timer readiness.

The old synchronous TLS phase dispatcher, its detailed phase enum and the temporary synchronous test-oracle module/feature have been deleted. The remaining TLS health observation (`Handshaking`, `Connected`, `Failed`) does not select the next message. Synchronous receive can only parse OneRtt NewSessionTicket frames after Finished; it cannot drive Initial/Handshake. No fallback to the old control path exists.

## Validation and unfinished work

The new integrated connection passed all seven connected-application cases, including byte comparison, distinct streams, loss, HandshakeDone retransmission, confirmation and close. Host self-transfer compared actual 2/3/5 MiB files. Both direct TLS peers now run the new choreography in one test that measures zero allocations across full handshakes and pending-input cancellation. The historical synchronous test peer is not used by that test.

Two integration defects were found and fixed with scoped Lean/Z3 checks and regressions: partial input erasure during cancellation, and carrying verified Initial/Handshake consumption into the application boundary so old-flight retransmissions are distinguished from new forbidden input. The models are not proofs of the complete Rust implementation.

Fresh official runner qualification remains NOT_RUN. Native Neqo diagnostics do not reproduce the QNS topology, impairments or trace verdicts. The native forward test uses unchanged Neqo's generated-zero payload mode; the reverse and self-transfer exercise candidate-served files. A debug-build 60-second large forward transfer timed out and is retained as a failure. Release revalidation passed: unchanged Neqo baseline and both candidate directions transferred exact 2/3/5 MiB payloads. See the sanitized native result in artifacts/rolled-route-runtime-20261004/native-neqo-release.json.

Existing tests built around the deleted synchronous TLS input API require migration to asynchronous fixtures. They remain visible and are not counted as passing or silently skipped. The earlier broad-library early-owner retirement PhaseInvariant and path-owner cancellation stack overflow remain open. Complete no-allocation lifecycle, compile-resource gates, all 20 cases / 120 cells, and embedded hardware qualification are incomplete.
