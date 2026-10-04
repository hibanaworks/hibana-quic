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

Official pinned runner pilot run 37173849532 passed at source 9e03afe89efad7a098e6ec17987d4b13b70318e3: handshake and transfer in both candidate directions, with a passing unchanged-Neqo baseline. Six non-null case results, zero unexecuted pilot cases. Remaining cases and release repetitions are unqualified. Evidence is retained in artifacts/rolled-route-runtime-20261004/interop-pilot-14/. Native Neqo diagnostics do not reproduce the QNS topology, impairments or trace verdicts. The native forward test uses unchanged Neqo's generated-zero payload mode; the reverse and self-transfer exercise candidate-served files. A debug-build 60-second large forward transfer timed out and is retained as a failure. Release revalidation passed: unchanged Neqo baseline and both candidate directions transferred exact 2/3/5 MiB payloads. See the sanitized native result in artifacts/rolled-route-runtime-20261004/native-neqo-release.json.

The main bounded TLS transcript suite is now entirely asynchronous: 16 cases cover real rustls peers, HelloRetry, fragmentation, both AEADs, certificate/Finished rejection, cancellation and ticket boundary checks. Independent RSA (2), resumption (7), and early-data (4) suites now also use actual async roles. The obsolete phase-specific mailbox/actor TLS, stream, path and recovery control implementation and its dedicated fixtures have been deleted (about 35,000 lines), rather than counted as passing or hidden behind compatibility APIs. Their historical PhaseInvariant/stack failures do not qualify the replacement. The current direct implementation passes the complete remaining core unit suite (476), integration suites (55), compile-fail contracts (27), host suites (99), four async TLS suites (29), Python checks (45), and thumbv6m core check. Full no-allocation lifecycle and embedded hardware qualification remain incomplete.

The old packet arena was unused by the live connection except as a recovery claim factory. Recovery now consumes a one-shot scope-bound installation directly; no compatibility arena is allocated. The actual recovery ledger, authenticated receive checks, accepted-send evidence and handshake confirmation remain in the direct roles. The direct construction obligation has separate scoped Lean/Z3 evidence.

The pinned runner registers 22 QUIC cases, including HTTP/3 and QUIC v2. Both directions require 44 cells per attempt (132 for three attempts). The earlier 20-case count was incomplete. [The qualification inventory](../interop/qualification.json) distinguishes each case and does not count missing, unsupported or skipped cases as passes.
