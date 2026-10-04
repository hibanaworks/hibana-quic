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

## Network impairment qualification in progress

The cleanup revision 92731a990f11f3bd293e776a1535d6f36cbfb3ff independently passed the same official pilot (run37176305141) and direct-runtime CI (run37176305247). Unique candidate qualification remains 4/44, excluding baseline cases and repeat runs.

The next native 2% packet-loss transfer exposed a real fixed-range ACK-history capacity failure. The new retention cutoff keeps the 32-range bound and never readmits discarded packet numbers. Scoped Lean/Z3 models, a failing-before regression, and real authenticated sparse-packet tests accompany the fix. Native Neqo baseline and both directions now pass deterministic loss, 1.5-second round-trip delay, corruption, and IPv6 diagnostics. The corresponding official runner results now pass in run37177524554 on b8cf48f7636eec7b81942a27175a89ba68a84333. The latest unique total is 12/44 candidate cells, excluding the six Neqo baseline results; the earlier 4/44 count above is historical. Evidence is in artifacts/rolled-route-runtime-20261004/interop-pilot-16/.

## Stream production migration (not a full lifecycle migration)

The generic source-data FIN boolean has been removed. The actual global now
contains stream opening, an inner rolled chunk exchange and a finite FIN/abandon
route with an explicit admitted/rejected terminal reply. Local ingress holds the
opened production lease; ordinary chunks cannot select another stream. Empty responses and cancellation can leave the data loop without
fabricating a FIN. Abandon is connection-level production cancellation, not a
RESET_STREAM acknowledgment.

The current source changes pass eight encrypted connected-application cases and
two real-endpoint production tests, including no allocation, empty streams,
multiple chunks, rejected terminals, data-after-FIN, repeated FIN and repeated
abandon. The complete current core run is 477 unit +59 integration +27 compile-fail
contracts. Scoped Lean/Z3 checks describe the remaining resource-slot identity
boundary; they do not claim it is supplied by Hibana.

**Still incomplete:** the lower stream table's RESET/ACK permission fields
and reset publication/recovery control have not yet been replaced. Same-stream
identity reuse is prevented by the one-shot lease issuer in addition to the source graph. Interoperability and
architecture migration are separate completion criteria. No whole-stack migration
claim follows from these tests. The published 12/44 runner result predates this
source-production change and does not qualify it.

## Removal of disconnected legacy controllers

Six standalone controllers were still exported but had no callers in the live
endpoint: early-send, deferred early-control, close lifecycle, idle timeout,
version-negotiation, and migration selection. They and their private phase/state
machines have now been deleted, together with obsolete stream-import helpers and
old usage documents. The actual connection's direct close/drain choreography is
unchanged. Numerical path/CID and TLS cryptographic building blocks remain where
they have current tests or callers; no removed feature is counted as migrated.

The 67 unit tests belonging to those deleted controllers were removed with them,
not converted to passes. The remaining core suite is 410 unit +59 integration +27
compile-fail contracts, all passing. In particular the eight live encrypted
connection tests and two finite stream-production tests remain. The new capability
ledger no longer presents old-driver feature tests as current implementation.

## Affine production issuance

The opened resource now moves as a non-Copy/non-Clone `Production` lease borrowing
its actual table identity. Ordinary chunks no longer contain a stream handle;
there is no per-chunk stream selector to substitute. Issuance is removed from the
registered stream exactly once, and repeated registration does not replenish it.
Ingress retains the lease only through the finite source production continuation.
Its numeric admission checks the actual table identity, not just numeric IDs.

The lower `send_final` field and its admission checks are deleted. Raw queue enqueue
is no longer public; the old whole-chunk application enqueue entry point is also
removed. Lost STREAM/FIN retransmission continues from independently retained
chunk/packet references and does not reopen production. RESET/ACK control fields
remain a migration task; this does not claim the entire stream lifecycle is done.

Two additional no-allocation Rust tests reject repeated issuance after drop and
same-handle registration, and reject a foreign-table lease even when numeric
handles are identical. Updated Lean/Z3 checks model the actual issuer and scope
check, with a satisfiable numeric-only mutation counterexample. They are scoped
models, not a whole-Rust verification claim.

The finite source-production checkpoint c3e01d12c132bef0896b03e605bcf2183dfbc3da
subsequently passed official runner37179772627: six cases in both directions,
unchanged 12/44 unique cells, with baseline six kept separate. Runtime CI37179772615
also passed. Controller-deletion checkpoint c950d725f8fdc21001f45513874ed3d51e42a187
passed runtime CI37180144793. Evidence for the runner is in interop-pilot-17.
The newer affine lease change still requires its own runner qualification.

Affine production verification: 412 core unit +59 integration +27 compile-fail
contracts, 100 host tests, 47 Python tests, thumbv6m core compilation, and the
scoped Lean/Z3 models pass locally. The production tests also have compile-time
negative Copy/Clone assertions. Native unchanged-Neqo baseline and both candidate
directions compare exact 2/3/5 MiB contents; a separate deterministic-loss run
compares 2 MiB contents. These remain native diagnostics, not runner verdicts.

## Stop application is a publication alternative

The receive callback now captures an authenticated, actual-table-bound stop
observation. It no longer secretly applies RESET_STREAM. The old `deferred_stop`,
`reserved_chunks` fields and `apply_stop` callback are removed. Applying a stop is
an explicit alternative in the publication global, after a complete datagram's
Accepted/Rejected and Settled edges. The actual adapter owner receives ApplyStop,
consumes the owned observation, replies StopApplied/StopFailed, and awaits
StopSettled. TX processes at most one stop per output iteration so repeated peer
requests cannot starve ACK/retransmission work.

Real projected-endpoint tests reject reset application before adapter outcome
and before Settled, and accept it after complete publication. Numeric integration
checks that receiving an observation and completing a send do not apply a reset
until that explicit operation. No-allocation tests retain the first duplicate
observation, reject a foreign table even with identical numeric handles, and
cancel unapplied observations on connection retirement without claiming a wire
reset. Scoped Lean/Z3 models cover payload identity/coalescing, not the ordering
already enforced by Hibana.

The three-role proposal was rejected by receive-lane causality validation. The
implemented graph uses the actual adapter owner, with no validation bypass or
Hibana patch. The lower reset pending/acknowledged flags and reference history
remain unfinished migration work. Peer STOP end-to-end interoperability has not
been qualified by these component tests.

The preceding affine-production commit1369ffbd7583b3600fe25537986655d1de340db0
passed runtime37181080973 and official runner37181080895: still12/44 unique
candidate cells, six separate baseline results. Evidence is in interop-pilot-18.
This result predates the stop-application change.

Stop-application local validation passes: 415 unit +61 integration +27 compile-fail
contracts, 100 host tests, 47 Python checks and thumbv6m compilation. Unchanged
Neqo baseline and both candidate directions compare actual bytes for 2/3/5 MiB
ordinary transfers, 2 MiB deterministic loss, and strict ChaCha20 3 MiB transfers.
The next official pilot adds the already implemented strict ChaCha20 case to the
six prior cases. Its two cells remain unqualified until the runner returns actual
verdicts; no new pass is inferred from local diagnostics.

## Independent reset-result resolver

The stop-application result now uses its own `g::Resolve` site and actual outcome
cell, separate from UDP publication. The adapter records the actual effect result,
uses the matching resolver, then sends StopApplied/StopFailed and clears the result
only after StopSettled. Tests reject a fabricated opposite result and a missing
reset result even when a UDP result exists. All four UDP/reset result combinations
are exercised through actual endpoints. Duplicate receive-role loss/retry entry
points and unused phase/snapshot accessors have been deleted.

The stop-application commit27065079e0d778bf7d238dec7c92f493817548e3 passed official
runner37183144899 and runtime37183144902. ChaCha20 passed in both directions,
raising unique candidate qualification to14/44, excluding seven baseline cases.
The next priority is deletion/replacement of remaining reset retry and ACK control;
no further interoperability-case expansion is planned before that migration.

## ACK application and deleted RESET controls

RX now retains an affine, actual-scope-bound FrameAcknowledgments grant issued
by validated recovery. It cannot directly update stream delivery. The explicit
publication branch ApplyAcknowledgments / AcknowledgmentsApplied /
AcknowledgmentsSettled consumes the grant through the adapter owner, outside any
unsettled datagram publication. Captured ACKs drain before publication retirement.

Deleted controls: application reset_pending, application reset_acked, and table
reset_transmitted, including the public reset_transmitted operation. Published
RESET frame references provide the actual in-flight evidence. The lower
send_fin_acked/reset_acked completion fields remain migration work; this is not
an assertion that the entire stream lifecycle has been migrated.

Local validation at this checkpoint: 415 unit tests, 64 integration tests and 27
compile-fail tests; 100 host tests; thumbv6m no-default-features compile. Real
projected-endpoint tests reject ACK application before publication result or
settlement and reject a new datagram before ACK settlement. Earlier intermediate
versions stalled handshake confirmation and skipped captured ACKs on retirement;
these were fixed, without deleting or weakening the eight connected tests.
Official interop remains 14/44 at the previously identified commit, not this
unqualified source revision. No additional interop cases were added.
