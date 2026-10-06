# Active implementation and qualification

## Current qualification boundary (2026-10-06)

The historical matrix remains 30/44 unique candidate cells, not a complete
latest-commit matrix. Experimental 43c0c48a5b74f686adb4eb4557db0f008aac4cc5
passed all runtime CI37430945679 steps. Official CI37430945721/artifact11397292521
passed unchanged quiche C1/L1/M/Z controls and all eight candidate direction/case
cells, plus the existing six Lean and six Z3 model groups. Client C1 and L1 each
have fifty actual successful terminals, zero idle expiry, closed lifecycle and
resources retired. M transferred1999 files; Z transferred40 across two
connections with actual resumption. This is a checkpoint, not the full matrix.

Earlier intermittent L1 client failures remain recorded in direct-locals.md;
their cause is not established by later passes. The timer stop/expiry deadlock
was separately reproduced pre-fix and corrected without dropping the actual
expiry acknowledgement. Failed phases now preserve sealed authenticated
capture/keylog/log evidence for private diagnosis; the later33c83f4e trial supplied the first actual failed capsule. See
[direct locals](direct-locals.md) for exact boundaries. Earlier evidence sections
below are historical checkpoints, not current claims.

The subsequent33c83f4e trial passed runtime37434925495 but failed server L1 in
37434925514. Its actual encrypted capture was recovered: the1490-byte
ClientHello lacked its357-byte tail at the server, while all three server ACKs
were absent at the client. Other selected cells and controls passed. This trial
is not a full pass; see the captured-evidence section in direct-locals.md.

## Architecture

The pinned Hibana branch is development/rolled-route-ownership at
c3d89f787aa1a8e066b310a5307fdf7cb076ee26, with no local vendor patches.
The actual connection uses global choreography and explicit local endpoint
send/recv/offer/resolver calls. RX, TX, key, timer, source/sink and retirement
roles run on the bounded caller-owned async runtime; the host supplies an actual
epoll/eventfd reactor. The core remains no_std/no_alloc.

- Source: stream open, rolled data exchange, finite FIN/abandon. A non-Copy,
  actual-table-borrowing Production lease is issued once; chunks carry no stream
  selector or hidden FIN flag.
- Publication: complete Datagram / Accepted-or-Rejected / Settled exchanges.
- Peer stop: owned authenticated observation, explicit ApplyStop /
  StopApplied-or-StopFailed / StopSettled, with an independent result resolver.
- ACK: affine recovery evidence, explicit ApplyAcknowledgments /
  AcknowledgmentsApplied, rolled StreamDelivered / StreamDeliverySeen exchanges,
  DeliveriesDone / AcknowledgmentsSettled. The application sees delivery only
  after the actual owned receipt crosses the projected consumer boundary.
- Loss: one-shot scope-bound ApplicationLoss evidence, explicit ApplyLoss /
  LossApplied / LossSettled, before retransmission is selected. The direct Tx.lost
  callback is deleted.

The old roles tree, independent phase dispatchers, synchronous TLS fallback,
source send_final gate, deferred_stop/reserved_chunks callbacks, application
reset_pending/reset_acked, table reset_transmitted/send_fin_acked/reset_acked,
and automatic table sending_complete/reset_acknowledged/retire APIs are deleted.
No old compatibility controller is retained.

## Remaining work

This is not a claim that all QUIC control or all required interop is complete.
Numeric stream/recovery kernels still retain flow-control limits, packet/frame
references and loss history. Their legitimate arithmetic/resource bookkeeping
must not become an independent protocol phase selector. Peer STOP now has explicit SourceStopped/SourceEndStopped arms that terminate
only the current finite production and continue the next stream. Both the real
ingress and projected endpoints are tested for STOP during data and FIN without
connection failure. Actual encrypted peer-STOP interoperability remains unqualified. Stream-slot
retirement/reuse now consumes three independently transferred owned receipts;
see the current checkpoint below. Other unsupported interop features need actual global
and local implementations, not resurrected old controllers.

Four obsolete automatic table-retirement tests were removed with that API; they
are not counted as passes. Numeric receive, flow-control, reset final-size,
late-ACK, pending adapter and 5 MiB bounded-window coverage remains. New affine
receipt, foreign-owner, FIN-before-data-ACK and actual endpoint-order tests cover
the replacement. Full embedded hardware qualification is not established.

## Evidence

The lower-completion replacement at remote
ea8490b5e3c41561dd714af5b440480887b8e0ec passed locally: 413 unit +65 integration
+27 compile-fail =505; host 100; thumbv6m no-default-features; Python 47; scoped
Lean/Z3 payload checks. Native unchanged Neqo transfers pass in both directions
for clean 2/3/5 MiB payloads and deterministic 2 MiB loss. Native diagnostics are
not official runner qualification. The subsequent loss-projection refinement passes locally: 413 unit +66 integration
+27 compile-fail =506; host 100; thumbv6m no-default-features; Python 47. A fresh
native deterministic-loss baseline and both candidate directions pass with matching
2 MiB payload hashes. Its actual binary hash is recorded in the local evidence.

Official unmodified runner qualification is 21/44 unique candidate cells.
The seven existing cases passed both directions at `99943a86` in
[run 37255425723](https://github.com/hibanaworks/hibana-quic/actions/runs/37255425723).
Session resumption passed both directions at `622a17a4` in
[run 37257163222](https://github.com/hibanaworks/hibana-quic/actions/runs/37257163222).
Blackhole client passed with Neqo control in
[run 37263917795](https://github.com/hibanaworks/hibana-quic/actions/runs/37263917795);
the initially failing server direction subsequently passed with the same Neqo
control at e33e9df1 in run37269130471. Reference controls are not counted.
The remaining 24 aggregate cells and full repeated matrix are unqualified.
Server 0-RTT passed against quiche with its control in
[run 37261848054](https://github.com/hibanaworks/hibana-quic/actions/runs/37261848054),
separately from the Neqo count. Client 0-RTT remains unconnected. The new Hibana
dependency passed local consumer regressions; its official repeat is pending.

Lean/Z3 models prove only the stated resource/payload arithmetic outside Hibana's
order guarantee. They are not full Rust verification or a second QUIC FSM.
See proofs/stream-delivery and proofs/reset-observation for exact scope.
Historical checkpoints are retained in MIGRATION-HISTORY.md, not as current results.


## Source-stop continuation

The previous receive-side SendClosed-to-control.fail mapping and producer-wide
return on a stopped stream have been removed. SourceStopped and SourceEndStopped
are distinct global alternatives. Local SOURCE and INGRESS spell out their
send/recv/offer calls; a stopped production sends its finite abandon/end boundary
and the next stream continues on the same endpoints. Admission is the result of
one ingress exchange, not a replacement stream-phase FSM. Connection interruption
and actual application failure remain separate outcomes.

Local source-stop tests: 414 unit +67 integration +27 compile-fail =508; host100;
thumbv6m compile. The new actual-ingress test uses the real scoped publication
gate, stopped stream, real endpoints and no-allocation check. It verifies that
both data and FIN rejection leave connection health intact and admit another
stream. This does not by itself qualify an encrypted peer-STOP runner case.

The source-stop checkpoint also passes unchanged-Neqo clean 2/3/5 MiB and
2 MiB deterministic-loss transfers in both directions, with a separate Neqo
baseline and matching payload hashes. Sanitized evidence is in
artifacts/rolled-route-runtime-20261004/explicit-stream-control. The existing
seven official cases are requested again for regression qualification; no new
case was added and no new official pass is claimed before its result.


## Owned stream reclamation

Production, drained input, and actual delivery each transfer a distinct non-Copy
receipt on independent projected parallel lanes. Their bounded inventory joins
only matching actual table/slot/generation/stream resources. Retained chunk
arithmetic must be zero. ReclaimStream / StreamReclaimed / ReclaimSettled keeps
numeric slot reuse outside any unresolved UDP publication. The old reset_read
flag is removed; release-input authority is taken once. Closed-stream frames do
not reopen old IDs and incorrect unidirectional frame classes still fail.

Local checks: 415 unit +70 integration +27 compile-fail =512, host100, Python47,
thumbv6m compile, scoped Lean/Z3 identity/drain models. Four encrypted requests
reuse two client slots, both clean and with loss; actual endpoints reject
reclamation before publication settlement and publication before reclaim
settlement. Native unchanged-Neqo clean 2/3/5 MiB and deterministic-loss 2 MiB
transfers pass in both directions with exact payload hashes. Evidence is in
artifacts/rolled-route-runtime-20261004/stream-reclaim. Native results are not
new official runner cells. The total request bound remains16; MAX_STREAMS
credit replenishment and encrypted peer-STOP remain unqualified.

## Projected early-data ownership

The independent early-data Phase and six per-slot lifecycle flags are removed.
Four direct projected roles govern input completion, actual TLS Finished receipt
consumption, control/data delivery, rejection and cancellation. Bounded byte and
final-size arithmetic remains in a private kernel. Actual scoped AEAD receipts
bind input; labels alone confer no release authority. Both supported cipher
suites pass the real TLS resumption and projected release component test with
zero allocations in its measured path. This does not qualify endpoint 0-RTT.
See early-data-integration.md for the precise boundary. CID retirement and
key-update lower-control migration remain open; this is not full migration.

The early-owner checkpoint passes locally: 420 unit +70 integration +27
compile-fail =517; reference TLS29; host100; Python47 plus impairment4;
thumbv6m compile. These are local component/regression results, not new interop
cells. The prior owned-reclamation commit ff3c3d0 passed official regression
run37197056168: unchanged Neqo baseline and seven cases in both candidate
directions, still14/44. Its runtime workflow37197056163 also passed.


## Lower key-control removal (local checkpoint)

The combined ApplicationKeys implementation and provider Legacy branch have
been deleted, including their duplicate lifecycle tests. Directional tests now
compare actual ciphertext to raw packet primitives instead of an old controller.
Actual confirmation and current-epoch ACK receipts replace write-side flags.
The read-side Pending enum is deleted: the actual receive key moves inside the
transition receipt and returns through installed/rejected ownership. Key-role
retirement transfers the real closing write key and consumes RX control.
Transcript retirement consumes the transcript; the duplicate close-phase flag
is removed from the already-projected finite close continuation.

LocalUpdate/Installed/Rejected/Settled is part of the existing key-role global.
Both branches execute on actual endpoints with zero allocations; the positive
fixture explicitly synthesizes ACK/confirmation authority, so it is not network
qualification. CID retirement no longer stores an ACK flag: its table transfers
a unique owned frame once. The CID projected retransmission/ACK integration and
live local-key-update trigger remain open. See control-migration-audit.md. No
full-migration completion or additional official interop cell is claimed.

This local checkpoint passes 414 unit +70 integration +26 compile-fail =510,
reference TLS29, host100, thumbv6m compile, Python47 and impairment4. The lower
count than the prior checkpoint reflects deletion of seven duplicate combined-key
lifecycle tests, the obsolete copied-CID-admission test and two old-API doctests,
plus new owned-CID and projected-key tests. Default Clippy completes with warnings;
strict root Clippy is not clean. No new official runner was requested for this
intermediate checkpoint: final replacement qualification takes priority.


## Existing-control migration checkpoint

Unused Paths/PathEcn/ClientRetry controllers are deleted. The remaining ECN and
Retry routines validate actual counters and packet integrity without storing a
protocol phase. TLS key-schedule Stage is derived from owned secret material;
Finished verification creates an actual one-shot receipt in the projected TLS
owner. KeySource moves that receipt, the actual integrity budget and the actual
early key rather than tracking duplicate taken flags. Recovery retains the actual
OrdinaryRetired proof and terminal accounting instead of close_only/terminal flags.

Final local checks:385 unit +70 integration +26 compile-fail =481, reference TLS29,
host100, thumbv6m compile, Python47 and impairment4. Reduced test count reflects
removed unconnected controllers; it is not new feature qualification. Known-old-
controller source guard passes. The existing implemented control paths are direct
Hibana contracts/locals; remaining numeric/resource tombstones are documented in
control-migration-audit.md. Dynamic CID, local-update trigger, migration/ECN/Retry
endpoint features and host0-RTT remain unqualified work, not hidden old fallbacks.
The new exact replacement tree still requires official regression qualification.

Client 0-RTT now has a bounded projected transmission/admission prefix, with
actual accepted-publication receipts and authenticated rejection replay.
Native forty-file accepted, rejected and first-early-packet-loss cases pass;
official client Z passed in run37272347426. Blackhole both directions and Neqo control
passed at e33e9df1 in run37269130471, taking the unique aggregate to 19/44 at that stage.

## Official client 0-RTT and next key-update check

At commit 6c20cf86, [run37272347426](https://github.com/hibanaworks/hibana-quic/actions/runs/37272347426)
passed the unchanged quiche control and both candidate Z directions. The unique
aggregate is 20/44 (24 remaining), without counting server Z twice. The actual
candidate-client trace measured 10,826 bytes of 0-RTT and 769 bytes of 1-RTT;
the reverse direction measured 11,125 and 4,981 respectively, so that latter
pass is not a claim of repeated margin under the 5,000-byte threshold. Runtime
run37272347413 also passed. Remaining cases and three repeated release attempts
are not claimed.

The next server keyupdate native attempt exposed an actual stale timestamp:
RX observed a packet, awaited the projected peer-key installation while other
roles progressed, then submitted the old observation time to shared recovery.
The monotonicity guard correctly rejected it. Recovery now reads the actual
clock at its synchronous commit after that await; it does not clamp time or
relax the rollback check. The failed-before native evidence and fixed 3 MiB
byte-exact transfer are separate from the pending official key-phase verdict.

## Key-update qualification and client initiation (2026-10-05)

The unchanged Neqo baseline and candidate server U passed officially at
6bfdf43 in [run37274077941](https://github.com/hibanaworks/hibana-quic/actions/runs/37274077941).
Runtime run37274077932 also passed. This adds one unique cell, taking the
current aggregate to 21/44; client U remains pending its actual trace verdict.

The client now accepts an explicit `--key-update once` policy for a single
file-transfer connection. The library compares a target generation with actual
installed key generations and scoped ACK/QUIC-confirmation evidence. It adds no
update-in-progress flag: the existing localUpdate contract parks the real read
key, installs the write epoch and returns the read owner through LocalSettled.
Default ordinary traffic does not request local updates. Peer updates retain
the independent actual-authentication path. The report observes the actual
write generation before final key retirement, and the host refuses success if
a requested target was never installed.

Three native Neqo trials pass the control and both candidate directions with
byte-identical 3 MiB transfers. The candidate client reports key generation 1,
real confirmation, all stream bytes ACKed and completed close. Native 0-RTT and
blackhole regressions also pass. These local results do not substitute for the
runner's encrypted packet-trace requirement for key-phase changes on both sides.

## Long-chain amplification candidate

Two native controlled trials use the pinned runner's unchanged nine-certificate
generator, including its inflated SAN leaf, for a 9,662-byte DER chain. Actual
client/server processes authenticate and close after six selected client UDP
datagrams are lost; all 5,120 file bytes match. Before the first observed client
Handshake publication the server emits 2,400 bytes against 1,200 received.
The official amplificationlimit request retains the unchanged generator, trace
limit and both directions with a Neqo baseline; this is not yet a counted pass.

A separate native stateless VN diagnostic checks three CID geometries, reversed
CIDs, v1 advertisement, the threefold byte budget, invalid-input/VN-loop silence,
and a subsequent authenticated v1 handshake on the same listener. It adds no VN
qualification claim or official request: an eligible reference control has not
been established for that case. No runtime behavior is changed by these tests.
