# Active implementation and qualification

## Architecture

The pinned Hibana branch is development/rolled-route-ownership at
9fbb84cdc932cbd0a81ee995a8689393f322763e, with no local vendor patches.
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
must not become an independent protocol phase selector. Peer STOP handling across
all source continuations and explicit stream-slot retirement/reuse remain to be
integrated and qualified. Other unsupported interop features need actual global
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

Official unmodified runner qualification remains 14/44 unique candidate cells,
seven cases in both directions, at 27065079e0d778bf7d238dec7c92f493817548e3 in
[run37183144899](https://github.com/hibanaworks/hibana-quic/actions/runs/37183144899).
Seven Neqo/Neqo controls are separate. Remaining 30 cells and the full repeated
matrix have not been qualified. No additional interop cases are being added while
this control migration is incomplete.

Lean/Z3 models prove only the stated resource/payload arithmetic outside Hibana's
order guarantee. They are not full Rust verification or a second QUIC FSM.
See proofs/stream-delivery and proofs/reset-observation for exact scope.
Historical checkpoints are retained in MIGRATION-HISTORY.md, not as current results.
