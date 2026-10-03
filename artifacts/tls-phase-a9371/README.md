# TLS phase ownership on exact a9371 performance vendor

Vendor: `a9371bea437bbc1f4303ceeb3fc833f605efe730`, with no external correctness
repair. Previous exact-3aef logs and the scoped source archive remain under
`artifacts/tls-phase-production/` and are not relabeled as new-vendor evidence.

## Production change

The production TLS global is `protocol_tls_phases::tls_choreography`;
`protocol_tls` only re-exports it. `tls_owner::run_borrowed` has no universal
command/provider loop fallback. Its private roots sequence the actual five
phase locals, consuming private authorities and moving the sole Provider by
value. Grants are consumed outside elastic rolled work. Actual phase-specific
operation bodies retain confirmation/ACK authority, early/open/Finished
receipts, sealed packet integrity, unique integrity loans and drop cleanup.

Handshake retirement is independent of early-key retention. Application now
contains exactly four residual early arms, grouped as
`RetainedEarlyReceiveWork`: OpenEarly, EarlyHeaderMask, TakeEarlyReplayClaim
and DiscardEarly. One local still exclusively owns both the Provider and its
Endpoint. Application admits neither early sending, Handshake crypto nor
reconfirmation. The Provider destroys actual early keys on discard and
rejects subsequent early crypto; that absence is not graph-sealed. The
connection's other independently owned services retain their outer `g::par`.

## Verification

- `prefix-runtime.log`: five production-root Initial/Initial-to-Handshake
  projected-prefix tests pass with zero-allocation assertions;34.56s total,
  maximum child RSS789724KiB
- `full-graph-integrity.log`: one measured full staged tls_integrity_loan build
  was stopped by its memory guard at2637548KiB sampled process-group RSS after
  52.95s during const lowering; no tests ran
- `graph-size.txt`:333 sends/140 routes/five rolls
- `source-sha256-before-runtime.txt`: exact sources before those runs
- `source-sha256-current.txt`: exact current sources, adding the explicitly
  pending private Application-local fixture afterward
- `status.json`: machine-readable outcome and scope

The pending `application_early_tests.rs` fixture uses real ticket issuance and
resumed TLS through Finished, then directly sets up provider confirmation and
actual Handshake discard before entering the unchanged Application locals.
It asserts late0RTT receipt/mask/claim behavior and actual early discard followed
by KeysUnavailable. It is source coverage only, not yet typechecked or run;
it does not fabricate Finished/Path evidence or qualify full-root transitions.

No common-suffix factoring, dummy priming, core edits, hidden key-state machine,
shared provider/endpoint, new public capability constructors, or full runtime
qualification claim is included. Duplicated confirmation/Handshake discard
remain terminal. Later-phase cancellation and whole connection behavior still
need executable qualification once the existing blockers are resolved.
