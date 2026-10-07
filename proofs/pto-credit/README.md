# Bounded cross-space PTO credit

[RFC 9002 section 6.2.4](https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4) recommends probing other spaces with data in flight.
The client keeps the normal Handshake PTO timer. After actual publication of
its required Handshake probe, the second existing credit can target in-flight
OneRtt data. It does not infer handshake confirmation, declare loss, add a
third datagram, alter timer backoff, or authorize unaccepted/0-RTT data.

Production mapping: `src/connection/recovery.rs`, `reserve_kind` consumes a
credit, `settle` records acceptance or refunds an unaccepted reservation in the
same epoch, and the existing probe-space field selects the second datagram.
The global/local publication exchange still owns actual effect completion.

`credit.py` models the arithmetic of one allowance: available + reserved +
accepted = 2. It checks nonnegative conservation, the second-space budget,
no third accepted probe, and stale-epoch rejection. Every precondition must be
SAT; two intentionally broken refunds must be SAT counterexamples. Run with
Python and z3-solver. This is an independent abstract model, not a proof that
Rust refines it, not verification of the native adapter, and not a liveness or
arbitrary packet-loss guarantee. The integration test
`handshake_pto_also_recovers_lost_application_before_confirmation` and the unit
`handshake_probe_publication_hands_second_credit_to_one_rtt_and_cancel_preserves_it`
exercise the real implementation. Full same-commit interoperability is separate.
