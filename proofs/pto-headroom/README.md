# Bounded PTO publication headroom

The packet ledger still has 64 records. Ordinary in-flight admission stops with
16 free records, reserving capacity for actual PTO-authorized publication. No
ACK or loss is fabricated and no packet number is reused. Exceeding this finite
PTO capacity returns an explicit capacity error rather than waiting for an ACK
that the unsendable probe was supposed to elicit.

This is a bounded numerical resource policy, not a new protocol controller.
Hibana still orders the real timer receipt and Datagram/Accepted-or-Rejected/
Settled exchanges. Existing affine reservations and actual adapter acceptance
remain mandatory. Terminal ACK-only history remains reclaimable by its existing
exact-history compression; the change does not delete outstanding data records.

The scoped Lean/Z3 model proves that at most 48 ordinary outstanding records
leave room for at least eight two-packet PTO rounds without any freeing. It
also rejects authorizing a 65th outstanding record. It does not prove arbitrary
loss tolerance, Rust implementation correctness or a universal time bound.
The SAT negative witness represents the old policy allowing all 64 slots to be
occupied before a required fresh probe.

The actual Recovery regression failed before the fix with Accounting(Full)
after a real timer expiry, then passed. A second no-allocation test consumes all
backed probe slots through actual timer grants, preserves in-flight accounting,
and requires explicit Capacity on exhaustion. Existing capacity and encrypted
close tests use the ordinary quota while preserving cancelled PN burns.

Native reproduction drops both directions for two seconds after 4 MiB of wire
traffic. The old server timed out; the corrected server transferred the exact
10 MiB and exited successfully. This is not the runner's exact time-based ns-3
scenario, so its official result is tracked separately.

Run with Lean 4.30.0 and Z3:

    lean proofs/pto-headroom/Budget.lean
    z3 proofs/pto-headroom/Budget.smt2

Expected: four Lean theorems; four UNSAT results and one SAT negative witness.

Final local verification: 402 core tests plus existing integration, compile-fail,
thumbv6m, TLS and host suites passed. The native two-second blackout passed three
consecutive times in both directions; clean, resumption, forty-file server early
receive, loss, corruption and 64-file transfers also passed. A seven-run 32 MiB
client comparison measured 0.320447349 s versus Neqo 0.057752085 s with 9,612 KiB
candidate RSS. This is approximately 100 MiB/s, not a speedup or Neqo parity claim.
The official blackhole verdict is still pending for this change.
