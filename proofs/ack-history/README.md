# ACK-only history must not consume recovery capacity

A native loss test reproduced a receive-side stall: the peer ACK for a real
MAX_DATA/MAX_STREAM_DATA packet was dropped. That in-flight packet prevented
completed-prefix reclamation. Sixty-four subsequent sent records then exhausted
the recovery ledger, so even a PTO publication could not obtain a slot.

The no-allocation regression retains one actual eliciting publication while
publishing 256 accepted ACK-only packets. It failed with `Accounting(Full)`
before this change. Under pressure, the existing single-owner ledger now
compresses only accepted, non-in-flight records into bounded exact packet-number
runs. Outstanding data, reservations, cancellations, packet-number gaps and
packet-number spaces are not conflated. No probe completion or peer ACK is
invented, and no private protocol controller or public API is added.

Runs hold validation evidence, not retransmission payload or fresh delivery,
RTT or key-update receipts. The same authenticated ACK processing validates
retained records plus exact runs before applying live-record effects. Old runs
are reclaimed with the actual contiguous prefix or packet-space retirement.
Key-epoch entries are removed only for the exact compressed record identities.
The bounded additional history contains at most `LEDGER_CAPACITY` runs; this
is a representation change, not an increase in active publication capacity.

Rust tests exhaustively compare ACK validation for all 1,024 five-packet
histories of accepted ACK-only, accepted data, cancelled and reserved packets.
They also cover a long ACK-only tail behind outstanding data, no invented
receipts, independent PN spaces and retirement. The scoped Lean theorems and
Z3 checks establish exact adjacent-run union and retained-floor clipping. They
do not prove the complete Rust implementation or liveness under arbitrary
network loss. Native peer repetitions and final performance measurements are
separate qualification requirements.

    lean History.lean
    python3 check_history.py
