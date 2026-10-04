# Owned stream-delivery receipts

The stream table's send_fin_acked and reset_acked fields, sending_complete,
reset_acknowledged and phase-dependent retire method are deleted. No compatibility
implementation is retained. Newly validated packet ACKs yield actual FIN/RESET
payload evidence in the frame-effect owner. FIN evidence stays pending while
unacknowledged data remains. Once ready, the evidence is taken exactly once into
an actual-table-bound, non-Copy/non-Clone Delivered receipt.

The global ACK fragment explicitly rolls StreamDelivered / StreamDeliverySeen,
then DeliveriesDone and AcknowledgmentsSettled. The local adapter puts the owned
receipt and sends StreamDelivered; the transmitter receives the message, takes
and validates that receipt and records a read-only delivery observation, then
sends StreamDeliverySeen. A numeric stream ID alone cannot manufacture receipt
ownership. Application completion reads that received observation.

Hibana enforces these message edges and rejects ending the batch before the
consumer receipt. Lean/Z3 do not duplicate this protocol as an independent FSM.
They check the bounded arithmetic obligation that FIN alone does not acknowledge
outstanding bytes and that numeric stream equality cannot replace actual-table
identity. These are scoped payload models, not a proof of all Rust or QUIC.
Actual Rust tests enforce the affine receipt and table binding under no-allocation
measurement, FIN-before-data-ACK ordering and late STOP after completion.

Four old unit tests of automatic table phase-retirement/reuse were removed with
that unused lifecycle API, not reported as passes. Numeric receive, flow-control,
late-ACK, reset final-size, queue reclamation and 5 MiB bounded-window tests remain.
Stream-slot retirement/reuse must be integrated with explicit endpoint ownership
before that feature is qualified again. This work does not claim complete QUIC
interop, all stream controls migrated, or embedded hardware qualification.
