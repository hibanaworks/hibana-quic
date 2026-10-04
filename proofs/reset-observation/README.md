# Stop observations and the publication boundary

`STOP_SENDING` is captured only by the authenticated receive continuation as an
owned, actual-table-bound observation. Capturing it does not apply RESET_STREAM.
Pending observations are bounded per live stream and retain the first error code.
The old `deferred_stop`, `reserved_chunks` and hidden `apply_stop` callbacks have
been deleted.

The global publication roll now selects either a complete datagram publication,
an explicit stop-application exchange, or retirement. The datagram exchange must
finish its accepted/rejected result and `Settled` before applying a stop. The
actual adapter role, which owns the pending send, performs the reset only after
receiving `ApplyStop`. It replies `StopApplied`/`StopFailed` and awaits
`StopSettled`. It does not infer permission from a counter or callback.

A proposed separate reply role was rejected by Hibana's receive-lane causality
validation. The implementation keeps stop application with the actual adapter
owner and passes projection unchanged; there is no validation bypass or Hibana
patch. `tests/stream_reset.rs` exercises real projected endpoints, including
rejection before the adapter outcome and between that outcome and `Settled`.
Those order properties are Hibana's responsibility, not a second FSM in Lean.

Lean/Z3 model only the payload property outside that guarantee: first-observation
retention and rejection of a mismatched complete identity. Z3 includes satisfiable
premises and an overwrite mutation counterexample. These are scoped models, not
verified compilation or full QUIC proofs. Actual no-allocation tests verify that
capture and adapter completion do not secretly reset, duplicate observations keep
the original code, and connection retirement drops unapplied observations without
claiming reset publication or acknowledgment.

The lower reset publication/ACK flags and reference history remain unfinished
migration work. This change concerns authority to apply the stop, not a claim that
all RESET/ACK control or end-to-end peer STOP interoperability is qualified.
