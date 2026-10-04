# Bounded ACK history under packet loss

A native unchanged-Neqo baseline passed a deterministic loss fixture. The
candidate client failed the same 2 MiB transfer with `Recovery(Capacity)` after
its receive history accumulated 32 disjoint ACK ranges. The added sparse-history
Rust regression failed before the fix. The prior limit was a connection-fatal
capacity condition, not an interoperability pass or a Hibana core defect.

The fix keeps the existing 32-range bound, prunes the oldest disjoint ranges and
advances a monotone packet-number cutoff. Numbers below that cutoff are never
accepted again. The largest range remains present, and merging adjacent ranges
cannot acknowledge a hole. This follows
[RFC 9000 section 13.2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.3).

Lean proves cutoff monotonicity, exclusion of discarded numbers, preservation of
the largest number, bounded list retention and subset membership. Z3 separately
checks those numerical obligations, no fabricated merge coverage, and a replay
counterexample for pruning without advancing the cutoff. These are scoped
models, not a complete Rust/QUIC proof or a model of all incoming ACK parsing.

`tests/receive_history.rs` supplies 2,048 real AEAD-authenticated sparse packet
numbers under the zero-allocation counter. It checks the fixed range bound,
absence of ACKs for missing packets, and rejection of a replay below the cutoff.
The native bidirectional loss fixture passes after the fix with identical file
hashes. Native delay, corruption and IPv6 diagnostics also pass; only the
unmodified runner can supply their official qualification.
