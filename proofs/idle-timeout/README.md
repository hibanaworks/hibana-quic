# Idle deadline arithmetic

These Lean and Z3 models cover nonnegative deadline arithmetic: the negotiated
millisecond duration, the three-PTO floor, checked-add monotonicity, and the
first-send rule. Z3 expects four UNSAT results and one SAT expiry witness.
They do not prove Rust side effects, physical I/O, or the whole QUIC protocol.
Rust behavior tests cover timestamp updates and overflow rejection; projected
terminal routes and native tests must separately establish actual retirement.
No source-name, hash, or fixed-source-shape guard is used.

Reference: RFC 9000 section 10.1, https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1
