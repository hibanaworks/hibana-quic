# Handshake buffering and RTT

RFC 9002 section 5.3 permits ignoring Initial ACK delay, but does not extend
that exemption to Handshake packets. Before confirmation, peer key-buffering
delay is not capped by max_ack_delay. A sample that would fall below min_rtt
may instead be ignored; it is never clamped to invent a better measurement.
After confirmation, the peer's maximum delay bounds the adjustment.

These four Lean theorems and four UNSAT checks cover only the arithmetic
minimum and exact buffering subtraction. The SAT case witnesses the old
inflation. They do not prove packet authentication, peer parameters, or Rust
source refinement. Rust tests separately cover the pre-confirmation ignored
sample and confirmed cap. Native interop must test actual loss recovery.

https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3
