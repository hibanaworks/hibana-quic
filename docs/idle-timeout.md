# Idle timeout

`idle::IdleTimeout` and `HandshakeEndpoint` implement the idle policy from [RFC 9000 section 10.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1). The period uses the nonzero minimum of the local and authenticated peer transport parameters, with a floor of three current PTO estimates. Both zero disable idle expiration. The estimate excludes recovery's exponential timer backoff; unanswered probes cannot keep extending their own connection lifetime.

Only successfully authenticated and processed peer packets restart activity, including ACK-only packets. Only the first actually adapter-accepted ack-eliciting send after such a receive restarts it again. Rejected outputs, output preparation, corrupt packets, discarded duplicates, Retry, Version Negotiation, later sends and ordinary polling do not restart activity. Changing the PTO floor recalculates from the existing activity timestamp. A received ACK can change RTT; the engine preserves the arrival-time estimate until successful packet processing has renewed activity, then applies the new estimate.

An endpoint reaching the deadline silently retires its keys, driver authority and prepared output. It generates no CONNECTION_CLOSE. `TransportEndpoint` closes the stream table and clears its pending output even when normal recovery would otherwise be blocked awaiting an adapter result. Local close and peer close stop the idle policy; closing/draining retain their own independent lifecycle deadlines.

## Setup and clocks

The Provider trait exposes peer parameters only. `HandshakeEndpoint::new` and `new_after_retry` therefore have an explicit local default of zero. Before any receive/transmit attempt, callers whose TLS bytes advertise nonzero TP 1 must call `configure_idle_timeout(local_timeout_ms)` with that exact advertised value. Setup does not rewrite an existing TLS message. The configuration is one-shot. The current HQ adapter advertises no TP 1 and explicitly configures zero; its host process deadline is a separate setting.

Transport parameters use milliseconds. All event clocks and PTO estimates use monotonic microseconds. The engine installs the peer's TP 1 only after successful TLS authentication and connection-ID validation. Remembered 0-RTT parameters do not substitute for these values.

The caller must poll the injected clock, include `next_deadline()` in its scheduler, and call `transmit_permitted(output, now)` immediately before synchronous submission. Output reservation is not acceptance. Serialize submission, receive and timer effects; a delayed notification about an earlier send cannot be reported as a new send. Existing engine output descriptors reject foreign or duplicate callbacks before the idle policy is reached.

`idle_deadline_token()` and `idle_timeout(token, now)` support queued idle callbacks. Tokens contain opaque connection generation, revision and deadline. Foreign, superseded, premature, duplicate, stopped and expired callbacks cannot advance the clock or alter connection state. Direct clock polling remains available through `poll_idle_timeout(now)` and the normal endpoint timer. Generations must never be reused while old callback descriptors can exist.

All time conversions, three-PTO multiplication, deadline addition and revision increments are checked. Unit conversion follows negotiation so a large legal peer timeout remains usable with a smaller local limit. A duration outside the representable microsecond clock range reports a local range error; it is not evidence of an invalid peer transport parameter. Clock rollback also returns an error without reviving or extending the connection.

## Evidence and boundaries

The dependency-free kernel has 18 tests covering negotiation, disabled state, actual-send gating, current PTO changes, terminal expiry, rollback/overflow and generation/revision timer validation. The no_std kernel compiles for thumbv6m-none-eabi.

`reference-tls/tests/idle_wire.rs`, also registered in the clean bounded host package, uses real BoundedTls endpoints, real certificates, encrypted QUIC packets and the Hibana driver. All six test groups pass. The allocation counter includes endpoint/TLS construction, packet processing, idle errors, retirement and drop. Certificate fixture generation, trust-anchor import and TLS/CRYPTO buffer setup occur before counting; the pending-stream scenario also initializes its fixed stream buffers inside the measured interval. These tests are Sans-I/O evidence; they do not claim independent-peer wall-clock timing or Pico execution.

Initial test attempts encountered the concurrently expanded service graph's insufficient 32-port carrier budget. A temporary 64-port diagnostic passed all five original scenarios. The graph owner independently measured and published a 48-port production budget, including timer-first service coverage; final tests use `protocol::SERVICE_PORTS` rather than a private oversized fixture. The original kernel and test classifications were not relaxed.

This component does not add keepalive policy, a separate handshake deadline, stateless reset, migration, or a whole-program embedded memory bound.
