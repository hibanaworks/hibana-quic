# Early-data qualification boundary

The early-byte lifetime is now expressed by `early_data::protocol`: projected
INPUT, OWNER, TLS and APPLICATION roles. Direct async locals retain bounded
bytes, consume an actual scoped TLS Finished receipt, and transfer ranges and
deferred controls with consumer acknowledgments. Reject and cancel discard the
owned bytes without refunding the replay claim. The independent `Phase` and
per-slot control flags are deleted; the remaining private `HeldBytes` is a
numeric byte/final-size ledger, not a public lifecycle API.

Admission consumes the server's actual replay claim. Input consumes a receipt
from a successful 0-RTT AEAD open and binds scope, packet number and plaintext.
A copied Verified wire label cannot release data without the actual owned
Finished receipt. The receipt is returned to the TLS continuation after checking
its connection scope, server side, accepted early-data status and generation.

Actual TLS resumption tests for AES-128-GCM and ChaCha20-Poly1305 pass with
zero allocations in the measured encrypted-input/projected-release path. Their
handshake component fixture transports TLS CRYPTO messages directly; it is not
an encrypted QUIC handshake or a whole-connection allocation measurement.
Focused projected tests cover rejection, cancellation, absent Finished,
premature publication, data release and deferred-control acknowledgment.

The host's end-to-end 0-RTT stream workflow is still not connected or qualified.
The deleted early-send journal and phase dispatcher must not return as a
compatibility path. Further packet routing, recovery, rejection replay and
application integration must use Hibana contracts and actual owned resources.
The official `zerortt` cells remain unrun; see [qualification](../interop/qualification.json).
