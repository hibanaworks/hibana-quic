# TLS and packet-key owners

The historical whole-provider proxy and combined application-key controller are
not the current connection architecture. Actual TLS input/output runs through
bounded_tls protocol globals and direct async locals. KeySource owns the scoped,
one-shot handoff of handshake keys, application keys, early material, integrity
budget and the actual authenticated Finished receipt.

The connection separates receive and transmit key ownership. Authenticated peer
updates cross RX_KEYS/TX_KEYS and require the returned installed-write receipt
before ACK eligibility. Transport confirmation and sent-ledger ACK evidence are
actual scoped owned values. See key-updates.md and early-data-integration.md.

Source-owner adapters expose no mutable provider to callers. Numeric parsing,
cryptographic computations, replay limits and flow/congestion arithmetic remain
kernel obligations. Component tests and official interoperability are separate;
see ACTIVE-IMPLEMENTATION.md and interop/qualification.json for exact scope.
