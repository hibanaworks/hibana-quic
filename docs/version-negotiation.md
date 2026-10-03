# QUIC v1 Version Negotiation

Architecture recovery (2026-10-03): the central Driver, HandshakeEndpoint and
TransportEndpoint production path and its endpoint-only integration tests were
removed. Descriptions or results below that depend on those entry points are
historical evidence and do not validate the recovered independent-role
connection. Independent TLS/crypto and domain-role code remains. See
[recovery status](../RECOVERY-STATUS.md) and the
[removed-test inventory and coverage gaps](../artifacts/legacy-migration/coverage.md).

The bounded endpoint supports QUIC v1 only. A valid Version Negotiation packet that omits v1 can terminate an attempt, but cannot select another version, restart TLS, reset packet numbers, authorize a Retry, validate an address, or authenticate a server. An attacker that can observe the original connection IDs can forge this termination indication. This is an unprotected denial-of-service boundary, not successful authenticated negotiation.

The client engine opens the VN window only after an actual adapter-accepted Initial. Preparation and rejected submissions leave it closed. It checks both echoed connection IDs and a complete, nonempty four-byte version list. A packet listing v1 is ignored. Any successfully processed server packet permanently closes the window, including an Initial and an integrity-checked Retry; Retry does not count as authenticated TLS. Corrupt or discarded packets do not close it. All seven unused first-byte bits are ignored. Malformed, unrelated and subsequent VN packets cannot reopen the window. An incompatible valid indication yields `VersionNegotiationNoCommonVersion` and silent endpoint retirement.

These rules implement [RFC 9000 section 6](https://www.rfc-editor.org/rfc/rfc9000.html#section-6) and its [packet format](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1), using the existing version-invariant parser. [RFC 8999 section 7](https://www.rfc-editor.org/rfc/rfc8999.html#section-7) requires authenticating semantic VN contents if an implementation switches versions. The authenticated version-information/downgrade mechanism in [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368.html#section-4) is therefore a prerequisite for any future multi-version extension. This implementation does not switch versions or claim RFC 9368 negotiation.

## Listener and host integration

`version_negotiation::Listener` owns fixed storage and a configurable global fixed-window response budget. `on_datagram` takes a monotonic microsecond timestamp, borrowed input/output and caller-provided `CryptoRng`. It handles only unsupported nonzero versions in complete datagrams between 1200 bytes and the configured cap. It never responds to VN, short headers, supported v1 packets, undersized or oversized input. Unknown-version packet-type/fixed-bit rules are not interpreted. Connection IDs from zero through 255 bytes are handled according to the version-invariant format.

Each response swaps both CIDs and lists exactly v1. Its length is at most 521 bytes, below every admitted input. The output first byte takes fresh low bits from the RNG and follows the v1 recommendation to set bit 0x40. RFC9000 allows arbitrary unused bits; cryptographic caller entropy is an explicit implementation choice here. Entropy failure and insufficient output capacity never substitute a fixed response or mutate output.

The caller must route existing connections and retired CID tombstones first, invoke the helper once per complete unmatched UDP datagram, and send a returned response once to that datagram's source. Local submission failure does not refund the preparation quota or trigger autonomous retransmission. The helper does not authenticate source addresses. Adjacent fixed windows can each consume their budget near the boundary.

The HQ host uses one listener across both admission phases of its optional two-connection mode, with a shared listener clock, 64 prepared responses per second and OS entropy. Its UDP metadata adapter rejects truncated datagrams. Existing Retry admission and source/ECN metadata remain separate. The host emits VN as Not-ECT and does not add it to authenticated packet or connection-success counters.

## Validation

Twelve isolated helper groups cover v1 lists, CID swapping and lengths 0/1/20/21/255, every client unused-bit value, malformed/truncated version lists, unsupported versions, receive admission, quotas, rejected-submission accounting, rollback, entropy failure and output capacity. The existing invariant-parser test is also included by the test filter. The no_std helper compiles for thumbv6m-none-eabi.

`reference-tls/tests/version_negotiation_wire.rs` is registered in the clean bounded host package. It uses real BoundedTls, certificates, encrypted Initial/handshake packets and Hibana authority. It tests silent abandonment, ignored spoofed VN, Initial/Retry window closure and corrupt-Initial exclusion. A separate listener case calls real OsRng. Allocation counting covers bounded construction, packet processing, errors and drop; fixture PKI and TLS/CRYPTO buffers are prepared outside the counter.

Actual UDP listener behavior and independent-peer continuation are recorded separately by the HQ host regression. Neither the component tests nor the presence of VN bytes establishes peer authentication.

The final consolidated evidence is [artifacts/version-negotiation/README.md](../artifacts/version-negotiation/README.md). Both listener UDP suites and all ten client UDP cases pass on the same frozen binary; the client cases use a synthetic unprotected sender and claim no TLS authentication.
