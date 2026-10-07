# TLS backend decision (2026-10-02)

Status: the original candidate assessment below led to the implemented bounded
backend in `src/tls/handshake.rs`. It performs real client/server TLS authentication,
HRR, certificate chains, Finished and packet-key derivation without allocation in
measured paths. See `bounded-tls.md` and current test artifacts. Tickets/resumption,
0-RTT and full release conformance remain incomplete. The candidate investigation
below is historical evidence, not current implementation status.

The inspected sources are pinned, not assumed from earlier APIs:

| Candidate | Inspected revision | Finding |
|---|---|---|
| rustls | `7dcbe4c1ae12185237d22e9197583329630a2014` | `rustls/src/quic.rs` imports `alloc::boxed::Box` and `alloc::vec::Vec`, and uses `Arc`. QUIC API supports client and server, but this is not an allocation-free backend |
| embedded-tls | `930fbbb040f62c96ee29c480a8c3b456ec03a571` | Cargo description and connection implementation are TLS 1.3 **client**. Heapless buffers do not establish server/raw-QUIC/ticket/early-data functionality. RSA feature explicitly enables alloc. Cannot substitute this directly for the required backend |

These are two investigated candidates, not a proof that no suitable backend exists.
Neither full TLS engine is a normal dependency of this crate. RustCrypto or other primitives must
be pinned and audited for target and selected features before use. A TLS reference
backend, if later added, must remain explicitly labeled `reference-tls` and cannot
qualify G-HOST or G-PICO.

`src/handshake.rs` implements sliding caller-storage CRYPTO reassembly and raw TLS
Handshake framing only. It deliberately does not expose a handshake-success,
certificate-verified, or traffic-key event. No plaintext or fixed-secret transport
has been added to hide this gap.

## Independent bounded TLS workstream

Before bounded TLS can be declared complete, implement and test client and server
transcripts, raw handshake input/output at the correct QUIC levels, HKDF traffic
secret export, HelloRetryRequest, Finished and CertificateVerify, authenticated
X.509 chain/hostname/time verification with an explicit trust anchor, hq-interop
ALPN, SNI, transport parameters, tickets/resumption, 0-RTT replay/rejection policy,
and encryption-level key retirement. Supply entropy and clock from the caller.
Use standardized audited primitives; do not invent crypto. Use RFC 8446/9001
vectors and independent negative tests. Bound CRYPTO gaps, message storage,
certificate parsing, chain length, and ticket storage independently.

The release gate includes AES-128-GCM and ChaCha20-Poly1305, and the applicable
TLS mandatory-to-implement group/signature requirements. A successful small
certificate fixture is insufficient for the runner's amplification test.

The current dependency/target/allocation evidence is recorded in the README and
artifacts; the original investigation itself established none of those gates. Device driver, entropy source, board variant, and actual
Pico memory budget remain open decisions requiring measured evidence.
