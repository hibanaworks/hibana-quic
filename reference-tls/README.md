# Allocating reference TLS backend

This standalone development crate implements `hibana_quic::tls::Provider` using
rustls **0.23.45**, pinned with its dependency closure in `Cargo.lock`. It uses
rustls's TLS-only QUIC interface. It does not reuse another QUIC transport engine.

This backend deliberately uses `std`, heap allocation, ring, OS randomness, and
system certificate-validation time. **It does not satisfy the no_alloc/Pico TLS
release gate.** It exists to test real authenticated TLS and wire integration
while a separate bounded release TLS backend remains unfinished.

## Security and scope

- TLS 1.3 only; QUIC v1; ALPN `hq-interop`
- Explicit client trust roots and WebPKI certificate/hostname validation
- Server certificate and matching private key required; no insecure verifier
- Raw TLS handshake bytes, not TLS records
- Initial bytes are queued at Initial level before installing Handshake keys;
  similarly, Finished bytes stay at Handshake level before 1-RTT output
- Fragmented output keeps its original encryption level
- Message types and partial-message boundaries are checked per CRYPTO level
- Initial packet protection remains in the transport core
- Per-level send packet numbers are strictly increasing; key confidentiality
  limits and one shared Handshake/1-RTT integrity-failure limit are enforced
- An authentication failure wipes the input packet payload; TLS failure or
  integrity-limit exhaustion is terminal for this provider
- Peer transport parameters and ALPN are exposed only after TLS completion
- The transport must separately parse and validate transport-parameter semantics
- No resumption, 0-RTT, TLS key logs, QUIC key updates, key retirement timers,
  certificate-authenticated client identity, or no_alloc claim
- The TLS message-length cap is 1 MiB; this is a defensive input limit, not a
  bound on total heap use

The optional TLS constructor inputs use matching rustls types from the `rustls`
re-export. `RustlsProvider::client` accepts `RootCertStore`, an owned
`ServerName<'static>`, and encoded local transport parameters.
`RustlsProvider::server` accepts the certificate chain, private key, and encoded
local transport parameters.

## Tests

```
cargo test --locked --manifest-path reference-tls/Cargo.toml
```

Unit tests generate ephemeral test CAs/certificates with dev-only rcgen 0.13.2.
They perform actual in-memory client/server TLS handshakes, including one-byte
fragmentation, verify ALPN and transport-parameter exchange, use negotiated
Handshake/1-RTT packet/header keys bidirectionally, and reject corruption,
untrusted CAs, wrong hostnames, malformed handshake data, forbidden TLS
KeyUpdate, packet-number reuse, and exhausted AEAD limits.

These are backend/integration tests, not Neqo interoperability results.

## API source contract

The pinned release source `rustls-0.23.45/src/quic.rs` specifies that a
`write_hs` call returning `KeyChange` supplies new keys for **future** handshake
output. Applying those new keys to bytes returned in that same call incorrectly
encrypts ServerHello or Finished. This wrapper preserves the old level before
handling each key change.

Reference: <https://docs.rs/rustls/0.23.45/rustls/quic/index.html>

## UDP handshake development executable

The `handshake` binary drives the actual `HandshakeEndpoint`, caller-owned
Hibana carrier/runtime, and rustls reference provider over `std::net::UdpSocket`.
It handles one connection, with cryptographically random connection IDs from
rustls's ring provider. The server obtains the original destination connection
ID from the first received QUIC v1 Initial; no fixed test CID is assumed.

From the `hibana-quic` directory:

```sh
cargo build --locked --manifest-path reference-tls/Cargo.toml --bin handshake

reference-tls/target/debug/handshake server \
  --listen 127.0.0.1:4433 \
  --cert server-chain.pem --key server-key.pem \
  --timeout-seconds 10

reference-tls/target/debug/handshake client \
  --connect 127.0.0.1:4433 \
  --server-name localhost --ca root-ca.pem \
  --timeout-seconds 10
```

Addresses must be explicit IP/socket addresses; IPv6 uses `[::1]:4433`.
`--ca` is required and supplies the explicit trust roots. Certificate-chain,
hostname, validity, and signature verification remain enabled. The PEM reader
uses rustls-pki-types 1.15.1 `PemObject` and supports PKCS#1, PKCS#8 and SEC1
private-key PEM blocks (the bounded provider only accepts P-256 PKCS#8/SEC1). There is no insecure
verification option. `--timeout-seconds` defaults to 10 and accepts 1–300.

The adapter reports accepted transmission to the core only after `send_to`
succeeds for the whole datagram. It uses injected monotonic elapsed microseconds,
bounded work per turn, and read/write deadlines. Client completion is checked
only after its own Finished and other queued output have been flushed to UDP.
The peer address is fixed for this single-connection run; it does not silently
follow packets from new source addresses.

One JSON line reports `backend: "reference-tls"`, `scope: "handshake-only"`, the
local handshake outcome, and successful-run packet counters. Any timeout,
certificate error, I/O error, or terminal core failure exits nonzero and reports
failure. A successful local handshake and socket acceptance do not establish
remote receipt of the final flight or full interoperability.

This is **not** a quic-interop-runner executable and has no `TESTCASE` wrapper,
HTTP/0.9 transfer, stream transfer, migration, complete loss-recovery, or
congestion-control support. The experimental core now retains bounded CRYPTO
flights and drives fresh-packet-number PTO retransmission from the injected timer;
this is a narrower capability than a complete recovery implementation. The ALPN remains `hq-interop` for handshake testing;
it does not imply an implemented HTTP application. Lost handshake packets can
therefore cause an honest timeout. This host program allocates and makes no
Pico/no_alloc TLS claim.

```sh
cargo test --locked --manifest-path reference-tls/Cargo.toml --bin handshake
```

The binary's tests generate an ephemeral CA/certificate and run client/server
over actual localhost UDP, require hostname rejection, require timeout failure,
and reject missing roots or unsupported transfer flags. A separate two-process
CLI smoke was also run using generated OpenSSL PEM fixtures; both sides completed
their authenticated local handshake. Neither self-test is a Neqo result.

Direct Neqo evidence is recorded separately in `../artifacts/direct-neqo/`:
our verifying reference client completed a real UDP handshake with the unchanged
Neqo 0.32.0 server. The reverse direction uses the explicitly certificate-verifying
Neqo library wrapper in `../interop/neqo-verifying-peer/`, which reached `Confirmed`
with our reference server. Wrong-CA/hostname negatives reject as expected. These
remain direct handshake-only experiments outside quic-interop-runner.

## Bounded profile integration

This host package now also contains tests and the `bounded-handshake` binary for
`hibana_quic::bounded_tls::BoundedTls`. That command uses the bounded P-256
provider exclusively; it has no reference-TLS fallback. Its host PEM/filesystem,
network setup and diagnostic code still allocate. See `../docs/bounded-tls.md`
for exact measured allocation scope, direct Neqo evidence and release gaps.
`client_p256` is a verifying rustls test helper constrained to one group for this
first profile; the ordinary reference client constructor is unchanged.
