# Bounded-profile host adapters

This package intentionally has **no rustls TLS dependency**. Its QUIC/TLS provider
is `hibana_quic::bounded_tls::BoundedTls`; selected cryptographic primitives,
borrowed webpki validation and caller-owned core storage are shared with the
thumbv6m build. The allocating reference TLS implementation lives in the separate
`reference-tls` package and is only for development comparison.

The binary sources are shared with the development harness to avoid divergent
application logic. Host argument parsing, files/PEM, root/key import, UDP adapter
and JSON reporting use `std` and may allocate. This is not a claim that the entire
host process never allocates. The measured core boundary is documented by the
allocation tests; no-allocation error-path tests must use this dependency closure,
not a mixed reference-TLS graph that enables webpki's diagnostic `alloc` feature.

PEM import uses `rustls-pki-types` 1.15.1 `PemObject` slice APIs in the shared
host-only `src/pem.rs`. It reads PEM setup files into host memory and enables
only `pki-types/alloc`, not `pki-types/std` or webpki diagnostic features. The
standalone core dependency graph enables neither feature. Certificate import
validates every PEM block; key import selects the first PKCS#1, PKCS#8 or SEC1
block. Empty inputs and malformed supported blocks fail closed. PEM decoding
does not replace DER, algorithm, certificate-chain, hostname or time validation.

```sh
cargo build --manifest-path adapters/host/Cargo.toml --release
cargo test --manifest-path adapters/host/Cargo.toml --test bounded_wire
cargo tree --manifest-path adapters/host/Cargo.toml -e features -i rustls-webpki
```

The profile's algorithm/protocol exclusions remain in `docs/bounded-tls.md`.
Direct handshakes or transfers are not the 40-case runner gate, and host tests
are not Pico hardware-in-loop evidence.

The separately tested native IPv4/IPv6 ECN metadata socket helper and bounded
validation component are documented in [ECN.md](ECN.md). Endpoint wiring and direct real-peer tests are covered there; full runner
qualification is still separate.
