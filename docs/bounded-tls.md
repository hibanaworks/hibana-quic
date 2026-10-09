# Bounded TLS in the current QUIC implementation

The transcript order lives in `hibana-tls/src/handshake/global/owned.rs`. Its directly
projected owner and input roles live in `hibana-tls/src/handshake/local.rs`. Input
adapters assemble complete messages; the local continuation authorizes the next
message and cryptographic operation. `Provider::receive` is not a replacement
handshake dispatcher.

## Ownership and storage

The caller supplies receive-message, transmit-flight, certificate and transport
parameter buffers. The input role transfers a message through `MessageSlot` to
the owner. Cancellation clears the active message and fails closed. The caller
must retain the actual endpoints until their companion roles finish.

`hibana-tls/src/handshake/key_source.rs` owns the scoped transfer of directional keys,
early-data material, integrity accounting and authenticated Finished evidence.
Successful UDP submission, authenticated ACKs and TLS Finished are distinct
facts. Receiving an ACK does not establish a completed TLS handshake.

## Current cryptographic profile

The current implementation supports TLS 1.3 with X25519/P-256 key exchange,
SHA-256, AES-128-GCM and ChaCha20-Poly1305. Server signing uses ECDSA P-256.
Client certificate validation additionally supports the explicit bounded RSA
profile described in [RSA verification](tls-rsa-feasibility.md). Certificate
path/name/time/usage validation is the owned implementation in hibana-tls; see
its X509-PROFILE.md. The old vendored webpki implementation, patch and verifier
are removed.

This profile is not a claim that every TLS algorithm, extension or certificate
format is implemented. Product and Host test dependency closures contain only
owned Hibana crates. The independent comparison workspace retains external
reference engines, not implementations linked into the product.

## Executable checks

From the repository root:

```sh
cargo test --locked --manifest-path tests/tls-reference/Cargo.toml
cargo clippy --locked --manifest-path tests/tls-reference/Cargo.toml --all-targets -- -D warnings
```

- `bounded_tls`: actual projected transcript, fragmented input, cancellation,
  invalid certificates/CertificateVerify/Finished, and allocation measurements.
- `certificate_depth`: generated nine-certificate chains, name/root/time/path
  constraints, explicit buffer limits and full projected handshakes.
- `resumption_rustls` and `early_rustls`: independent Rustls peer, PSK resumption,
  early keys and HelloRetryRequest. The candidate executes production globals
  and locals through the shared test-only transport fixture.
- `rsa_tls` and `rsa_vectors`: real RSA certificate handshakes and independent
  positive/negative encoding vectors.

The private-runner-certificate case remains explicitly ignored unless its
external fixture is supplied. Generated certificates and reference-peer
allocation are outside the candidate's measured zero-allocation intervals.
Local tests do not replace [exact-commit official interop](QUALIFICATION.md).
