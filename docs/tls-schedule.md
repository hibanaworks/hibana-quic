# Bounded TLS 1.3 SHA-256 schedule

`src/tls/schedule.rs` is a no_std/no_alloc cryptographic building block. It is
**not a complete TLS backend**, and a successful derivation is not a claim that
TLS authenticated a peer or completed its handshake.

## Implemented

- Fixed-size SHA-256 transcript state; complete Handshake-message framing checks
- RFC 8446 §4.4.1 HelloRetryRequest `message_hash` transformation, at most once
- Noncommitting ClientHello-prefix transcript hash for PSK binders
- HKDF-SHA256 early → handshake → master → resumption schedule
- Client/server handshake and application traffic secrets
- External/resumption PSK binders and client early-traffic derivation
- Finished HMAC generation and constant-time verification
- Exporter derivation and per-ticket resumption PSKs
- Checked derivation stages; terminal secret destruction on bad Finished
- Non-Clone/non-Debug secrets and zeroized retained secret material on drop
- Caller-owned exporter output, bounded HKDF label/context/output lengths

Primitives are RustCrypto `sha2`, `hkdf`, `hmac`, `subtle`, and `zeroize` with
allocation/default features disabled. SHA-256 is the only supported transcript
hash. This covers the schedule for AES-128-GCM-SHA256 and
ChaCha20-Poly1305-SHA256, not AES-256-GCM-SHA384.

`Transcript::append` takes one complete encoded message. The existing CRYPTO
reassembly/message parser and future bounded TLS state machine must supply that
message. This module does not retain the transcript's bytes.

Schedule stage checks guard derivation order and checkpoint shape. They do not
replace validation of TLS message order, negotiation, certificate signatures,
peer identity, or the precise message contents. `derive_master` and
`derive_resumption` require the caller to have handled the corresponding Finished
message correctly. `verify_finished` must run on the transcript before appending
the received Finished. A failed verify destroys the schedule.

## Evidence

Seven unit-test groups pass:

- RFC 8448 §3: published ClientHello through client Finished; transcript hashes,
  early/handshake/master secrets, both handshake/application secrets, both
  Finished MACs, exporter master, resumption master, and ticket nonce PSK
- RFC 8448 §4: published resumed PSK, truncated ClientHello binder hash/MAC,
  complete ClientHello transcript hash, and early traffic secret
- RFC 8448 §5: published CH1/HRR/CH2/ServerHello transcript hash and handshake keys
- Every one of 256 server Finished bit flips and wrong MAC lengths rejected
- All ClientHello truncations, trailing bytes, synthetic message injection,
  illegal/repeated HRR, transcript overflow, wrong stage, invalid PSK/ECDHE
  input, and HKDF bounds rejected
- Exporter output independently checked using OpenSSL 3.5.7 HKDF EXPAND_ONLY;
  label/context/output-length separation tested

Checks performed: host unit tests, strict library Clippy, and
`thumbv6m-none-eabi --no-default-features` compilation. These are known-answer and
regression tests, **not formal verification of Rust or the cryptographic
primitives**, complete TLS interoperability, final no-allocator linking of an
endpoint, or Pico hardware results.

## Still required

- Full client/server TLS handshake state and extension negotiation
- Bounded certificate/X.509 and CertificateVerify validation
- Entropy and audited ECDHE/group-public-key validation
- PSK identity/ticket issuance/storage, expiration, and replay protection
- QUIC traffic-secret installation and key-retirement/update lifecycle
- Authenticated transport-parameter validation and handshake confirmation
- SHA-384 if AES-256-GCM is offered
- Complete no_alloc endpoint linkage, allocation instrumentation, RAM/stack/flash
  measurements, negative/fuzz/formal checks, and Neqo/Pico gates

Sources: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-7),
[RFC 8448](https://www.rfc-editor.org/rfc/rfc8448).

The separate bounded P-256 full-handshake profile is now integrated; see
[bounded-tls.md](bounded-tls.md) for its tested scope and remaining release gaps.

## Resumption-only ownership

After `derive_resumption` at the authenticated client-Finished transcript,
`take_resumption_master()` moves only the resumption master into a separate
`ResumptionMaster`. Extraction is one-shot and immediately discards all other
schedule secrets, including both original application traffic secrets and the
exporter secret. The schedule becomes terminally Discarded. The new owner is
32 bytes, non-Clone/non-Debug, and inherits zeroization on drop from Secret32.

`ResumptionMaster::derive(ticket_nonce)` uses the same existing HKDF resumption
label as `resumption_psk`; it does not authorize early data, cache tickets, or
check their lifetime/identity. Empty through255-byte nonces are structurally
allowed; nonce uniqueness remains the ticket manager's duty. Tests cover stage
checks, repeated extraction, destruction of other secrets, nonce separation and
the existing RFC8448 ticket PSK vector after the schedule has been dropped.
