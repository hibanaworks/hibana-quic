# QUIC-specific Hibana TLS integration plan

## Non-negotiable architecture

hibana-quic and hibana-tls compose **one shared global** and run its projected
locals. TLS is dedicated to this QUIC implementation: no TCP record/socket API,
executor dependency, allocator, compatibility provider or independent lifecycle
controller is introduced. Both crates use the same exact Hibana revision.

Ordering and authority belong to that global and its direct send/recv/offer
continuations. Do not mirror them in State enums, ready/created/discarded flags,
external dispatch tables, protocol helpers or communication wrappers. Numerical
crypto, parsing and fixed-storage operations are separate from communication.
Rust locals may retain actual owned secrets, bytes and errors; those values are
not replaced with flags, synthetic receipts or historical phase queries.

## The shared boundary

1. **Canonical global in hibana-tls.** QUIC embeds its actual TLS Flow inside the
   connection global. Remove the duplicate graph from QUIC rather than keeping
   two definitions synchronized. A namespace re-export performs no communication.
2. **Direct locals.** TLS verification/input roles execute the shared graph.
   QUIC supplies authenticated, reassembled CRYPTO bytes through its corresponding
   local. No callback proxy or compatibility FSM may choose the next TLS phase.
3. **Affine key transfer.** TLS exports the actual directional traffic secrets
   exactly once; QUIC consumes them to create packet-protection keys. QUIC packet
   formats, packet-number/nonce accounting and key retirement remain in QUIC.
   Secret-bearing owners have no public duplication constructor, Copy, Clone or
   Debug. No boolean stands in for possession or transfer of key material.
4. **Affine Finished transfer.** Only the verified TLS local can produce the
   Finished receipt. The actual receipt and authenticated parameter data cross
   the local boundary once. QUIC separately checks its transport parameters and
   handshake confirmation; early availability of application traffic secrets is
   not authentication or permission to deliver ordinary application data.
5. **Retained exchanges.** A completion arrival never cancels an already-started
   source/publication exchange. Independent endpoints remain runnable at queue
   capacity one. Wake parked TX from the actual event before awaiting its next
   Request/Taken exchange. Keep real ACK/PTO work live while Finished is missing.
6. **Actual storage only.** Any in-process handoff storage contains the real
   owned value, with exclusive producer/consumer access. It must not become a
   second state machine, an extra acknowledgement, or a readiness flag. Receive
   the projected event before taking its owned material; capacity rejection must
   preserve that material and successful transfer must reject repetition.
7. **Failure and cancellation.** Preserve the real error and retire the actual
   outstanding owners. Authentication failure must not expose plaintext; abort
   must not regenerate keys/nonces or fabricate a successful peer receipt.

## Ordered implementation and evidence

- [x] Connect QUIC to the separate TLS crate's canonical global; compile real
  connection roles and show exactly one Hibana crate identity in Cargo's graph.
- [ ] Move the direct TLS locals and their owned cryptographic context behind
  that boundary. Remove the legacy Provider escape and its handoff flag rather
  than reconstructing them as wrappers in the new crate.
- [ ] Replace key-created/key-discarded flags with actual affine secret ownership
  in the projected continuations. Preserve duplicate-generation, early-export,
  cancellation, wrong-scope and no-allocation negative tests.
- [ ] Complete the QUIC-only TLS crypto and authentication path. New primitive
  tests alone do not authorize replacing the production provider.
- [ ] Exercise full/resumed/HRR handshakes, rejected/accepted early data, invalid
  Finished, certificate/name/trust rejection, delayed/lost Finished, queue-one
  scheduling, real publication failure, cancellation and repeated transfer.
- [ ] Run core/host/reference tests, strict Clippy, no_std target checks and the
  applicable Lean/Z3 obligations on the exact final source. State each proof's
  scope; arithmetic lemmas are not Rust refinement or cryptographic security.
- [ ] Requalify both directions against pinned independent peers and the official
  44 candidate interoperability cells, keeping deadlines/capacities unchanged.
- [ ] Preserve every completed checkpoint as a source ZIP with verification
  limits. Before publication, replace any temporary sibling-path dependency with
  an actually published, immutable TLS revision and verify a clean checkout.

## Current verified pieces and limits

The QUIC source already consumes a projected TranscriptComplete event instead
of polling Connected. Finished handoff uses the actual owned verified receipt;
insufficient output capacity preserves it and repeated transfer is rejected.
Outward state/is_handshaking forwarding APIs have been removed and regression tested.
The separate hibana-tls currently contains the global and project-owned crypto
building blocks; complete direct TLS locals and production integration are not
finished. Existing non-Hibana production dependencies have not all been removed.
No new remote CI or full native interop qualification is implied by this plan.


The first connection is currently a paired-checkout path dependency. Root,
host and reference locks add only the project-owned hibana-tls package; all
three resolved graphs contain one exact Hibana identity. The composed connection
passed the 595 core/integration/doc tests. This does not imply that TLS locals,
key ownership or the production crypto backend have all migrated yet.

### HKDF package removal checkpoint

Production packet keys, TLS key schedule, connection-ID seeds and path challenge
seeds now use hibana-tls's bounded HKDF implementation. The external `hkdf`
package is absent from the resolved root, host and reference graphs and all three
lockfiles. P-256 keeps its existing validated-key arithmetic; dropping its `ecdh`
convenience feature removes the remaining transitive HKDF edge. Secret results
retain their Zeroizing owners. P-256 and other third-party packages still remain.

Validation: 595 core/integration/doc tests, 123 host tests, 55 TLS reference tests
(with one existing private-fixture test ignored), and thumbv6m no_std check passed.
The all-target strict Clippy run failed on existing-style lint findings across the
repository; this checkpoint does not claim strict Clippy or fresh remote CI passed.

### Borrowed RSA public-key parser

The `pkcs1` package is absent from the complete root, host and reference locks
and resolved graphs. `rsa/public_key.rs` reads only the exact borrowed DER
SEQUENCE of modulus/exponent, preserving key-size, odd-modulus and exponent
constraints. The independent `der` implementation remains in certificate code
and reference tests; it has not been eliminated. Dependency CI now rejects any
reintroduction of `hkdf` or `pkcs1`, including transitively.

Core/integration/doc tests: 599 passed. The reference suite's existing 55 tests
passed (one private-fixture test ignored); an added bit-mutation differential DER
test also passed, and all 1,224 signature corpus cases still match. Each public
RSA verification in this test is allocation-counted. thumbv6m check passed.
Strict Clippy's error descriptions matched the pre-HKDF shared-global baseline;
those findings still require cleanup. No remote CI result is implied.

### ChaCha20 and Poly1305 package removal checkpoint

QUIC packet payload protection, header protection and resumption-ticket encryption
now call hibana-tls's own bounded ChaCha20/Poly1305 arithmetic. The external
`chacha20`, `chacha20poly1305` and `poly1305` packages are absent from all three
complete dependency graphs/locks, alongside `hkdf` and `pkcs1`. Existing packet
number limits, confidentiality/integrity accounting, authenticated-before-plaintext
rules, failure-buffer wiping and ticket owners remain in their existing locals.
No protocol-progress flag or communication wrapper was added by this replacement.

599 core/integration/doc, 124 host and 56 reference tests passed, including
independent-peer ChaCha handshake/packet-key tests, RSA corpora and no-allocation
checks. thumbv6m passed. Primitive RFC/oracle vectors and the existing limited
Lean arithmetic lemmas do not establish complete cryptographic security,
constant-time machine code, guaranteed temporary erasure or Rust refinement.
AES, certificate and key-exchange dependencies still remain. The legacy
provider/flags and full TLS-local/key/Finished crate-boundary move are unfinished.

### AES package removal checkpoint

Packet/header/Retry-integrity AES-128 now uses hibana-tls's own AES/GCM. The
server's *private opaque address token* uses its existing 256-bit random key with
project-owned ChaCha20-Poly1305; its format prefix and AAD domain advance from
HQR1/v1 to HQR2/v2. Old-format tokens fail closed, without an algorithm fallback.
This does not change the RFC's public AES-128-GCM Retry-integrity construction.
Issuer nonce uniqueness, expiry, address/CID binding, replay consumption and the
same conservative issuance/authentication limits remain unchanged. A restart
already generated a fresh issuer key; seamless old-issuer retention must use its
matching old implementation until expiry rather than reinterpret its tokens.

The root/host/reference graphs no longer contain aes, aes-gcm, aead, cipher,
ctr, ghash, inout, opaque-debug, polyval or universal-hash. The combined source passed 599 core/integration/doc, 124 host and 56 reference
tests, plus the thumbv6m no_std check. Test deadlines and loss injections were
not relaxed. Target timing/performance and temporary
secret erasure are not qualified by functional vectors or length lemmas.

### X25519 package removal checkpoint

The raw X25519 operation now comes from hibana-tls. The existing non-Clone
one-use secret owner retains its Zeroizing storage and consumes itself on the
exchange; malformed lengths and all-zero results still reject. The shared global
and negotiation order have not been replaced with another phase controller.
The complete root/host/reference graphs contain no x25519-dalek,
curve25519-dalek, curve25519-dalek-derive or fiat-crypto. Some test-only macro
packages still occur in host/reference graphs, so removal from the root lock is
not reported as their complete elimination. The combined source passed 599 core/integration/doc, 124 host and 56 reference
tests and thumbv6m. These functional checks and limited limb lemmas do not prove
full cryptographic security, machine-code timing or temporary erasure.

## Authority at the crate boundary

A public wire decoder must not manufacture a private Finished authority from
arbitrary bytes. Hibana's public WirePayload codec validates payload-local bytes;
the endpoint kernel separately validates choreography context. Preserve the
actual verified, non-Clone owner through the projected local transfer and its
exclusive storage, rather than add a public receipt constructor or substitute a
boolean/decoded observation. The transfer must consume the real owner once;
cancellation must retain or destroy it consistently, never synthesize success.

The external-package elimination target includes Host and reference-test Cargo
graphs, not only default library features. Track both unique package names and
(name, version, source) identities. Independent-peer verification must remain
explicit and must not be relabelled as an internal self-test when a reference
crate is removed. Moving a dependency into vendor, another crate or a feature
flag is not elimination.

### Local cancellation obligation

TLS VERIFY locals no longer keep an Owner.complete boolean. The unfinished
borrow-only guard fails key material closed on cancellation/error. Only the
successful continuation after the actual Hibana Complete send discharges that
guard; it contains no owned buffer or key to leak. Message storage was already
cleared before the send. No inferred endpoint status or shadow phase is consulted.
Combined 599 core/integration/doc and 56 reference tests plus thumbv6m passed;
the reference tests include partial-input cancellation and aborted early owners.

### Actual integrity-budget handoff

The TLS key_handoff boolean is removed. Conversion into KeySource moves the real
IntegrityBudget out of TLS; legacy combined packet operations require possession
of that value. TLS retains neither a duplicated flag nor a depleted replacement
budget. Observations report absence after transfer instead of inventing a counter.
The dedicated forwarding getter is removed. The existing owned-role tests verify
failure-count continuity, denial of legacy operations and repeated transfer.
On Hibana 8302a07b, 599 core/integration/doc, 56 reference tests and thumbv6m passed.

### Authenticated application protocol follows Finished ownership

Application assembly now takes ALPN from the actual affine Finished receipt
received by its handshake continuation. The receipt owns the protocol validated
by the successful TLS transcript; the former KeySource forwarding getter is
removed. BoundedTls only exposes authenticated ALPN while it still owns that
receipt, and returns None after the receipt moves out. This removes application
admission's dependence on a historical State::Connected observation. It does not
claim that the remaining TLS lifecycle state or all key locals have migrated.

### P-256 and Finished MAC implementation

QUIC uses hibana-tls's own P-256 field/group arithmetic, ECDH,
RFC6979 ECDSA/SHA-256, and strict borrowed SEC1/PKCS8 private-key parsing.
Finished/PSK-binder HMAC and deterministic ECDSA nonce HMAC share the internal
primitive. Both p256 and hmac declarations are removed together across the
production, host and reference manifests; actual resolved closures are audited
before claiming package removal. Reference rustls/OpenSSL comparisons remain.
Generated-code side-channel behavior and compiler-proof secret erasure remain
unqualified. Passing vectors and interoperability do not prove those properties.

The validated production QUIC closure has 8 direct non-Hibana dependencies and
18 with transitives. Whole root/host/reference graphs retain 54 unique external
package names (57 version/source identities), including independent comparators.

### SHA-256 implementation

The transcript, ticket bindings, RSA encodings and authenticated-data digests
use hibana-tls's own incremental SHA-256 directly. There is no compatibility
wrapper around the removed package. Checked transcript/hash length failures
propagate before the owning transcript is replaced. Fixed, bounded QUIC digest
sites retain explicit bounds assertions. Independent reference engines remain.
The production candidate has 7 direct dependencies and 8 including transitives;
sha2 and seven associated packages are absent from all three complete locks.

### RSA public exponentiation

RSA certificate/signature verification uses hibana-tls's bounded public modular
arithmetic. crypto-bigint is absent from all three complete dependency graphs.
The previous three width-specific arithmetic adapter functions are removed.
The primitive has no private-key operations or independent protocol controller;
Hibana locals retain transcript order and authentication/ownership transitions.
The production closure is 6 direct non-Hibana packages and 7 with transitives.
