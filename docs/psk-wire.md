# Bounded PSK_DHE and ticket syntax

The additive `*_psk` APIs in `tls_wire.rs` implement syntax only. They do not
authenticate binders, authorize a ticket, establish trust, install keys or
complete a TLS handshake. Provider, key-schedule and ticket-store tests qualify
those separate operations. Legacy parsers still reject actual PSK offers and
selections; all 27 pre-existing syntax tests continue to pass.

The bounded profile accepts one identity of 1–4096 bytes and exactly one
32-byte SHA-256 binder. It requires `psk_dhe_ke`; unsupported offered modes are
ignored, while a PSK offer without DHE support is rejected. Client early data
remains rejected. The signature-algorithm offer for certificate fallback remains
required. A PSK ServerHello selects identity zero and still includes a valid
P-256 or X25519 key-share encoding.

`PskOffer::binder_prefix` is an offset into the complete handshake message,
ending before the binders vector's two-byte length. `binder_offset` points to the
32-byte binder value. All enclosing message/extension lengths include the full
binder vector, as required by [RFC 8446 §4.2.11.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11.2).
The encoder emits a zero placeholder. A provider must copy the scalar offsets,
compute the binder over the correct transcript prefix, and replace that
placeholder before exposing the message to transport.

The PSK extension must be last. CH2 preserves the single identity, original
fixed fields and all unchanged extension bytes/order. Only the requested
key-share replacement, exact cookie echo, allowed zero-padding changes, ticket
age and binder can differ. Cookie-only retries retain both original shares.
The provider must still enforce one HRR and the transformed transcript.

NST parsing returns borrowed nonce/ticket fields, lifetime, age-add and a valid
QUIC early-data indication if present. Parsing does not make a ticket eligible
for storage or 0-RTT. Zero and excessive lifetimes remain structurally parseable
for discard compatibility; cache policy excludes them. The NST encoder rejects
lifetimes above seven days and never emits an early-data extension.

Twelve additional tests cover independent binder-tail bytes and truncation
offsets, one-identity/binder bounds, DHE mode, PSK-last, early-data rejection,
CH2 mutation constraints, ServerHello selection and DHE requirements, NST field
round trips, every truncation, short output buffers and single-bit malformed
input mutations. All 39 syntax tests pass. Evidence is in
`artifacts/psk-wire/syntax-tests.log`; the syntax module also compiles with
`no_std`, `forbid(unsafe_code)` and `thumbv6m-none-eabi`.

The integrated root suite subsequently passed280/280 tests, strict Clippy and
thumbv6m compilation (`artifacts/resumption/`). Provider-owned tests additionally
cover real bounded and bidirectional rustls resumption; those logs qualify
cryptographic behavior separately from this syntax module.
