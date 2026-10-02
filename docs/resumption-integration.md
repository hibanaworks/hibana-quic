# Bounded 1-RTT resumption

The bounded provider now implements real TLS 1.3 PSK_DHE resumption and post-handshake NewSessionTicket issuance/retention. Both Finished messages and fresh X25519/P-256 ECDHE remain mandatory. The existing certificate-only constructors keep tickets disabled. Ordinary constructors do not enable0RTT; the separate explicit early-data path and its remaining qualification gates are documented in [early-data-integration.md](early-data-integration.md).

## Ownership and API

`tls_ticket` supplies caller-owned `TicketKey`, bounded `ReplaySlot` and `ClientSlot<BYTES>` slices, `ClientCache`, consumed `ClientOffer`, and object-safe borrowed `ServerTicketStore`, `ClientTicketStore` and `TicketClock` services. There is no box or hidden allocation. Keep the server key and client cache alive across sequential connections; recreating either for every connection cannot demonstrate resumption.

Provider constructors are additive:

- `BoundedTls::client_with_tickets(config, storage, rng, ClientResumption { store, clock })`
- `BoundedTls::client_resuming(config, storage, rng, ClientResumption { store, clock }, offer)` consumes the selected offer
- `BoundedTls::server_with_tickets(config, storage, rng, ServerResumption { store, entropy, clock, policy, lifetime_seconds, max_age_skew_ms })`
- `BoundedTls::server_p256_with_tickets` applies the existing explicit P-256-only group policy for genuine HRR testing
- `is_resumed()` returns true only for a connected, successfully PSK-authenticated handshake

`KeySchedule::take_resumption_master()` moves the resumption secret only after client Finished and immediately destroys every other schedule secret. The non-Clone/non-Debug 32-byte `ResumptionMaster` derives ticket PSKs with the existing HKDF label implementation. A ticket-enabled client retains it for authenticated NST reception; the server drops it after its single NST is queued. Failure, owner drop and application-key retirement destroy the retained owner. Ticket-disabled connections retain no resumption master.

The server waits until it verifies client Finished before issuing at most one NST. Its bounded pending output explicitly uses `Level::OneRtt`; it is fragmented through the ordinary output interface and never appended to the handshake transcript. An undersized output slice does not claim publication. The client only processes NST at authenticated OneRtt level in Connected state. Zero/excessive lifetime tickets are discarded. Full/duplicate cache insertion is a discard decision; other failures remain explicit. The provider wipes consumed post-handshake RX bytes.

## Trust and origin binding

`VerificationContext::new(anchors, certificate_limits)` hashes a versioned verifier-profile identity, all configured certificate limits, ordered anchor subjects/SPKIs and optional name constraints. Profile v2 covers P256 plus exact RSA2048/3072/4096 SHA256 verification, PSS-rsae/salt32, certificate-only PKCS1, depth8 and the existing usage/name checks. It excludes advancing clock time. Reordering equivalent anchors conservatively misses the cache; changes to future verifier semantics must advance the profile identity. Current ticket lifetime/age rules govern reuse duration; this is not a fresh certificate validation on every resumption.

The provider inserts tickets with `ClientCache::insert_verified`. Callers select with `take_verified_for_origin(now_ms, origin_binding, suite, verification_context)`. The resuming constructor independently checks the actual new `ClientConfig` digest and SNI/ALPN against the consumed offer, even if a caller selected it through the older generic lookup. Changed trust roots/limits and legacy unverified entries return `VerificationContext` rather than silently resuming.

Server authenticated tickets bind case-normalized DNS SNI, exact ALPN, canonical stable QUIC transport limits and explicit bounded server policy bytes. Parsed numeric defaults/non-minimal encodings and parameter order normalize to the same values. Connection-specific CIDs/reset tokens are excluded. Unknown/application-specific stable policy must be represented in the explicit policy bytes. Client cache origin selection need not know the next connection's server limits; the server still checks its complete current binding before selecting PSK. Remembering this digest is sufficient for this 1-RTT policy, but is not storage or authorization of remembered 0-RTT limits.

## Ticket security and bounds

The original private128-byte ticket has advanced to version2/201bytes for authenticated early-permission and remembered-limit fields; see [early-data-integration.md](early-data-integration.md). It uses pinned RustCrypto ChaCha20Poly1305. Its authenticated header contains format version, a random key ID and nonce. Its encrypted body contains PSK, suite, issue time, lifetime, random age-add, binding digest and an early-data flag that remains zero for ordinary1RTT constructors. Keys are generated only from injected fallible CryptoRng, are non-Clone and zeroizing, and have no fixed/raw-key import API.

One key may reserve at most 2^32 unique counter nonces; abandoned or failed reservations are burned. After 2^24 failed tag checks it retires and wipes. Lifetimes are positive and at most seven days with an exclusive expiry boundary. Injected clocks use trusted milliseconds; rollback, arithmetic overflow and excessive configured age skew fail closed. Client and server clocks have independent epochs but must each preserve their owner's timeline.

Client entries are consumed before exposure, selected oldest-first and never evict live entries implicitly. Server replay policy is explicitly `ReusableOneRtt` or `SingleUseOneRtt`. The latter has a bounded, exclusively borrowed ledger: only a successful final binder acceptance commits a use, live entries are never evicted, and only expired entries may be reused. `TicketKey::check` validates CH1 before HRR without consuming its single-use slot; CH2 must call `accept` with its recomputed binder. Neither replay mode authorizes early data. Process/key replacement invalidates old tickets; persistent import, multi-process sharing and rotation grace keyrings are absent.

## Wire and state requirements

The explicit PSK codec profile supports one identity (at most 4096 bytes) and one 32-byte SHA-256 binder, with matching counts, PSK extension last and known `psk_dhe_ke` mode. It rejects `psk_ke` selection and early-data negotiation. Strict certificate-only parser entry points still reject PSK. The binder prefix ends immediately before the binders vector length, while all enclosing lengths retain their full-message values. ServerHello may select identity zero only for an offered, accepted PSK and the exact original suite. This is a conservative interoperability restriction even though both supported suites use SHA-256; independent suite-rotation resumption is not qualified.

Unknown/expired/policy-incompatible/replayed identities can decline resumption and perform full certificate authentication. A recognized acceptable ticket with an invalid binder is fatal authentication failure. A PSK decline resets the client's early schedule before fresh ECDHE; it then requires normal certificate/hostname/CertificateVerify checks. Accepted PSK skips Certificate/CV, never Finished.

HRR preserves the existing strict one-requested-share rule, group/suite continuity, exact cookie and stable fields/extensions. Only PSK age/binder may change; identity stays identical. The binder uses the existing transcript's synthetic message_hash(CH1), actual HRR and truncated CH2. No extra GREASE share is admitted to pass a peer-specific test.

## Verified scope

- Ticket AEAD/binder, nonce, replay, capacity, age/expiry, zeroization and trust-digest unit tests
- Existing RFC8448 schedule/binder vectors, including one-shot resumption-master extraction
- `reference-tls/tests/resumption.rs`: full first connection then resumed connection, actual encrypted Handshake/OneRtt TLS/NST flights, fresh application keys and Finished, one-byte/127-byte/4096-byte fragmentation, and zero allocations for both constructors, real entropy, ticket/cache ownership and two complete provider handshakes
- The same six resumption tests also pass in the clean host release package, which has no rustls TLS dependency. Source/binary hashes and commands are recorded in `artifacts/resumption/manifest.json`
- Negative/transition tests cover changed trust anchors/limits even through an unfiltered lookup, known-ticket bad binder, expired/unknown issuer fallback, server policy/limit changes, cache pressure, and equivalent parameter encodings/CID changes
- `reference-tls/tests/resumption_rustls.rs`: real resumed handshakes in both directions against pinned rustls 0.23.45 QUIC with shared configurations, plus a resumed rustls client through an actual P-256 HRR; both sides' 1-RTT packet keys interoperate

These provider tests are not a persistent UDP host test or the runner resumption gate. Full endpoint/lifecycle integration and the host work below remain separate evidence. The allocating rustls peer is not included in the bounded allocation counter. The core builds for thumbv6m without alloc/std; final hardware RAM/stack qualification is still required.

## Proposed host integration

Reuse the clean `adapters/host` package and existing shared `hq`/`bounded-handshake` sources. Add an explicit bounded sequential-connection mode, initially exactly two connections, rather than claiming that a single handshake proves resumption. Keep OS entropy, injected `Instant`-based millisecond ticket clock, root material, one fixed cache slot and one server key/replay slice outside per-connection construction. Do not serialize PSKs/private ticket keys or enable key logging.

For each connection, allocate fresh random CIDs and a checked new transport/Driver generation; `Config.generation` must equal `Driver` generation, and every transmit callback must carry that generation. Preserve first-generation state until its callbacks/packets are retired according to the real lifecycle, or route stale packets by CID and reject them. Never reuse a descriptor from connection one in connection two.

Client flow: authenticate and flush the first connection, keep reading authenticated OneRtt CRYPTO until an NST is actually cached within its bounded deadline, close/retire appropriately, consume an offer matching the current trust configuration, then create and drive connection two. Server flow: use the same ticket key with a new independent transport/TLS connection and checked generation. Report each connection's full/resumed status, authenticated peer and output completion separately; a requested resumption test fails if connection two merely falls back.

Suggested explicit CLI additions are `--connections 2` and `--require-resumption true` on the client and `--max-connections 2` on the server. These flags are a proposal, not implemented commands. The existing hq transfer interface can later map the pinned runner's real resumption testcase onto this lifecycle; retain exact runner fixture/authentication and file checks. No success may be inferred from queueing a ticket, a timeout, or a full fallback.

0-RTT remains rejected until a separate server anti-replay policy and actual remembered QUIC transport limits/application replay policy are implemented and verified.
