# Bounded TLS handshake profile

`src/bounded_tls.rs` implements real client and server TLS 1.3 full handshakes
through `tls::Provider`, using caller-owned storage and RustCrypto/webpki. It is
an explicit **X25519/P-256 ECDHE and SHA-256 authentication profile**. Clients
verify ECDSA-P256 and bounded RSA identities; server credentials still sign with
ECDSA-P256. This is not completion of the mandatory TLS algorithms or QUIC matrix.

## Implemented path

- ClientHello/ServerHello with X25519/P-256 ECDHE, TLS_AES_128_GCM_SHA256 or
  TLS_CHACHA20_POLY1305_SHA256, ECDSA secp256r1 SHA-256, hq-interop, and QUIC v1 TP
- Client RSA-PSS-rsae/SHA256 CertificateVerify and RSA PKCS1/PSS certificate
  verification for exact 2048/3072/4096-bit keys. ClientHello advertises RSA-PSS
  for CV and PKCS1 only through signature_algorithms_cert; server signing stays P256
- Injected fallible RngCore + CryptoRng for randoms and bounded scalar sampling
- Vetted curve-point validation and ECDHE; ephemeral private key dropped after use
- Client validation of chain, hostname, caller-supplied time, EKU and KeyUsage
- Correct server CertificateVerify signature and client verification
- SHA-256 transcript/traffic schedule and both Finished MACs
- Negotiated packet and header protection for Handshake and 1-RTT
- Fixed-storage QUIC key updates with unchanged HP, authenticated promotion,
  transport ACK/confirmation gates, and bounded old-read-key retention; see
  [key-updates.md](key-updates.md)
- Fail-closed handshake errors, terminal secret destruction, AEAD limits and PN
  reuse rejection; explicit irreversible packet-key retirement
- One complete inbound TLS message at a time, with checked framing and level
- Outbound flight fragmentation retaining Initial/Handshake boundaries
- ServerHello stays Initial; the remaining server flight and client Finished stay
  Handshake. There is no TLS-record wrapping or plaintext transport substitute
- One bounded HRR: server requests P-256 when supported but not initially shared;
  client supports cookie-only retry and rejects repeated/same-group retries
- Strict ClientHello2 invariant/cookie/suite checks and RFC transcript replacement
- Optional caller-owned authenticated tickets/cache and real PSK_DHE resumption,
  trust-context/origin/transport-policy binding, strict HRR binders and OneRtt NST
  output; see [resumption-integration.md](resumption-integration.md)
- Ticket-disabled constructors validate and discard authenticated NST; all modes
  retain QUIC early_data sentinel checks and wipe consumed post-handshake RX bytes
- Unknown offered PSK modes, including NSS GREASE, are ignored; only psk_dhe_ke
  is selected when explicitly enabled, and 0-RTT remains unsupported

The TLS state reports Connected after verifying peer Finished and generating its
own Finished for transport. The endpoint/host adapter separately flushes queued
TLS output and checks authenticated transport-parameter semantics before its
handshake-success report. Server signing-key/certificate consistency is checked
at construction. There is no certificate-verification bypass or rustls fallback.

## Ownership/API

`Storage` borrows four independent buffers: rx_message, tx_flight,
peer_certificates, and peer_parameters. The RX buffer holds the largest complete
handshake message; TX holds one full outbound flight. Certificate storage holds
ClientHello1 during retry, then an encoded Certificate message plus fixed
offset/length descriptors. Server scratch must also fit ClientHello1 for HRR. No
self-reference is stored; the client reborrows/revalidates the retained chain at
CertificateVerify. Parameters are exposed only after TLS completion.

`ClientConfig` borrows DNS name, trust anchors and local encoded parameters, and
supplies UnixTime and certificate limits. `ServerConfig` borrows the DER chain,
P-256 SigningKey and local encoded parameters. Both constructors accept an
external cryptographic RNG. Optional ticket services borrow caller entropy and
clock callbacks. The provider performs no file/network I/O, implicit system-clock
access, or hidden allocation.

Buffers and long-term server credentials outlive the provider. Overflow or an
unsupported profile choice fails explicitly. Buffer contents are never silently
truncated and an intermediate CA is never promoted to a trust anchor to shorten
an otherwise unsupported chain.

## Evidence and allocation scope

`reference-tls/tests/bounded_tls.rs` has thirteen test groups:

- Bounded client/server full handshakes at 1/3/17/127/4096-byte fragmentation
- Bounded client ↔ default rustls server and verifying P-256-constrained rustls
  client ↔ bounded server, with matching AEAD/header-protection results
- Wrong CA, wrong hostname and corrupt Finished failures; injected entropy failure
- Zero measured allocations for both bounded constructors, actual entropy calls,
  full two-sided handshakes, and bidirectional packet-protection checks
- Additional zero-allocation measurements for entropy, malformed framing,
  capacity, corrupt-Finished failure branches, and fragmented ticket discard
- Default rustls X25519-first client completes a real P-256 HRR handshake; every
  bounded-server constructor/Provider call is independently checked for zero
  allocation, excluding the allocating peer
- Changed CH2 random, repeated/same-group HRR, retry suite mismatch, wrong-role/
  wrong-level tickets, malformed tickets, and invalid QUIC early_data reject

PKI generation, root import, PKCS8 decoding and caller-buffer preparation occur
outside that handshake counter. The separate certificate smoke measures root
parsing and certificate validation. The reference package's rustls std dependency
can feature-unify allocation-enabled webpki diagnostics: this is NOT evidence
that every error path in that mixed host package is allocation-free. The
standalone main crate's thumbv6m/default dependency closure has alloc/std disabled.

`reference-tls/tests/bounded_wire.rs` measures zero allocations through real
Hibana session/Driver setup, bounded TLS constructors, encrypted QUIC packets,
corrupt Initial discard, fresh-PN PTO retransmission, authenticated completion,
1-RTT HANDSHAKE_DONE and key retirement, bidirectional key updates and phase
wrap, delayed/expired old-key packets, and pending-output Busy handling. Caller
storage/PKI setup are excluded.
Earlier route/capacity failures are preserved in artifacts, not counted as passes.
The active choreography uses 24 carrier ports with 16-byte descriptors and a
32-KiB runtime slab; this is not the complete endpoint RAM/stack budget.

The clean-host `bounded_streams` release test additionally measures a full
TransportEndpoint 5-MiB stream transfer, real loss/corruption/rejection recovery,
flow-credit replenishment, both-role key updates, stream/local endpoint
retirement and drops, plus a terminal wrong-CA handshake failure. PKI and caller
storage preparation are excluded. See [bounded-stream-allocation.md](bounded-stream-allocation.md)
for the measured boundary; local retirement does not establish QUIC wire
closing/draining behavior.

## Direct Neqo evidence

`artifacts/direct-bounded-neqo/20261002-031930/manifest.json` pins a frozen
executable SHA-256 and unchanged before/after-build source hashes. All attempts,
including earlier failures and log-disabled attempts, are retained separately.

- Bounded client → official unmodified Neqo 0.32.0 server: authenticated success;
  Neqo logs Complete/Connection established, group 23 and hq-interop
- Verifying Neqo-library wrapper revision 2 with `--group p256` → bounded server:
  both processes succeed, Neqo reaches Confirmed after real certificate
  chain/hostname/time verification and publishing post-authentication CRYPTO
- Wrong hostname and wrong CA reject in both directions; no negative run reports
  handshake success

The reverse peer is an explicitly group-constrained wrapper using Neqo's public
API, not the official neqo-client CLI or evidence of default-group/HRR support.
This is authenticated direct handshake smoke, not quic-interop-runner file
transfer/pcap acceptance or a 40-case release result.

The clean `adapters/host` Cargo package builds the shared host command
`reference-tls/src/bin/bounded-handshake.rs` using only BoundedTls and without
a rustls TLS dependency. Its webpki verifier does not enable alloc/std diagnostics.
Its report labels backend bounded-profile and mandatory_tls_algorithms_complete
false. PEM/filesystem/socket/diagnostic setup is ordinary allocating host code.

The RSA verification expansion has separate evidence in
`reference-tls/tests/rsa_tls.rs`: real rustls servers with fresh RSA
2048/3072/4096 keys authenticate to the bounded client, both Finished messages
complete, and 1-RTT packet keys match. A corrupted RSA CertificateVerify carried
inside a valid encrypted packet fails closed. Bounded calls measure zero
allocations; host key generation and the independent peer are excluded. See
[tls-certificate.md](tls-certificate.md) for exact algorithm/size policy and
substantial target stack costs.

## Explicit release gaps

- RSA server signing, other RSA key widths/PSS-restricted SPKI, SHA-384/P-384 and
  other algorithm profiles; the bounded RSA verifier still needs final target
  stack/latency qualification
- Persistent host/runner resumption integration, 0-RTT/replay policy, client authentication
- Revocation/OCSP/CRL and dynamic trust/time provisioning
- The reviewed private webpki depth-eight extension accepts the runner's nine-
  certificate chain with genuine root, name, time and constraint verification.
  Both host adapters provide a 16 KiB TLS/Handshake-CRYPTO profile; full nine-chain
  TLS/no-allocation and localhost UDP handshakes pass. The runner amplification
  assertions and final target stack/Pico memory qualification remain open; see
  `webpki-depth8.md` for the pinned source delta and measured stack subtotal
- Final whole-endpoint allocation-free linkage, adversarial all-path allocation
  evidence, RAM/stack/flash measurement, and Pico hardware execution
- Full Neqo runner matrix, recovery/congestion/migration coverage, and formal
  correspondence proofs. Separate broad Hibana offer-path issues are not claimed
  fixed by this TLS implementation


## Default-group Neqo HRR caveat

The clean-host frozen attempt in
`artifacts/direct-bounded-neqo/20261002-033830-hrr/manifest.json` records forward
success but reverse default-group failure. Its actual Neqo ClientHello2 carries
the requested P-256 share plus a second GREASE share. The strict retry validator
rejects this; the implementation is not silently relaxed to count the run as a
pass. Reverse wrong-CA/name attempts in that snapshot stopped at this earlier
parser issue and are **not** counted as authentication-negative evidence. The
older explicit P-256 group-constrained reverse success and security negatives
remain separately valid.

RFC 8446 §§4.1.2/4.2.8 require a single requested retry share; RFC8701 §5 requires
GREASE senders to honor protocol constraints. Current RFC9846 (July2026), which
obsoletes RFC8446, retains the only-requested-share rule. Current-standard changes
also require a separate acceptance-matrix review; this project does not claim
complete RFC9846 compliance merely because older vectors pass.
