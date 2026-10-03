# Bounded-profile HTTP/0.9 development adapter

`hq` uses `BoundedTls` and this repository's real QUIC/STREAM implementation.
It does not wrap another QUIC engine. Build the **host package**, whose normal
dependency closure avoids the allocating rustls reference-provider feature union:

```sh
cargo build --release --locked --manifest-path adapters/host/Cargo.toml --bin hq
```

The host filesystem, CLI, PEM setup and process runtime allocate. This is not a
claim that the whole host executable makes no allocations. The TLS/transport
buffers are explicit and bounded; whole-endpoint allocation measurements and
Pico hardware results are separate gates.

## Run

Use a real CA-issued ECDSA P-256 server chain and matching P-256 PKCS8 or SEC1
key. The client requires an explicit CA file and DNS hostname. No insecure mode,
implicit system roots or rustls TLS fallback is provided.

```sh
adapters/host/target/release/hq server \
  --listen 127.0.0.1:4433 --cert server-chain.pem --key server-key.pem \
  --www ./www --max-requests 2 --timeout-seconds 120

adapters/host/target/release/hq client \
  --connect 127.0.0.1:4433 --server-name localhost --ca ca.pem \
  --request /five-mib.bin --request https://localhost:4433/nested/small.txt \
  --downloads ./downloads --timeout-seconds 120
```

A repeated `--request` opens a bounded pipeline on **one connection**. Absolute
URLs must use `https://` and match the explicit hostname and destination port.
Path-only requests are also accepted. Query strings, fragments, whitespace,
HTTP/1.x headers and methods other than GET are rejected.

The server prints its actual listen address to stderr, including when port zero
is requested. `--max-requests N` provides deterministic completion after N
completed streams and outstanding application/control work drains. Without it,
the single-connection development server exits after two seconds of quiescence
after completed transfers. The default is a single connection. The explicit two-connection mode below is a bounded development dispatcher, not a production listener.

The client writes GET followed by CRLF and a stream FIN. Responses are file body
bytes terminated by FIN, with no HTTP/1.x response headers. Empty files use a
zero-length FIN. A server stream is counted complete only after its send and
receive halves become terminal. The client waits for completed bodies, stream
retirement and reliable application/control work, then lingers briefly to ACK
final peer traffic. A timeout, reset, malformed request, missing source file,
I/O failure or certificate error exits nonzero; an incomplete run is not success.

## Explicit cipher policy and IPv6

Both roles accept `--cipher-suite default|aes128|chacha20`. The omitted/default
policy preserves the existing AES-128-GCM plus ChaCha20-Poly1305 offer and
AES-first server preference. `aes128` offers/accepts only TLS_AES_128_GCM_SHA256
(0x1301); `chacha20` offers/accepts only TLS_CHACHA20_POLY1305_SHA256 (0x1303).
Unknown values and duplicate flags fail. A peer without a common allowed suite
fails the handshake; there is no fallback to the other suite. This is a real
construction-time TLS policy, applied before transcript and PSK binder hashing,
including HRR and ticket resumption. Initial QUIC packet protection remains the
RFC-required AES-based Initial protection irrespective of negotiated TLS suite.
JSON records both `cipher_policy` and the actual numeric `negotiated_suite`.

Use bracketed IPv6 socket addresses, e.g. `--listen [::1]:4433` and
`--connect [::1]:4433`. Authentication still requires a DNS `--server-name` and
an explicit trusted CA; choosing IPv6 never changes certificate validation.
The host's `--timeout-seconds` is a wall deadline. TP 1 is omitted, advertising
local max_idle_timeout=0; it is not inferred from this wall deadline.

`interop/neqo-verifying-peer/tests/test_hq_ipv6_cipher.py` exercises direct IPv6
loopback transfers to the unchanged official Neqo server and from the verified
Neqo library client. The library peer keeps its default group policy. This is a
development test harness, not the full runner IPv6/chacha20 gate or routed-network
coverage. The pending/concurrent dispatcher proposal is in
`docs/bounded-host-dispatcher-proposal.md`; current host dispatch remains sequential.

## Version negotiation listener

While waiting for a new connection, the server answers eligible unsupported,
nonzero versions with one unprotected Version Negotiation packet advertising
only QUIC v1. It first filters retained original/local/Retry CID aliases. The
version-invariant input CID lengths can be 0..255 bytes; the reply swaps those
CIDs. A whole untruncated datagram of at least 1,200 bytes is required; the reply
is at most 521 bytes. Ordinary UDP payloads up to 65,527 bytes are supported by
this helper; jumbograms are outside its profile.

One listener-wide fixed window permits 64 prepared replies per 1,000,000
microseconds, using the same monotonic epoch across the two admission phases.
Adjacent windows may each use the full quota. A local send rejection does not
refund that quota or trigger autonomous retries. Header bits use OS entropy;
responses go once to the actual datagram source and use Not-ECT. Malformed,
undersized, already-supported-version and VN input never generate a VN response.
No authentication, validated address, TLS state or application success is inferred
from this unauthenticated exchange. During an active sequential connection the
existing connection owner still controls admission; this is not a concurrent
production listener.

`reference-tls/tests/test_hq_version_negotiation.py` is the actual UDP listener
regression, including maximum-length/empty CIDs, silence, quota and a subsequent
certificate-verified exact-hash transfer. Client version switching is not provided.

## Two-connection 1-RTT resumption

Add `--connections 2` to the client and `--max-connections 2` to the server.
The client transfers exactly its first request on connection one, consumes an
actually received authenticated ticket, then transfers every remaining request
on a fresh connection. At least two distinct request destinations are required.
The server serves exactly one request on the first connection; `--max-requests`
counts both connections and must be at least two when supplied. Both persistent
connections remain routed through real CONNECTION_CLOSE/draining until Closed.
The client retains the old bound socket, so the next connection uses another
source port; the server rejects Initials naming retired connection IDs.

One bounded client cache slot (maximum ticket identity 4,096 bytes), one server
ticket key and two single-use replay slots live outside the per-connection TLS
state. No ticket/PSK/private-key serialization or key logging is implemented.
Each connection gets fresh CIDs and a checked generation increment shared by
Config, Driver and stream ownership. Certificate/hostname/time verification
establishes trust on the first connection. Cache lookup binds the current roots,
verification limits, SNI/ALPN and exact previously negotiated cipher suite.
A resumed handshake performs fresh ECDHE and Finished authentication; no stream
is opened before handshake completion and 0-RTT remains disabled.

`--require-resumption true` is the two-connection client default. If the server
declines a ticket, success is rejected before second-connection application
work. Explicit `false` permits a full certificate-authenticated fallback.
`--resumption-delay-ms 0..60000` adds a bounded delay before the second connection.
The server's optional controls, requiring two-connection mode, are:

- `--ticket-lifetime-seconds 1..604800`, default 60, with strict exclusive expiry
- `--ticket-age-skew-ms 0..300000`, default 10000, in trusted monotonic milliseconds
- `--ticket-policy-second STRING`, bounded to 256 bytes, to exercise policy fallback
- `--rotate-ticket-key-after-first true|false`, default false, to exercise unknown-issuer fallback

The 10-second default age skew accommodates handshake/closing/retransmission
delay between ClientHello encoding and server acceptance. This does not extend
ticket expiry or authorize early data. In a measured loopback case, server age
1,379ms versus client-reported age 317ms (delta 1,062ms) correctly declined under
the earlier 1-second policy; the same approximately 1.06-second delay resumes
under the explicit 10-second policy. Failed and successful cases are retained in
`artifacts/host-resumption/age-1000.json` and `age-10000.json`. The diagnostic
trace identifies a second Initial arriving while the previous server is Draining,
then a fresh-PN PTO retransmission about 999ms later. This is a sequential-host
tradeoff, not an unavoidable network delay. RFC context, exact timestamps and
policy-boundary evidence are in `artifacts/host-resumption-age/README.md`.

The aggregate JSON contains two independent connection reports, actual
`resumed`/`handshake_mode`, ticket-cache insertion/acceptance facts, negotiated
suite/group, generation and actual `lifecycle_closed`. `ticket_age` exposes only
elapsed milliseconds/delta from the locally issued ticket, never its age-add,
identity, PSK or private key. A resumed client report labels authentication as
`cached-ticket-finished`; its fresh certificate verification boolean is false.
A full first handshake or fallback reports `verified-certificate` and true.
Server reports authenticate peer Finished, not a nonexistent client certificate.

See `docs/resumption-integration.md` for provider ownership/security rules and
`interop/neqo-verifying-peer/tests/test_hq_resumption.py` for actual direct Neqo
positive, trust, expiry, policy, unknown-issuer and recognized bad-binder cases.
The allocating Neqo wrapper is a development oracle, not an official CLI or the
full quic-interop-runner resumption gate. Host/Pico allocation qualification is
separate.

## Explicit key-update exercise

Either HQ role accepts `--key-update-after-bytes N` for one local key update,
where N is a positive byte count. The client counts body bytes delivered to its
file; the server counts body bytes accepted into the retained send queue. The
count spans the connection. Only the expected handshake/ACK authorization gate
or an outstanding adapter submission is retried. Unsupported-provider and other
errors fail the run. Leave enough body data after the threshold to exchange the
new phase; 1 MiB during a 5 MiB transfer is the regression profile.

JSON records the requested threshold, actual initiation byte count, local send
generation and **authenticated receive key generation**. With the option set,
success requires both local initiation and receipt of an authenticated new-phase
packet. A local generation change alone is insufficient. An unreachable threshold
fails even if all file bodies arrived; completed files are not rolled back. With
no option, the existing file-transfer success conditions are preserved, while
the report can still show a peer-initiated phase change.

`interop/neqo-verifying-peer/tests/test_hq_key_update.py` runs verified 5 MiB
transfers with bounded-server and Neqo-client initiation, plus optional bounded
client initiation to the unchanged official Neqo server. All hashes and bounded
receive generations must match the assertions. `artifacts/key-update-transfer/direct-neqo.json`
records all three paths and both unreachable-threshold negatives passing. The
peer README has the reproduction command. This is direct development evidence,
not the full runner keyupdate testcase or an allocation/Pico qualification.
`certificate_verification_profile` labels the supported bounded verifier, and
`bounded_server_signing_profile` labels its server signing capability. Neither
asserts which peer signature was actually used. The separate numeric
`negotiated_group` reports the actual key exchange (29=X25519,23=P-256).

## Storage and file safety

- Four live HTTP streams; cumulative stream IDs grow independently of these slots
- 4,096 receive bytes plus presence bitmap per live stream
- Sixteen 1,024-byte retained send chunks, 128 packet references
- Sixty-four numeric control records and 128 control references
- Initial/1-RTT CRYPTO windows of 8,192 bytes; Handshake window of 16,384 bytes,
  each with its exact-size presence bitmap
- Bounded TLS RX/TX/certificate buffers of 16,384 bytes each, peer TPs 2,048 bytes
- Bounded GET line buffer of 1,024 bytes; target length at most 1,000 bytes
- File bodies are read/written one chunk at a time, regardless of file size

The current host capacities are a host profile, not a Pico SRAM measurement.
The stack must accommodate these caller-owned arrays and additional connection
state; embedded profiles must budget their own storage explicitly.
The HTTP state also has a fixed live-file map; the CLI request list is capped at
4,096 entries. Input flow credit is backed by actual receive-window capacity.
Consumption emits reliable MAX_DATA/MAX_STREAM_DATA updates; retiring incoming
streams emits MAX_STREAMS. ACK, threshold loss and PTO are driven through the
same transport engine and typed driver as other packets.

Linux directory descriptors anchor every file lookup. Each subsequent component
is opened relative to its held parent with `O_NOFOLLOW`, and directory components
also require `O_DIRECTORY`. Dot traversal, backslashes, empty components,
encoded separators and control characters are rejected. Percent decoding occurs
once. A symlink cannot redirect a request or download outside its root.

Downloads stage to an exclusive `.hibana-*.part` file and become visible at the
requested final name only after a complete FIN body is consumed and synced.
Publication uses no-overwrite hard-link creation in the held parent directory;
an existing destination, including a symlink, is never overwritten. Normal
failures remove staging files; process crashes may leave clearly unfinished
`.part` files. Use roots that are not writable by untrusted local users. Source
files should remain stable during transfer; the adapter does not snapshot them.

## Reproducible local test

```sh
python3 reference-tls/tests/test_hq_localhost.py \
  --binary adapters/host/target/release/hq --negative-auth \
  --output artifacts/hq-localhost-bounded.json
```

The script creates an ephemeral P-256 CA/leaf with OpenSSL, runs separate client
and server processes over UDP, transfers eleven actual files (including a 5 MiB
file, nested names and an empty file), and compares every SHA-256 and length.
Wrong-hostname and wrong-CA checks must both fail before any file is downloaded.
Private fixture keys stay in temporary directories and are not written to the
artifact report. The report records the tested binary hash and both process
results. `cargo test --manifest-path adapters/host/Cargo.toml --bin hq` additionally
checks traversal, symlink parents/leaves, replacement of the root pathname,
no-overwrite publication, staging cleanup, URL authority and GET parsing.

## Evidence boundaries

`artifacts/hq-localhost-bounded-hardened.json` records the latest clean bounded-host run after path/FIFO hardening; `artifacts/hq-localhost-bounded.json` retains the earlier successful attempt. The
older `artifacts/hq-localhost.json` records the slower debug executable built
inside the reference package; do not substitute it for the clean dependency
closure evidence.

`artifacts/hq-direct-neqo/forward.json` records the bounded client against the
unchanged, pinned official Neqo server. That direct test uses Neqo's documented
non-QNS numeric-path service (N zero bytes), checks actual downloaded hashes and
uses explicit CA/hostname verification. It does not exercise QNS `/www` file
serving or the simulator/pcap runner gate. `artifacts/hq-direct-neqo/reverse-regression.json` records the opposite direction using the certificate-verifying Neqo library peer (wrapper revision 3), with an actual 5 MiB source file, empty FIN and negative authentication checks. That peer is not the official CLI; the run explicitly selects P-256, so it does not validate default-group HRR behavior.

Retry, resumption, 0-RTT, migration, HTTP/3, qlog and TLS keylog export are not
provided by this CLI. RSA and the complete mandatory TLS algorithm set remain
separate requirements. `ROLE`, `TESTCASE`, `REQUESTS`, `QLOGDIR` and
`SSLKEYLOGFILE` runner integration is not silently inferred by this executable:
use an explicitly reviewed runner wrapper. No direct development result counts
as any of the required 40 quic-interop-runner combinations or Pico HIL results.

`--ecn on` enables the integrated ECN probe/validation path; see [ECN.md](ECN.md)
for real kernel metadata, ACK_ECN feedback, congestion response and fallback evidence.

## Address-validation Retry (single-connection development dispatcher)

Server `--retry` is a unary opt-in flag. Before constructing a per-connection TLS
provider, the adapter sends a real QUIC v1 Retry for a tokenless Initial and only
admits an Initial carrying a valid token for its actual UDP source IP/port and
unchanged client source CID. The returned destination CID must match Retry SCID.
`--retry-lifetime-ms N` (1..=60000, default 10000) is server-only and requires
`--retry`. Without the flag, the previous server bootstrap is unchanged.

The issuer uses a fresh OS-random AES-GCM key per process, a monotonic nonce
counter, short monotonic expiry and a fixed 64-entry new-admission replay cache.
It returns at most one Retry per incoming datagram. Each raw Retry is smaller
than the required >=1200-byte input datagram; no failed raw UDP send is retried
without another received datagram. This bounds pre-validation amplification
without retaining an unbounded source-address table. Raw Retry uses Not-ECT.

Tokenless retransmissions can receive additional Retry packets. Invalid tokens
are silently discarded, without another Retry response. After one successful
admission, packets from that same UDP peer go directly to the existing endpoint;
repeated token-bearing Initials are ordinary packet retransmissions, not another
new-connection admission. This CLI accepts one connection and does not claim a
production listener, concurrent admission capacity, cross-process token sharing,
address migration, or indefinite key rotation.

The token's original DCID and Retry SCID are copied into server transport
parameters 0 and 16; parameter 15 is the actual server Initial SCID, which may
differ. `new_after_retry` consumes the validated admission, derives Initial keys
from Retry SCID and marks only that bound path validated. The first admitted
packet's real ECN metadata is preserved. Existing ECN and key-update modes remain
available. Success JSON includes `server_retry` with enabled, input_datagrams,
accepted packets_sent, invalid_tokens and admissions; raw Retry datagrams are
included in the aggregate UDP counters. Failure JSON makes no admission claim.
