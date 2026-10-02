# Bounded path and connection-ID building blocks

Status: the opt-in endpoint now runs CID/path effects through real authenticated
QUIC and typed Hibana authorities. Two encrypted wire tests cover NAT port changes,
preferred-address validation, old-path ACK isolation, and authenticated used-token
reset/draining. A bounded 5 MiB stream test covers port and IP changes, lost old-path
flight, deadline-driven backpressure, exact bytes/FIN and retirement, with zero
allocator calls in the measured core/TLS/runtime path. The frozen host executable
also passes actual UDP 5 MiB baseline, NAT port/IP, concrete/wildcard preferred
address, and wrong-CA/name cases. These are direct development tests, not
quic-interop-runner results; the Neqo path matrix is tracked separately.

## Storage and evidence boundaries

`connection_id.rs` borrows caller-provided local/peer slot arrays. IDs own at most
20 bytes. The profile uses nonzero IDs. Every distinct sequence consumes a
lifetime history slot, including retired entries: arbitrary gaps are never
collapsed into a false retired high-water mark. `HistoryFull` is explicit local
resource exhaustion. Active limits and lifetime limits are separate. Provision
active capacity and a retirement backlog before advertising transport limits.
Local IDs should all use the endpoint's configured short-header CID length until
an unambiguous variable-length CID router is implemented.

Local sequence allocation and actual advertisement are distinct. `issue*` reserves
and starts routing a CID; `mark_advertised` is called only after an actual accepted
send containing its Initial/preferred-parameter/NEW advertisement. RETIRE above
the highest actually advertised sequence rejects. IDs below a requested retirement
floor continue routing until an authenticated RETIRE arrives. Retirement in a
packet using that same destination CID rejects. Random local CIDs/tokens must be
unpredictable and unique across connections; the caller supplies that entropy.

Peer NEW processing preflights sequence, CID/token conflicts, monotonic
retire-prior-to and active capacity before mutation. Tokens enter only through
methods whose input must already be authenticated. A token is eligible for reset
detection only after an actual accepted send on that CID and exact remote
address. Unused, retired and merely authorized-but-unsent bindings cannot match.
All eligible suffix comparisons use `subtle`; no early token match or header-bit
filter is used. Detection considers the original complete UDP datagram and never
interprets arbitrary AEAD failure as reset evidence.

`path.rs` borrows `PathSlot<SENDS, CONTROLS>` arrays and reuses the existing
`PathBudget` accounting. Each address is the exact local/remote IP-and-port pair,
including IPv6 scope where applicable. Handles include connection, slot and path
generations. Outstanding reservations consume 3x amplification credit; rejection
refunds pending bytes, while adapter acceptance commits the entire datagram.
Retirement invalidates old descriptors and slot reuse advances the epoch.

Challenges use eight bytes from a caller `CryptoRng + RngCore`. Pending challenges
are not response evidence until their send is accepted. Live collisions and RNG
failures fail closed; generation, lifetime and one-time consumption reject stale
responses. Retry scheduling uses PTO-style exponential backoff and bounded attempt
storage. Time is monotonic microseconds, matching the endpoint clock. The owner
supplies a validation timeout at least three times the larger current/new-path
PTO. A short, amplification-constrained probe validates only the address; a fresh
1200-byte probe must establish the required MTU. General DPLPMTUD is not implemented.

RFC9000 deliberately allows a response arriving on any path to validate the
original challenge's path. The arrival path is not the target selector. Incoming
PATH_CHALLENGE responses are instead queued on their exact receipt path and sent
at most once per admitted frame. The packet owner must suppress duplicate packet
replays before queueing responses.

## Migration policy

`migration.rs` records one active path, one last validated fallback and one
preferred-address candidate. The peer handshake must be confirmed before client
migration. Server selection changes only for the largest authenticated
non-probing packet number; reordered or probe-only packets do not select a path.
Apparent migration requests challenges on both the candidate and the old active
path, as required by the forwarding-attack defense. Failure returns to the still
live validated fallback or reports that no viable path exists.

A client validates a verified preferred server address before switching. A server
uses its preferred local address for non-probing traffic only after validation
and a current highest-numbered non-probing packet there. Unknown server addresses
are discarded. The policy may accept and validate observed NAT rebinding even
when active migration is disabled; it never treats an address change alone as
permission to close/reset the connection. Returned decisions are obligations for
the endpoint, not side effects performed by this kernel.

## Actual typed services

`driver/path.rs` adds separate checked authorities:

- Receive-ticket-bound path effects, peer CID installation and local CID retirement
- Distinct Finished early-control release and completed timer event sources
- Path reservation bound to the live transmit ticket, opaque path reservation and peer CID
- Distinct accepted/rejected adapter branches; only acceptance yields an accepted-send ticket
- Accepted-send-bound local CID advertisement and its matching completion

The driver's checked state retains complete generations/handles. Typed carrier
messages contain descriptor IDs and full-width path-generation/sequence values,
with a maximum 16-byte payload. A live path outcome cannot be bypassed through
the generic adapter callback. Ordinary path effects cannot reuse early quarantine
authority, completed receives, another effect, or stale generations.

The enlarged graph and timer-first/early-control routes use **48 carrier ports, 16-byte messages and a 32-KiB runtime slab**.
The isolated host `path_kernels` test measured zero Rust allocator calls across
exercised successful and rejected kernel/typed-service operations. Packet
authentication is assumed by that fixture; it is not a wire test.

32 ports failed; 40 still failed timer service. These are service-storage results,
not complete embedded RAM/stack or hardware measurements. Fixtures use
`protocol::SERVICE_PORTS` and the existing slab budget.

## Endpoint integration

`enable_network` takes two caller-owned `PathSlot<1,3>` entries, eight local CID
history entries, sixteen `PeerCidSlot<2>` entries, and a borrowed cryptographic
RNG. `receive_from` takes the actual local/remote tuple. `Transmit.address` and
its pending reservation retain that exact destination until the adapter callback.
Local CID lengths remain fixed. New paths send Not-ECT; validating cumulative ECN
feedback across paths is deliberately deferred.

The server's original path receives byte credit only after successful packet AEAD,
replay and whole-frame admission. A coalesced datagram earns credit once. All
managed sends, including early data, reserve real per-path byte budgets before
publication. A client is exempt from server amplification restriction, but this
exemption is separate from address/MTU validation evidence.

Legal early NEW/RETIRE/PATH_CHALLENGE frames retain their original path and DCID.
A read-only bounded CID simulation includes all held frames and remembered credit
before packet admission. Later advertisement cannot rescue an invalid earlier
RETIRE. Finished releases use a distinct checked early-control grant, never a
fabricated ordinary receive ticket. Actual deferred-control wire tests live in
`reference-tls/tests/early_wire.rs`.

Path effects also accept a separate, single-use timer grant from an actual
completed timer event. Equal timestamps carry different descriptors; an active
timer effect prevents supersession until completion. Validation expiry abandons
only the identified path, retains late-ACK semantics, requeues its data and reclaims
completed ledger prefixes. A full ledger cannot arm an impossible immediate probe.
The regression requires both real backpressure and bounded eventual progress.

ACK validity and PN allocation remain connection-wide. RTT samples require the
exact ACK-largest sent path and matching receive tuple. New-path CC and PTO reset
use immutable original sent-path metadata. Packet-threshold counts exclude other
paths/generations. Old flight remains a fallback PTO source so a lost old-path
STREAM can be probed on the new path without importing old RTT or congestion
signals. Abandonment and late ACKs do not change replacement-path congestion state.

Preferred server CID sequence one becomes advertised only when actual accepted
Handshake CRYPTO completes the outgoing EncryptedExtensions message and its
address/CID/token match the configuration. This uses an optional caller-owned
prefix buffer: the host supplies 2048 bytes; smaller explicit profiles are legal
if their complete EE fits. Rejected sends do not advance accepted prefix state.

Reset detection is integrated into managed receive and real silent draining.
It requires a token from this connection's authenticated peer parameters/frames,
a CID actually used in an accepted send, and the matching remote address. Random
AEAD failure, wrong suffix or wrong source does not suffice. Generating/statelessly
serving reset packets after losing connection state is not implemented.

The profile supports two live paths and finite lifetime CID history; exhaustion
is explicit rather than silently forgetting gaps or falling back to a raw CID.
Only serialized candidates are qualified. General multipath, unbounded migration,
variable-length local CID routing and general DPLPMTUD are outside this profile.

`adapters/host/src/path_socket.rs` retains its bounded concrete-socket API.
The underlying `udp.rs` additionally handles wildcard sockets using actual
IP_PKTINFO/IPV6_PKTINFO and typed per-datagram source selection, preserving ECN.
Missing packet info on a wildcard binding, truncated ancillary data, conflicting
metadata and incompatible source tuples fail explicitly. The host ancillary
implementation can allocate and is outside the core allocation measurement.
HQ uses managed tuples by default and optionally binds/advertises one same-family
`--preferred-address IP:PORT`. It retains all issued public CID aliases through
sequential connection dispatch, including retired aliases. Host tests and the
exact frozen executable are recorded separately under `artifacts/path-host`.

Primary requirements: [RFC9000 §5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1),
[§8.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2),
[§9](https://www.rfc-editor.org/rfc/rfc9000.html#section-9), and
[§10.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3).

## Reproduction and checkpoint scope

The complete local UDP result is [`direct-v1.json`](../artifacts/path-host/direct-v1.json).
It pins the executable SHA256, each exact file hash, real terminal lifecycle,
observed NAT mapping changes, replay/corruption outcomes and authentication
failures. The immutable binary and its source manifest live beside that result.
`test_hq_paths.py --binary <frozen-hq> --output <new-report.json>` refuses to
replace an existing result. `--inject-replay-corruption` adds the protected
pre-switch replay and corrupted duplicate without decrypting or constructing
protocol frames.

The current component/engine checkpoint is
[`path-engine/manifest.json`](../artifacts/path-engine/manifest.json). It records
which tests used earlier frozen sources and the later focused cleanup checks.
Terminal retirement and owner Drop now clear path records while preserving
slot epochs, and the same caller arrays can be reinitialized safely. This
cleanup postdates the host binary, so the host result does not silently claim
that later source identity. Host memory, TLS fixture construction, file I/O and
ancillary-buffer allocation are excluded from the core zero-allocation claim.
