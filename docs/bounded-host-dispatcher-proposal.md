# Bounded repeated-connection host dispatcher proposal

Status: design only, 2026-10-02. No dispatcher or engine change is included in
this capability increment. Current HQ still has one sequential connection owner.

## Observed problem and smallest useful step

The preserved ticket-age trace (`artifacts/host-resumption-age/strict-1000-summary.json`)
shows the next connection's Initial PN 0 arriving on a fresh client source port
while the previous server is Draining. `exchange` currently owns the shared UDP
receive loop and its `Ok(_) => {}` branch drops that datagram. The old connection
expires 7,424 microseconds later; the next client retransmits the same ClientHello
in PN 1 approximately 999,583 microseconds after PN 0. A broad ticket-age window
does not remove that extra transport delay.

First implement a bounded pending-Initial slot in the shared listener, retaining
one **whole UDP datagram** and its actual source/ECN/receive timestamp while the
previous connection drains. A 65,535-byte slot matches this host's current UDP
input capacity. Do not silently truncate a larger legal datagram to 1,200 bytes:
that could discard coalesced packets. This step needs no new engine semantics,
keeps one full endpoint, and avoids the demonstrated drop when the slot is free.
It delays processing by the remaining old drain time, not by a new client PTO.

## Routing and bounds

Use one socket owner and explicit fixed capacities:

- One active/full Closing endpoint, one pending Initial datagram, and one draining
  tombstone for this two-connection profile
- A checked, never-reused generation for every endpoint; queued adapter/timer
  work also carries slot index plus generation
- Three CID aliases per connection in the present host profile: original client
  destination ID, issued local ID, and optional Retry source ID. Each is at most
  20 bytes. Future NEW_CONNECTION_ID support must raise/document that bound
- One output reservation per engine, serialized `transmit_permitted` followed by
  the actual UDP submission and exactly one `adapter_result`
- Fixed per-turn receive/transmit work quotas and earliest-deadline scheduling;
  queues full means an explicit drop/capacity metric, never eviction of a live
  endpoint or a nonexpired tombstone

Demultiplex by destination CID before source address. Matching live/closing CIDs
route only to that owner; its existing path checks decide address eligibility.
A new source port alone does not identify a new connection. Matching draining
aliases are discarded silently. Only an unknown-CID, version-1 Initial carried
in a sufficiently large datagram can enter the pending-admission slot; unknown
short-header traffic does not create a connection. Preserve the entire datagram
and receive metadata. Continue to reject mixed-owner coalescing rather than
assigning one datagram's bytes/ECN credit to two owners. Never infer authentication
or replay admission from public header/CID matching.

On old-owner expiry, dequeue once and perform the **normal** Retry/token gate at
the current monotonic time. A queued token might have expired: do not validate it
at enqueue and then reuse that old decision. Credit actual datagram bytes and
ECN once when the new engine receives it. Keep the earlier receive time only for
diagnostics; feed monotonic current dispatch time to a newly created endpoint.
Do not rebase a token-issuer clock. Shared ticket/replay and Retry state live
outside connection objects and remain serialized by the listener.

## Tombstones and true overlap

RFC 9000 sections 5.2 and 10.2 require packet attribution and closing/draining
retention; a draining connection sends no further packets, whereas Closing may
still need retained keys and rate-limited close output. See
[connection matching](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2) and
[immediate close](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2).

A follow-on compact tombstone can release the large TLS/stream storage **only on
an authenticated transition to Draining**, after all outstanding adapter work is
reconciled. It retains generation, all routed CID aliases, and the immutable
original retention deadline. It never owns keys, emits packets, extends its
expiry on input, or grants admission authority. Closing cannot be compacted this
way: keep the full existing owner until Draining or Closed.

Before implementing compaction, the engine needs a reviewed consuming API such
as `into_draining_tombstone()` returning the exact deadline and retained routing
facts, or an equivalent read-only export followed by checked retirement. The
host must not guess three PTOs from its wall timeout, reset retention from the
export time, or call compatibility `close()` to claim a wire close completed.
Use one listener monotonic epoch for all new owners. If retaining existing per-
connection epochs, convert the exported deadline with a checked stored epoch
offset; raw engine-relative microseconds from two connections are incomparable.
That API is a future change, not provided or assumed here.

With a tombstone, the next full endpoint can start immediately while old packets
remain suppressed. If overlap during **Closing** is also required, budget two
full endpoint/storage owners and route both; the existing host stack profile
must be measured at that concurrency. Never claim a one-endpoint budget supports
two simultaneous active TLS/transport owners. Safe Rust construction must keep
caller-owned arrays and borrowed providers stationary for each lifetime; no
self-referential movable aggregate or unsafe lifetime extension is proposed.

## Required executable acceptance tests

1. Deterministically deliver connection-two Initial before old Draining expiry;
   it completes from PN 0 without waiting for the client PTO, with exact file
   hashes, real authenticated ticket resumption, and explicit receive/dispatch
   timing
2. Delayed old Initial/Handshake/1-RTT packets, same-address new connections, fresh
   address old CIDs, and original/Retry CID aliases cannot steal a new owner
3. Duplicate queued datagrams do not double-credit amplification/ECN or consume
   ticket admission twice; corrupted/expired/wrong-address tokens still fail
4. A full queue or tombstone table never evicts live retention; behavior is
   bounded and counted. Malformed datagrams do not allocate TLS state
5. Closing retransmission remains rate-limited and obeys adapter acceptance;
   Draining emits zero datagrams. Queued stale timer/adapter generations fail
6. Expiry/clock-overflow boundaries and per-turn fairness prevent either owner
   from starving timers; no invented success on capacity/timeout
7. Preserve the prior strict-one-second rejection trace as historical evidence;
   measure the new dispatch delay instead of changing that expected result

The pending slot is the recommended first host-only implementation. Compact
Draining tombstones then permit true overlap with a small engine API addition.
Neither change establishes a general-purpose production listener, migration,
load balancing, or quic-interop-runner completion.
