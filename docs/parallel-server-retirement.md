# Independent server connections and actual idle retirement

The host admits bounded independent connections while an earlier connection
waits for its own ACK, peer close, or negotiated idle deadline. Each worker runs
the existing complete Hibana connection global. There is no host QUIC Phase or
replacement progression FSM. The host CID/address table only routes owned UDP
bytes; exact aliases, queue capacity and receiver lifetime are bounded.

One descriptor reads the physical socket. Each connection owns a duplicate
write descriptor so actual sendmsg acceptance is returned in the same poll as
DatagramTx completion. Queuing bytes is not counted as physical acceptance.
The ordinary one-connection reactor remains 4 sockets / 8 timers; the bounded
multi-connection host uses 65 sockets / 256 timers for at most 64 connections.

## Terminal meaning

Normal FilesComplete still requires the actual finite source result, stream
completion, settled retransmittable chunks, authenticated handshake confirmation,
and settled publication/ACK obligations. Missing feedback is not normal success.

An independent completion role waits for the negotiated idle deadline as well
as actual activity revisions. The numerical activity record follows RFC 9000
section 10.1: the minimum nonzero timeout; authenticated receive; the first actual
ack-eliciting publication after receive; and a minimum of three current base PTOs.
Later probe transmissions do not indefinitely restart the idle timer. Overflow
is rejected. Expiry revokes ordinary publication and sends the explicit
IdleExpired Hibana route. The existing ordinary join, key transfer and consuming
retirement still run. Expiry sends no fabricated close or ACK.

The host checks that native socket and timer owners are all released after the
root future returns. An idle outcome is reported as `idle-expired`, with
`resources_retired: true`, `http_transfer_complete: false` and
`lifecycle_closed: false`. Client idle expiry returns an error. Global host
execution deadlines remain errors, never successful terminal receipts.

## Verification boundary

Lean and Z3 in `proofs/idle-timeout` cover only deadline arithmetic and the
first-send rule. They do not prove arbitrary Rust effects or the complete QUIC
implementation. Rust tests and actual native connection tests are separate.

Early native burst experiments used a sequential UDP proxy that redirected
old server replies to the latest client and rejected prior client ports. This
was invalid for overlapping draining connections. MultiEndpointProxy now retains
bounded independent client paths, including delayed replies and late close/ACK
traffic. Its real socket test checks both late reply destination and old-client
return traffic. Delay, corruption and burst-loss selection remain unchanged.
These tests are diagnostics, not an ns-3 topology or official runner verdict.

Repeated former-proxy tests included complete transfers with incomplete
retirement at a 300-second host deadline. Some diagnostic runs also showed
large RTT-derived three-PTO deadlines. A successful rerun alone does not prove
every former failure's cause. Full qualification requires the unchanged official
runner and its controls. No new pass is counted from this document.

## Initial recovery refinement

Initial ACK packets already occupy 1200 bytes. When the server still retains
unacknowledged ServerHello CRYPTO, it includes those bytes in the same packet
when they fit the padding budget. Otherwise it retains the existing ACK-only
path. This uses the existing ACK publication choreography and real flight
reservation/acceptance. It does not declare a loss, mint probe allowance, add a
phase controller, or bypass congestion/amplification. A decoded-frame unit test
checks the ACK and exact CRYPTO bytes with unchanged 1200-byte size.

The RTT estimator no longer discards Handshake ACK delay. RFC 9002 5.3 only
permits that exemption for Initial. Before confirmation it uses the uncapped
peer delay; an implausible below-minimum adjusted sample is ignored as permitted,
not clamped. Confirmed samples remain capped. See `proofs/handshake-ack-delay`
for the limited arithmetic model and its explicit non-refinement boundary.

The final local candidate matched all 50 file hashes and retired all native
socket/timer owners in three burst-loss runs (58.941, 62.480, 56.890 seconds)
and one burst-corruption run (50.051 seconds). Normal and idle outcomes stayed
separate (10, 11, 19, and 18 idle outcomes respectively). An isolated lost-feedback
case also completed actual idle retirement; client 0-RTT and key-update
regressions passed. These are not new official interoperability passes.

## Parallel listener version negotiation

Official runs 37307010360 and 37309538333 failed before capture or client
traffic: the simulator exited 1. Its wait-for-it-quic sends the reserved WAIT
version and requires a Version Negotiation response before starting ns-3.
The parallel listener omitted the stateless response that the single listener
already implemented. Both now call the same bounded helper before admission.
Reversed connection IDs, v1-only advertisement and the threefold response
budget are preserved. The probe consumes no connection slot or TLS owner.

A native regression sends the exact simulator probe before the real client.
The previous parallel binary times out on this probe. The corrected debug
binary responds and subsequently transfers all 50 files with matching hashes
and verified resource retirement. All 111 host tests and strict host Clippy
pass. Official runner qualification is still required; no pass is inferred
from listener readiness.

A separate data-plus-FIN coalescing experiment was not adopted. Two native
burst-loss trials took 29.447 and 29.288 seconds to client completion, within
the previous 26.668–32.369 second range. Additional look-ahead complexity was
removed rather than claiming a material speed improvement. Native reports now
separate client elapsed time from subsequent verification/resource retirement.

## Owned prefix packet and parallel TLS resumption (2026-10-05)

The finite handshake prefix previously discarded a short-header packet that
arrived before its transmit branch settled, including application data
coalesced after the client's Finished. It now retains the first matching-CID
packet as a bounded owned ciphertext buffer. The actual handshake join and
application key transfer precede normal authentication and frame processing.
Later packets cannot overwrite that buffer. Its original UDP datagram has
already been accounted once; application delivery does not count it again.
Failure drops the single-use owner. No plaintext or successful receipt is
invented at this boundary.

Parallel workers now use the existing server TLS ticket interface through
short synchronous borrows of one root-owned key. Nonce issuance is shared and
abandoned reservations remain burned. The key outlives every worker and its
join. Reusable 1-RTT tickets do not enable early data. This adds neither a
Hibana public API nor a connection progress state machine.

The comparison also exposed a capability difference: the native Neqo control
completed 26 resumed and 24 full handshakes, whereas the prior parallel server
completed 50 full handshakes. Reports now count actual resumed connections;
this is separate from 0-RTT acceptance. Receiving a ticket before a short-lived
client closes is not guaranteed under loss.

Native diagnostics, unchanged 50 files, 15 ms one-way delay and three-packet
burst loss: ticket sharing alone took 29.153 s (17 resumed). With owned prefix
retention, two runs took 22.127 and 24.353 s. The corruption counterpart took
17.425 s. All 50 file hashes and actual resource retirement were checked in
each run. Missing close feedback still terminates through the existing honest
idle-expiry path; client completion and later retirement are reported separately.
The no-impairment run took 0.892 s with clean lifecycle closure. These are local
diagnostics, not new official qualification cells, and the requested 15 s
burst-loss target remains unmet. The verified historical total remains 28/44.
