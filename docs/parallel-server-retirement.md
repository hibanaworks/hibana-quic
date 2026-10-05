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
