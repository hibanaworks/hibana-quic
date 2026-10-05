# Bounded multiplexing

The pinned runner's multiplexing case transfers 1,999 distinct 32-byte files
on one connection. Its verdict also requires a key log, exactly one handshake,
and a server initial bidirectional stream limit at most 1,000. The unmodified
reference peer supplies actual key logs; no candidate logs are fabricated.

## Ownership and progress

The existing Hibana source/input/delivery release messages and explicit join
remain the only authority to reclaim a stream slot. Reclaiming a peer's
bidirectional stream makes one further slot-backed credit available. The
resulting MAX_STREAMS goes through the existing retained control flight,
physical publication, loss, PTO and authenticated ACK path. Cancellation keeps
it pending. No new phase controller or public Hibana API is introduced.

The finite workload bound is 4,096 requests, separate from the maximum 64 live
stream slots. Client TLS credit and actual receive storage both use the same
capped live count. Completion identity is retained per reusable slot, with a
checked cumulative completion count. A new current stream handle in a reused
slot replaces its old completion observation; it cannot reclaim storage.

Early-data storage remains bounded to 64 and multiconnection admission remains
bounded to 64. Increasing the ordinary total request bound does not enlarge
those resource budgets. Host file associations and unique destinations remain
bounded by the finite request limit.

## Verification boundary

The first native run transferred all 1,999 distinct files in both directions
against unchanged Neqo. Actual candidate reports had one connection, 1,999
completed files, all streams ACKed, resources retired and lifecycle closed.
The server direction uses 32-byte files. Native Neqo's ordinary server serves
numeric-size paths, so the client direction and Neqo self-control use distinct
32..2,030-byte files. This is a diagnostic difference, not a modified official
workload or a substitute for the runner verdict.

The focused stream-credit test performs 70 one-slot reuses, requires the actual
three release receipts, cancels and loses MAX_STREAMS publication, and verifies
that retransmission stops only after ACK. Existing full connection, reuse,
loss, retirement and no-allocation tests remain applicable.

Official multiplexing qualification is pending. The historical total remains
28/44 until exact-commit runner results are read. The deferred 15-second
50-connection loss requirement is a different workload and remains unmet.

Final local validation: all 420 core unit tests and all integration/doc-test
groups passed; host tests passed 114 cases. Selected host library/hq strict
Clippy, thumbv6m compilation and release build passed. The final binary repeated
all three native multiplexing directions with 1,999 distinct content matches,
and explicit candidate retirement assertions. Forty-file client 0-RTT retained
39 actual early packets and clean retirement; client key-update regression
passed. These remain local evidence, not official qualification.
