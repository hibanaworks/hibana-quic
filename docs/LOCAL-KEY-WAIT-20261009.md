# Measured local ACK decryption wait

The previous remote source pair, QUIC `4fa5ef7ca97bc631030627700d3b9751c5ff6e61`
and TLS `b5cd10fcabb26ed0b121ae9a192b4c254f000426`, passed the official 44-cell
qualification in run `37882500310`. Its additional native self-peer stress job
in run `37882500324` failed corruption seed `20261013`: one of 50 files was
absent and both processes reached their 180-second deadline. That is a real
failure, not a successful close or a complete delivery.

## Correction

The retained packet already owns its receive timestamp. Recovery used that
fact for outgoing ACK delay but still supplied zero local decryption delay to
the RTT estimator. It now passes the measured difference between receipt and
processing. The numerical commit clock remains monotonic. The existing estimator
subtracts this local wait only before handshake confirmation, as specified by
[RFC 9002 section 5.3](https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3).
There is no new protocol controller, phase flag, shared key owner, or endpoint
wrapper.

The new authenticated recovery regression fails before the correction with
16,040,000 microseconds instead of 40,000 and passes after it. All 44 selected
recovery tests pass. The existing finite seven-Handshake/three-short-datagram
fault test still completes with matching data and close (16.76 seconds locally).
One subsequent ten-seed run delivered all 500 expected file hashes; nine cases
also met the strict close criterion, while one server connection idled after
complete delivery. Keep these outcomes distinct. The CI failure has no numeric
RTT trace, so do not present this correction as proof of its sole cause or as a
guarantee for every random schedule.

## Verdict contract

The CLI fixture continues to report strict lifecycle failure and its real exit
status. CI records that status separately. Delivery qualification additionally
reads the actual report and requires all 50 file hashes, both successful
process exits, authenticated and confirmed TLS/QUIC, every file completed, and
retired owners. A client idle or incomplete/missing report is always failure.
A server idle following verified complete delivery remains explicitly recorded
as idle; it is not rewritten into a received close. Negative verdict tests cover
missing/corrupt files, process failure, missing reports, authentication,
confirmation, ownership, counts, and client idle.

The previously failed CI artifact is not reclassified: its missing file and
nonzero process exits still fail the new verdict. Original deadlines, impairment
seeds/distribution, capacities, and the full official 44-cell matrix are unchanged.

## Host deadline policy

Further repetition with the RTT correction alone still reproduced a missing file:
the client idled at 30.8 seconds although the explicit operation deadline was
180 seconds. A captured random-fault route trace showed three corrupted Initial datagrams,
then three corrupted client Finished datagrams; retransmission backoff exceeded
the hard-coded 30-second local idle setting before the next probe could run.
This is separate from the measured local key-wait error and is not hidden by
changing the verdict.

The host now derives its advertised and applied idle period from half the
existing `--timeout-seconds` whole-operation budget (180 s -> 90 s). The remaining
budget permits closing/retirement; the absolute operation deadline, packet
fault schedule, and missing-file failure remain unchanged. Both peers still
negotiate the smaller nonzero idle period as required by QUIC. No core protocol
phase or new command-line switch is introduced. Library consumers keep explicit
control of `Setup.local_idle_timeout_ms`; the host storage no longer hard-codes it.

An attempted finite Initial/Finished-loss reproduction also passed on the old
binary (8.36 seconds); it is not evidence that the old implementation fails that
finite schedule. The random-fault missing-file reports remain the evidence for
the additional host-policy change.

## Candidate verification

The release binary SHA-256 is
`b30fdb2c96aacba88e5037780d38ca3ea52a740e7fa6d764305e1cfc26ea0b2d`.
A repeat release build after formatting produced the identical binary.
The final Host passed 130 Rust tests and strict Clippy; all 98 root Python tests
and the UDP impairment unit suite passed. Paired source and control audits passed.
Actual native quiche handshake-corruption tests passed in both directions.

The final ten-seed 50-connection run delivered all 500 matching file hashes,
authenticated and confirmed every connection, and retired both sides. Nine cases
closed strictly; loss seed 20261013 retained one actual server idle after complete
delivery. No close receipt is claimed for that connection. The earlier RTT-only
repeat with missing files remains failed, as does the original remote CI artifact.

A finite additional regression uses 1100 ms latency in each direction and drops
exactly three client Finished-shaped datagrams, forwarding all other traffic.
The original binary failed with no received file: client exit at 38.89 seconds,
server at the unchanged 180-second cap. The final candidate passed twice,
including the checked-in fixture in 69.79 seconds, with both processes successful,
matching bytes, strict close, and retired resources. This regression is now part
of the fault CI job. It is not one of the independent official 44 interop cells.

The new remote commit still requires its own complete CI qualification; the
previous source pair's 44/44 result does not qualify these changes.

## Follow-up: retain both probes for unacknowledged Finished

The pushed f04db4b CI did not qualify. Core/Host/reference checks and Miri passed,
but the independent quiche client direction failed handshakeloss and
handshakecorruption with 49 of 50 files. Captured metadata shows four successive
Finished retransmissions absent at the server, while the second PTO credit was
spent on 1-RTT. The latter cannot finish the server's TLS handshake. The self-peer
stress also retained a real missing-file failure despite the longer local idle.

The first attempt to keep both credits in Handshake at every PTO was rejected:
the existing lost-confirmation/lost-request regression failed. A peer may already
have received Finished while its ACK and HANDSHAKE_DONE are both lost; starving
1-RTT in that case is incorrect.

The revised selection gives retained Finished both credits on the first and
alternate PTOs, and also probes the live 1-RTT space on intervening PTOs. Selection
uses the existing PTO backoff count, without another phase flag, timer, credit,
capacity, or key owner. Adapter rejection still refunds the exact credit. The
empty-Handshake-flight anti-deadlock path and server Initial-to-Handshake behavior
are preserved. The numerical regression checks both priority and later application
service. The existing end-to-end lost-confirmation test must pass unchanged.

The revised candidate passed all 457 root all-target Rust tests and strict Clippy,
including the unchanged lost-confirmation/request test, and the thumbv6m check.
Its finite key-wait fault completed in 4.38 seconds and the slow Finished fault
in 43.23 seconds. Actual native client-to-quiche handshakeloss and
handshakecorruption passed on three seeds each (50 connections per case).
These are native local observations, not a replacement for a new official run.

The same revised binary
`6589a148b2355e66d850cdfd8025998cd7edb59e84d3632040824c69efbe16a0`
passed all ten 50-connection loss/corruption cases with 500 matching files and
strict close on every case (zero observed idle connections in this run). The
reverse native quiche handshake-corruption case passed as well. Earlier failures
are retained; repeated success is not a guarantee for every possible loss pattern.

Final Host validation passed all 130 tests and strict Clippy before publication.

## Simulator capture shutdown

Remote 296dd52 runtime CI `37892461592` passed Rust, Miri, both finite fault
regressions, and every one of the ten native stress cases with strict close.
Interop attempt 1 was 43/44: reverse quiche handshakecorruption lost all three
observed peer Finished datagrams before peer exit. Three additional local reverse
seeds passed; this remains recorded as an intermittent failure, not reclassified.

A complete same-source rerun (attempt 2) exposed a different observation failure
in reverse Neqo retry. Both endpoints exited successfully, and 10,240 bytes were
received. The client-side pcap contained 37 decoded QUIC rows including completion,
but the server-side pcap contained only the initial four rows and no server
Initial. The unchanged runner counts handshakes from that server-side capture.

The upstream simulator shell forwards TERM to dumpcap children and exits without
waiting for their termination. A local process regression reproduces loss of a
delayed final flush when the container kills remaining children at parent exit.
Waiting for the signalled children preserves the final bytes. The CI preparation
now changes only that exact known termination tail; unexpected upstream scripts
are rejected. Scenario code, packet impairment, images, endpoint code, runner
source, case deadlines, and result criteria are unchanged. The original and
patched entrypoint SHA-256 values are published and must match across every group.
This is an explicit simulator shutdown adaptation, not an unchanged entrypoint
claim. Docker execution of the adaptation is still to be verified by the new CI.
