# Direct local continuations

## Current audit continuation

The next local candidate removes `Pending.initial_handshake_done` and the
transmitter's duplicate optional initial-flight tracker. Initial control
publication is selected from the actual retained flight and its reservation
references. A pending native submission owns a reference; cancellation removes
it; the existing Hibana Accepted exchange commits it. Loss and authenticated
ACK continue to use the same recovery records. No new stored flag, phase enum,
communication wrapper or queue was added. A focused reference-ownership test
covers pending, cancellation, acceptance, loss, ACK and slot reuse.

This is still a candidate under regression testing, not a whole-file audit
completion or a claim that impairment-induced termination is solved.

The design criterion is a direct local spelling of the Hibana global contract.
Do not replace progression flags with renamed state or communication wrappers.
Numerical/cryptographic/I/O operations may be separate components; they do not
choose a hidden alternative protocol continuation.

## Current prefix rewrite

- Remove `Schedule.stop_timer` and `Schedule.transmit_done`.
- The wire owner explicitly sends StopReceive / receives ReceiveStopped before
  StopTimer / TimerStopped and adapter retirement. The global contract declares both.
- The timer local consumes the stop while clock work is parked, completes any
  already-started expiry exchange, then explicitly retires and acknowledges.
- The receive-stop role is polled independently from the start of TLS input.
  If stop arrives first, the actual stop receipt is retained and the in-flight
  TLS exchange is still completed. It is not abandoned or replaced by a flag.
- Remove the local communication helpers `send`, `transmit_phase`,
  `settle_phase`, `publish_phase`, `publish_result`, `output_before_key`,
  `output_until_connected` and `output`. Concrete send/recv/offer branches are
  written in the TX, UDP and TLS-source local bodies.
- Packet construction/recovery selection is synchronous and contains no
  endpoint operation. Prepared bytes move to existing owned storage before
  the local awaits, keeping large preparation temporaries out of suspended
  role frames.

A capacity-one regression exposed why merely replacing the flag with a send
was insufficient: an unpolled stop role retained the only carrier slot and
blocked the TLS completion needed before that role was started. Starting that
independent receive immediately fixes the scheduling mismatch. Carrier capacity
and protocol success conditions were not relaxed.

The initial expanded candidate also overflowed the default debug-test stack.
A larger stack was used only to diagnose it, not as the accepted fix. Shortening
large packet temporary lifetimes allowed the real connection test to pass again
with the default stack. The temporary expanded-stack run is not qualification.

## Remaining scope

This checkpoint does not certify the entire application layer as fully migrated.
Application source/sink helper composition and cross-role completion readiness
still need the same direct-local review. Do not call the whole migration complete
or infer a Hibana core bug merely from the unfinished consumer rewrite.

## Qualification of the prefix checkpoint

The native forty-file client 0-RTT regression exposed an overly late finite-RX
handoff: keeping finite RX alive through unrelated timer/adapter retirement
could consume post-handshake input before the application receiver owned it.
The global completion sequence now stops and joins finite RX at the recovery
transfer boundary, before those other retirement exchanges. Already-owned
coalesced packet bytes are still processed. No completion flag, arbitrary
delay, larger queue or permanent RX backpressure was added.

Local verification on 2026-10-05: the full core test suite (421 unit tests plus
integration and documentation groups) passed with the default test stack;
selected host library/binary strict Clippy and thumbv6m compilation passed.
The native Neqo diagnostic passed 1999 distinct files in both directions with
real candidate retirement, and client 0-RTT passed forty files with 39 early
packets and both connections retired. These diagnostics are not official
runner verdicts. The new exact-head runner request covers multiplexing,
0-RTT, handshake loss and handshake corruption in both directions.

## Application-local follow-up (locally qualified)

- Source open/data/settle/finish operations are spelled directly in the client
  and server source bodies. The former submit/begin/end/source-finished and
  client-requests/server-responses communication wrappers are removed.
- Source retirement is an actual `SourceJoined` edge consumed by an independent
  local before checking numerical completion. `State.done` is removed. Error,
  cancellation and idle expiry stay independent and join that actual receive
  after stopping unfinished IO; they do not fabricate normal completion.
- The two terminal receivers each write their own offer/recv/ack and are joined
  as futures. `peer_done` and `files_done` are removed.
- Peer close/failure/cancellation communication is in the receive local. Its
  direct branch/return replaces `peer_reported`.
- The returned successful close/retirement join already proves completion; the
  extra publication `completed` cell and its post-hoc query are removed.

The subsequent local candidate replaces the application failure flag with
explicit SourceFailed, source data/end failure, ReceivedFailed and
PeerApplicationFailed branches. Five connected fault-injection tests exercise
request enumeration, source open/read and sink write/finish failures without
fabricating successful FIN. RX key-control exchanges, TLS input, early packet
publication and Initial-retirement exchanges are spelled in their local bodies.
The whole-repository review and exact-head requalification remain in progress.
Wire bits, numerical counters, buffer occupancy and OS readiness must retain
their actual validation; renaming control state to an enum or Option is not
a substitute for moving protocol progress into the projected local.

The application checkpoint passed 421 core unit tests and all integration/doc
groups, 114 host tests, selected host strict Clippy, thumbv6m check, and 57 + 13
Python diagnostic tests. Native diagnostics passed 1999-file multiplexing in
both directions and forty-file client 0-RTT. The impaired fifty-connection
server run preserved all fifty files and retired all resources: twenty real
idle expiries remained idle-expiry outcomes, not clean-close claims. Exact-head
remote qualification is still pending; this does not add new historical cells.

## Ownership-derived readiness and current handoff regression

The unpublished candidate removes mirrored write-key availability, receive
confirmation and learned-peer flags. The timer borrows the actual write-key
owner; receive confirmation comes from the recovery ledger and authenticated
packet observations. Actual IO-result resolver bindings remain session-bound
to Hibana. Removing that binding merely because it stores a decision would
weaken the contract; it is not an independent progression controller.

A native forty-file early-data recheck exposed a dropped resumption ticket.
After TLS input completes, finite RX now stops reading additional native input
when its existing application-ciphertext handoff slot is occupied. The separate
StopReceive continuation remains polled and joins the role. This backpressure
is deliberately not applied before TLS completion, when reordered application
packets must not block Finished. There is no extra slot or arbitrary delay.
The final native diagnostic passed three fresh runs of forty-file 0-RTT in
both directions, with all files matching and both candidate connections
retired. The client accepted 39 early packets in each forward run. A fresh
1999-file multiplexing run passed both directions. The impaired fifty-connection
run matched all files and retired all resources; actual idle-expiry outcomes
remain expiries. These concurrent diagnostic timings are not a performance
comparison or an official runner verdict. Core tests (421 plus integration and
doc groups, including 15 connected-application tests), selected host strict
Clippy and thumbv6m checks also passed. Six existing Z3 model groups passed;
fresh Lean execution is requested in CI because its official archive could not
be fetched in this workspace. These are scoped abstract models, not a proof of
arbitrary Rust/native IO correctness.

The published application revision 13923dd passed runtime CI. Its official
interop retry stopped at a failed Neqo/Neqo 0-RTT control, before candidate runs.
Handshake loss, corruption and multiplexing controls passed. The next request
uses quiche as the reference, under the same runner verdicts. No new historical
case is counted from a native diagnostic or a failed reference run.

## Interrupted receive delivery

The next audit found cancellation returning the same boolean as successful FIN
from the sink's native delivery attempt. It did not mark the stream complete,
but the local still sent ReceivedFin. The contract now has a separate
ReceivedInterrupted branch, consumed and checked against actual publication
revocation by RX. The one-attempt delivery result is not stored as a protocol
phase. A capacity-one endpoint fixture verifies the exact interruption message,
no sink write/finish, no completion record, and actual role retirement.

This follow-up passed 422 core tests plus integration/doc groups, fifteen
connected-application tests, selected host Clippy and thumbv6m. Native forty-file
0-RTT passed both directions; the impaired fifty-connection run matched every
file and retired every connection, including fifteen genuine idle expiries.
The formal runner remains responsible for exact-head interoperability verdicts.

## Upstream intrinsic entry repair

The next dependency candidate selects upstream Hibana 4d0077b9, whose intrinsic
controller selection no longer scans an unchosen arm's descendants before the
other arm's actual entry. Three upstream histories were also exercised with
the actual capacity-one QUIC carrier: repeated completed reads followed by the
outer return, rejection of a premature return, and either nested initial arm.
All passed. The full QUIC core/integration suites and selected host Clippy passed;
thumbv6m compiled. The standalone upstream test runner could not fetch its
additional crates under this workspace's network policy and is not counted as
a local pass. Native forty-file 0-RTT and 1999-file multiplexing passed both directions.
The fifty-connection impaired server diagnostic preserved all files and retired
all resources, with seventeen actual idle expiries.

CI run 37378345713 on 8936b133 actually executed and passed the six existing Lean
and six Z3 model groups. Its quiche self-control passed L1/M/Z but failed C1, so
no candidate phase ran. This does not increase the historical 30/44 inventory.

The exact 5fd93508 runtime CI passed. Official run 37379219813 had passing
quiche controls and all four server-side C1/L1/M/Z verdicts. Client C1 timed out
at 300 seconds with fifty length-complete files; this does not prove content
checks or proper retirement. Client L1 reported successful transfer/retirement
with 259285 ms duration, but the overall 600-second client phase expired before
M/Z and produced no final client verdict JSON. The next request isolates M/Z;
C1/L1 termination latency remains an explicit regression investigation.


## Executor boundary and remaining loss failure (2026-10-06)

The experimental 130c864 checkpoint uses unmodified Hibana c3d89f78. Its runtime
CI 37398933045 passed. In official run 37398932952, all quiche self-controls
C1/L1/M/Z passed, candidate server C1/L1/M/Z passed, and candidate client C1/M/Z
passed. Client L1 timed out at the unchanged 300-second limit, with 49 of 50
length-complete files and no final report. File lengths are not content
verification. This remaining failure is not established to be only shutdown:
one response is missing. Historical unique qualification remains 30/44.

The following readability candidate separates application assembly from locals:

- `application/assembly/mod.rs` binds and drives the independent projected roles.
- `assembly/ownership.rs` transfers actual startup/retirement owners and returns
  their values directly. It no longer stores Option result mirrors to extract
  them after joining.
- `timer.rs` and `termination.rs` write their projected send/recv operations
  directly. Pure completion/retirement messages use unit payloads; redundant
  sequence counters and equality checks have been removed. Actual resource,
  cryptographic, stream identity and native IO validation is retained.
- `runtime.rs` contains protocol-neutral polling/cancellation primitives.
  Pending native IO is kept as the same future during companion work; it is not
  cancelled and reconstructed. Their tests cover actual drop and wake behavior.

Pinning is an executor requirement, not a replacement choreography. Standard
`try_join!` is concentrated at role assembly boundaries where it keeps futures
in place without allocation in the core. Owned-join replacements overflowed the
normal debug test stack and were rejected, rather than increasing that stack or
calling a cosmetic pin-free rewrite an improvement. Explicit pinning remains
where it makes retaining/cancelling the actual future simpler. This is not a
claim that every remaining local has been fully audited.

For the remaining official loss failure, host diagnostics sample the actual
Hibana tap at existing polls. Sampling registers no timer or wake, does not
select a route and cannot change a verdict. Only fixed numeric tap metadata
and exact terminal fields are extracted into bounded CI artifacts. The next
run must establish the stalled connection's actual progress before attributing
or claiming to fix the root cause. Raw logs and peer-controlled text stay private.


The readability candidate passed 423 core unit tests, the integration groups
(including 17 connected application and 12 runtime tests), and 26 doctests.
Host suites passed 115 tests; embedded thumbv6m compiled; 58 Python tests passed.
Selected host `--lib --bin hq` strict Clippy passed. The broader core
`--all-targets -D warnings` invocation failed on 47 diagnostics (including
existing large affine-error payloads and fixture lints); it is not a full
strict-Clippy pass. Native/official qualification for this candidate remains
pending until its exact-source evidence is recorded.

The candidate's immutable native binary SHA256 is
`8ab9ce8e6f7cfeb1fcd42f4c46f3d4dafab372c2161f1d98cd667346aaed6184`.
Fresh fifty-connection self diagnostics passed deterministic loss and corruption
with all file hashes matching, zero idle expiries and all resources retired.
The loss sample exported fifty actual finished tap records on each endpoint and
fifty client terminal records. Unchanged native Neqo 40-file 0-RTT and 1999-file
multiplexing passed both directions. These are diagnostic fixtures, not the
unmodified official runner's loss verdict; the outstanding 49/50 failure is not
claimed fixed. The actual TLS/RSA/resumption/early reference test groups passed.


## Observed loss frontier, not a root-cause claim

Official run 37403324082 (44a05cb, artifact 11386523430) passed all quiche controls
and all candidate client C1/L1/M/Z cells. Client L1 had fifty actual successful
terminal records, complete files and resource retirement in 22.839 seconds. Server
C1/M/Z passed; server L1 failed when the reference client exited 255 with 11/50
length-complete files. Twelve server sessions were sampled. The unfinished one
last committed TLS_TX (role 3) receiving ApplicationTaken (label 100), ordinal 519,
at 26.392 seconds, with 17 sent / 10 received native datagrams. A last observed tap is
not proof of the next pending instruction or the underlying cause. All six Lean
and six Z3 groups passed. The failure is not claimed fixed or attributed to a
new Hibana defect.

The pinned runner's L1 is an extreme-loss case: 30 percent in each direction,
three-packet bursts, 15 ms one-way delay, 10 Mbps and queue 25. A follow-up adds bounded
preceding committed-operation samples (up to 512 per connection, explicit capacity
notice) and retains only the latest 16 numeric records for each of at most 64 sessions.
It adds no wake, protocol retry, phase state, deadline change or success override.

Additional actual paired-TLS fixtures pass 48 early server packet-loss bursts,
48 early client bursts, and 32 reproducible duplex long-header loss plans with 15 ms
one-way delay. All 20 connected tests pass. The duplex test deliberately targets
Initial/Handshake packets. An exploratory all-packet mask instead parked after
one peer had already closed: the capacity-one test path retained a packet with
no remaining reader, and its persistent server had no idle deadline. That test
is not evidence of the official unfinished-handshake fault and is not counted
as a successful full-network simulation. Whole-connection ACK/close loss remains
covered separately by the existing explicit cases; these fixtures do not replace
an unchanged runner verdict.


## Repeated extreme-loss observations

Run 37406336212 attempt 1 on fe49d4c passed the unchanged L1 control and both
candidate directions. Client 50/50 files, actual terminals and resource retirement
were observed (64.082 seconds). The server runner passed, but it was killed by
the runner with only 49 finished session samples; fifty clean server retirements
are not claimed. Attempt 2 failed: the quiche self-control exited 255 after
12/50 length-complete files; the diagnostic candidate client timed out after
49/50; the diagnostic candidate server passed. These results do not establish
repeatable qualification or a root fix.

The unfinished candidate client's last committed sequence was InitialRequest,
InitialIdle, InitialTaken, an accepted Initial ACK publication, then another
InitialRequest/Idle/Taken. It remained in the first key-exchange phase, with
15 sent and 6 received datagrams, last sampled at 25.946 seconds. Its timer
state was not in the tap. The following host-only observation borrows the same
physical clock and fault owner, records requested and returned deadlines, and
adds no timer or protocol decision. The reactor test confirms one physical timer
while pending and zero after cancellation; an expired wait registers no timer.
A returned clock future is not treated as evidence of successful packet delivery.

The local duplex fixture now also covers a 25-packet queue, 15 ms one-way delay,
333 ms initial RTT, real ticket issuance and a public 3265-byte certificate that
forces multiple CRYPTO fragments. Independent loss masks passed all 20 connected
tests. Three-packet burst masks expose a limitation in the earlier fixture's
30-second budget: seed 16 drops the first nine client datagrams, delivers none to
the server, and leaves the next real PTO armed at 30.969 seconds. That is not a
lost wake. The new extreme-loss diagnostic explicitly uses the runner's 300-second
outer bound; existing cases retain their 30-second bound. This changes no product
or runner timeout and is not a fix for the observed reference-peer failure.
All 32 burst histories complete under that diagnostic bound. Prior 30-second
failure evidence remains recorded and is not reclassified as a pass.

Because the repeated quiche control failed, the next targeted diagnostic uses
the already pinned Neqo reference with its own mandatory self-control. A failed
control invalidates qualification even when candidate diagnostics are collected.
No additional historical cell, whole-stack conformance or causal repair is claimed.

The host-clock observation candidate passes 116 host tests (including actual
single-timer retention/cancellation), selected host strict Clippy, 20 connected
tests with the explicitly documented diagnostic bounds, and 60 Python tests.
Its immutable native binary is
`105cafac4c27c0b4f4962689c98f00d44247a1df22ca6884afdfc16880e6e454`.
A four-connection lossy native smoke passed with all files and retirement;
actual requested/returned clock samples parsed for all four sessions on each
side. No new full fifty-connection or official pass is inferred from that smoke.


The e2d97dc runtime CI 37409859375 passed every actual step. In Neqo run
37409859215 (artifact 11388839882), the unchanged Neqo self-control and candidate
server L1 passed. Candidate client L1 failed with 26/50 length-complete files.
All fifty candidate handshakes were confirmed; 26 records completed and closed,
while 24 recorded idle expiry with zero completed streams and closed=false.
All fifty clock futures returned. This is a different symptom from the earlier
quiche Initial-phase stall; expiry is not relabelled completion.

The unchanged pinned Neqo ff4f4c61 HTTP/0.9 server owns read_state and write_state
maps keyed only by StreamId (a u64), while process_events iterates all active
connections. Its multiconnect client uses download_in_series. Thus its sequential
self-control does not exercise the same cross-connection state overlap as fifty
parallel candidate clients. An earlier native diagnostic also recorded responses
with another request's numeric size. These observations identify a reference
application isolation concern, not a proven attribution of every official failure.
The next run returns to quiche to observe the originally failing Initial-phase
connection's clock deadlines with the same e2d97dc executable source.


## Actual clock boundary: quiche L1 run 37411717036

The unchanged quiche control passed, and the candidate server passed the runner
cell (49 sampled terminal returns and one outstanding at runner shutdown, not
50 clean retirements). The candidate client failed the unchanged 300-second
case limit with 49 length-complete files and one incomplete handshake. Session
3257275226 had actually sent 19 and received 12 datagrams. Its latest clock
request at 283130335 us specified deadline 560572808 us. Its latest committed
trace reached TimerTaken at ordinal 581. This establishes a real backed-off
future deadline beyond the case budget; it does not establish why handshake
progress failed or prove that every prior receive/retransmission was correct.
Artifact 11389169979 retains this failed result. No production deadline was
changed, and no root repair is claimed.

The next diagnostic exports only a bounded numeric whitelist from the runner's
existing captures: relative times, ports, connection indices, packet/frame
numbers, CRYPTO offsets/lengths and ACK range numbers. It supplies no key log
and exports no payload, CID, hostname, address, raw log or capture. Coalesced
fields remain independent lists and must not be zipped into invented packet
associations. Input file descriptors reject links, the native dissector has a
20-second limit and an 8192-frame scan cap, and failed/oversized/malformed
output is withheld. This observes existing runner traffic without altering the
runner or endpoint; complete capture coverage is explicitly not claimed.
Local parser/privacy fixtures cover the whitelist and failure boundaries.
The local workspace has no tshark binary, so actual dissection is still a CI
verification requirement, not a locally verified result.

## Stop/expiry overlap reproduced locally

Run 37413518827 on 3986103594 passed the unchanged quiche L1 control and
candidate-client cell, but failed the candidate-server cell. The last server
session's actual trace committed StopReceive/ReceiveStopped and then sent
StopTimer (role 7, label 222) without the stop receipt. Numeric capture
extraction succeeded on both sides; this is a different boundary from the
previous client Initial PTO backoff, and does not establish that both share a
cause.

A capacity-one fixture using the real timer local reproduced the scheduling
hole: consume TimerExpired, allow the independent StopTimer to occupy the
carrier, then attempt TimerTaken. Before the correction it failed with
`stop blocked the in-progress timer acknowledgement`. The timer was awaiting
TimerTaken while not polling its already-owned stop receive, leaving both
messages unable to finish.

The correction keeps that exact stop receive runnable alongside the owned
expiry send/receive future. If stop is actually received first, the existing
expiry is still fully acknowledged before TimerRetired/TimerAcknowledged and
TimerStopped. No pending exchange is dropped on successful stop, no new
progress flag or state manager is introduced, and carrier capacity is unchanged.
The explicit pin here preserves an in-progress exchange across executor
selection rather than hiding or cancelling it. The new regression and the two
existing timer tests pass; full regression and external interop remain required
before claiming qualification. The earlier long Initial backoff remains open.

Local verification of the final timer correction: `cargo test --locked` passed
424 library tests, all integration groups (including 20 connected-application
cases), and 26 compile-fail/doc tests. The thumbv6m no_std library check and all
116 host tests passed. Source audit, the existing controller guard and the
1193-file c3d89f78 snapshot check passed. The changed timer file is rustfmt
formatted; whole-repository fmt still reports pre-existing unrelated formatting
and is not claimed clean. External interop qualification remains pending.

Remote qualification of 397acc54: runtime 37415310732 passed every actual step.
Interop 37415310712 attempt 1 passed quiche control/server but failed client:
49 successful transfers and one actual idle expiry (67.179 s, unconfirmed,
submitted 1/completed 0), with all fifty futures returned. Artifact11391555489
is retained, not replaced by the later pass. Its numeric captures show one
flow receiving ServerHello around 6.9 s, Handshake traffic around 7.17 s, then
client Handshake retransmissions at 22.312 and 52.580 s. This is evidence of a
remaining loss/backoff boundary, not proof of an executor hang or a fabricated
successful terminal.

Attempt 2, artifact11392225772, passed the unchanged control and both candidate
L1 directions. Client fifty actual terminals and the final report confirm
50 files, zero idle expiry, closed lifecycle and resources retired (28.787 s
endpoint duration). Six server futures were still pending when the runner
ended; runner-cell success is not fifty clean server retirements. A third
unchanged-source measurement is requested with both prior outcomes retained;
no new historical unique cell or reliable root resolution is claimed.

The third unchanged-executable measurement (37417448473,
artifact11392143204) again passed quiche control and candidate server, while
one candidate-client connection actually expired (index20, unconfirmed,
submitted1/completed0, 48.089 s). All client futures returned. Across these
three measurements the client outcome is fail/pass/fail, with every control
and server runner cell passing. Do not promote one passing run into stable
qualification or merge this candidate on that basis.

The next capture diagnostic uses only the already-created reference endpoint's
fixed `keys.log` inside the same CI environment, via a held regular-file
descriptor with a 1 MiB limit and no symlink traversal. This follows the pinned
runner docker-compose SSLKEYLOGFILE contract; it does not add endpoint key
logging, transmit keys or export a key file/hash/path. Numeric packet/frame,
ACK and CRYPTO-length metadata remains the only report content. This allows
Handshake/1-RTT numeric observations to separate missing Finished,
HANDSHAKE_DONE and response delivery. A supplied key file is not itself proof
of successful decryption. Missing/rejected files are disclosed, and raw
payload/keys/stderr stay withheld. The endpoint executable and all test
success conditions remain unchanged. Local Python tests: 66 passed.

Numeric reference-key dissection was actually verified in 37418902751:
artifact11393080404 reports locally supplied reference keys and parsed numeric
ACK/CRYPTO/HANDSHAKE_DONE fields on both capture sides. Control and both
candidate L1 directions passed, with fifty client terminals and zero idle
expiry. Runtime37418902557 passed all actual steps. Earlier failing outcomes
remain authoritative evidence against stable qualification. The next diagnostic
is narrowed to candidate client L1 plus unchanged quiche control to capture
that remaining failure with the now-verified numeric dissection. No product
source or timer changes accompany that measurement.

## Timer local progress belongs to Hibana

The last numeric-diagnostic series 37420065430 passed its unchanged quiche
control and candidate-client cell in all three attempts (artifacts11393326131,
11392694935,11393308585). Each actual final report has fifty successful client
terminals, zero idle expiry, closed lifecycle and resources retired. Endpoint
durations were 55.402,46.141,62.983 seconds. This does not erase the earlier
intermittent failures or establish their cause. Repeating only this same cell
is not treated as completion of the all-file local audit.

The finite timer's six progress messages now carry unit rather than mirrored
u64 counters: TimerExpired/Taken, TimerRetired/Acknowledged and
StopTimer/Stopped. Their real send/recv and projected ordering remain; the
extra sequence increments and echo equality checks are removed. Real numeric
deadlines, recovery accounting, actual native waits and ownership remain.
The capacity-one overlapping stop/expiry regression still passes without an
auxiliary progress flag or new communication helper. The exact pending expiry
is retained until acknowledgement before retirement.

Local final checks pass: all424 library plus integration/doc groups, thumbv6m,
all116 host tests and selected host lib/hq strict Clippy (dependency warnings
remain separately visible). The changed timer file is formatted; no global
formatting cleanup or complete all-file migration is claimed. The next remote
request rechecks C1/L1/M/Z in both directions and the existing formal models,
rather than using another isolated L1 pass to declare root resolution.
