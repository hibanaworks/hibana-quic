# Direct local continuations

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
