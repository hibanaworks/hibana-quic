# Experimental independent client retirement

This candidate is isolated on `ci/parallel-client-retirement`. The qualified
`development/rolled-route-runtime` head remains f160c2d2. Do not infer adoption
from this document or a native diagnostic.

The client previously awaited every connection's full closing interval before
starting the next independent connection. Fifty corruption-impaired connections
against native Neqo took 52.426 seconds. The candidate joins at most 64 distinct
existing projected connection owners concurrently; there is no extra QUIC phase
controller, thread pool or per-connection progression flag. Actual failures are
retained and every worker settles before native socket/timer ownership is checked.
Ticket-dependent resumption remains sequential.

Two termination distinctions are explicit:

- Normal local completion must not abandon retained control flights merely
  because native publication accepted them. The existing recovery owner exposes
  actual outstanding flights; an authenticated ACK regression checks the boundary.
- An authenticated peer close starts draining. Complete authenticated response
  delivery and handshake confirmation remain required. Missing request ACKs stay
  false in the report; the receiver does not fabricate acknowledgments or keep
  retransmitting after peer close. An encrypted ACK-loss test exercises this
  outcome with the actual projected peers and real stream FINs.

After ordinary RX has actually retired, the closing local owns the native receive
borrow. It responds to attributed late datagrams through the existing global
Datagram/Accepted-or-Rejected/Settled continuation until the original 3-PTO
closing deadline. Responses are bounded by three times actual input bytes and
progressively require more input packets, limiting close-response ping-pong.
See RFC9000 sections10.2.1–10.2.2:
https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2

## Evidence and unresolved boundaries

Core422 tests and integration/doc groups, sixteen connected tests, selected host
strict Clippy and thumbv6m passed. The forty-file native 0-RTT diagnostic passed
both directions after the changes. These are not official runner results.

The final-rate candidate's self-peer fifty-connection clean run completed in
2.408 seconds including both peers' real retirement. Its loss run completed in
6.455 seconds with all hashes and actual closes. A corruption run completed all
fifty client files and retired resources, but one server connection genuinely
idle-expired; the strict all-clean diagnostic therefore failed. This failure is
not reclassified as normal close or removed by extending a timeout.

Parallel native Neqo diagnostics failed even without impairment. The pinned
unmodified Neqo HTTP/09 server keeps partial read/write state in maps keyed only
by StreamId while iterating multiple connections; all these independent requests
use stream0. Its log observed fifty partial requests but only seven response
STREAM frames in one run. This is a source-backed explanation to investigate,
not a successful reference control or a claim about the whole Neqo transport.
The official quiche C1/L1 comparison is recorded below.

## Exact-head official result

Candidate d5b308ff passed runtime CI 37389272301 and official runner
CI 37389272661. Artifact 11380468306 was downloaded and inspected: both quiche
controls and both candidate directions passed handshake corruption and loss.
All six existing Lean and six Z3 model groups passed in that run.

The client reports show fifty files, fifty connections, zero idle expiries,
actual lifecycle close and resource retirement. Corruption took 20.132 seconds
and loss 24.014 seconds. The fifteen-second target remains unmet. The server
direction passed the official runner's file criteria, but the runner terminated
the server without a final retirement JSON; this does not establish fifty clean
server closes. The self-peer corruption failure above remains unresolved.
An unchanged-source repeat passed with both peers retired in 19.879 seconds;
that repeat does not erase the earlier failure or establish its cause.
A second unchanged-protocol repeat reproduced one server idle expiry and one
client idle expiry after complete response delivery, with client request ACK
evidence still absent. The client correctly returned failure; no normal close
is inferred from receiving all file bytes. Private per-peer diagnostic logs
are retained locally for investigation.

The canonical branch remains f160c2d2. These results qualify the selected
C1/L1 cells only, not the whole matrix or the all-file control migration.

## Response completion follow-up

An encrypted deterministic fixture now reproduces a termination stall without
random timing: drop server application ACK-only packets, keep the server open,
and deliver the complete authenticated response and FIN. Before the fix, the
client kept waiting for request ACKs and exceeded the fixture's simulated-time
bound. The client had completed its application exchange, but that completion
was incorrectly coupled to request-packet acknowledgment.

The global contract now declares a distinct `ResponsesComplete` edge. Its local
requires actual source retirement, all response FINs consumed, handshake
confirmation and settled native publications before initiating application close.
The request ACK report remains false when those ACKs were lost. The existing
server completion rule still requires response-chunk acknowledgment; no timeout
is renamed and no packet ACK is manufactured. The normal close/drain and actual
resource-retirement continuations remain mandatory. See RFC9000 sections5.3 and
10.2 for application-initiated connection close.

The formerly failing fixture and all seventeen connected-application tests pass.
Native impairment and complete regression qualification of this follow-up are
still pending. This does not establish reliable delivery of every close packet
under arbitrary network loss.

The first native forty-file 0-RTT follow-up received all files, resumed, closed
and retired, while reporting `all_streams_acked: false`. Its older diagnostic
assertion required that transport fact even after complete responses, so that
run failed the old assertion. The native diagnostic now checks the explicit
application-completion contract, exact completed-file count, hashes, real close
and retirement while retaining the actual ACK field. The encrypted ACK-loss
regression specifically requires that field to remain false. Official runner
criteria are unchanged. A self-corruption run also retained one genuine server
idle expiry; it remains a failure and is not explained away by this distinction.

The local impairment fixture now records a delayed send rejected by an already
closed peer as destination-unavailable, not as forwarded. A unit test verifies
that the rejected packet releases queue accounting without claiming delivery.
The official runner and its success criteria are unchanged.

## Integrity before host admission

A later self-corruption run delivered49/50 files: the remaining client never
confirmed the handshake and the server eventually reached its root deadline.
An actual UDP regression reproduced accepting a bit-flipped source CID from an
Initial before verifying its AEAD associated data. That could permanently bind
an incorrect peer identity or consume an admission slot before the intact retry.

Single and parallel host admission now check v1 Initial integrity before
committing routing identities, tokens or worker assignment. This is a bounded
cryptographic check, with no protocol phase, communication wrapper or new flag.
Initial keys are public, so it is explicitly not TLS peer authentication.
The untouched packet still enters the ordinary Hibana authentication path.
The test rejects the damaged Initial and then admits the intact packet with the
correct IDs. Version negotiation and bounded rejection/yield tests also pass.

The dependency candidate now selects c3d89f7 after verifying its eleven changed
Git blobs and exact snapshot manifest. Its distinct nested-visit reset repair is
exercised with zero, one and three samples, enclosing reentry and duplicate ACK
rejection on the actual capacity-one QUIC carrier. Upstream CI37396155673 and
consumer regression are still pending; the resident body is not updated here.

Hibana12383a07 carries the same production entry-selection repair as4d0077b9.
Its additional change separates the64-repetition native stress case from Miri;
upstream CI37384075093 was read as success. The body is not updated by this pin.
