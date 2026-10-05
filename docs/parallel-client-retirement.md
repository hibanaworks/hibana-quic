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
The official quiche C1/L1 comparison remains necessary.

The local impairment fixture now records a delayed send rejected by an already
closed peer as destination-unavailable, not as forwarded. A unit test verifies
that the rejected packet releases queue accounting without claiming delivery.
The official runner and its success criteria are unchanged.

Hibana12383a07 carries the same production entry-selection repair as4d0077b9.
Its additional change separates the64-repetition native stress case from Miri;
upstream CI37384075093 was read as success. The body is not updated by this pin.
