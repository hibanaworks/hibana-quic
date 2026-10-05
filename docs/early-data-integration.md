# 0-RTT integration status

This is an implementation ledger, not an official interop result.

Current observed qualification is **20/44** unique candidate case/direction cells.
The first sixteen came from seven
existing cases in both directions at `99943a86` in
[run 37255425723](https://github.com/hibanaworks/hibana-quic/actions/runs/37255425723),
and real session resumption passed both directions at `622a17a4` in
[run 37257163222](https://github.com/hibanaworks/hibana-quic/actions/runs/37257163222).
Server-only 0-RTT passed the unchanged runner against quiche in
[run 37261848054](https://github.com/hibanaworks/hibana-quic/actions/runs/37261848054)
at `4ba95dd2`, together with the same-image quiche/quiche control. The fixed image
was `cloudflare/quiche-qns@sha256:6cbde3c4767c8894917d6c88e62890a4e663188a36bb606907afc48ffd7fd7fc`.
Candidate client 1-RTT payload was 3,857 bytes (limit 5,000); 0-RTT payload was
11,125 bytes. This quiche result corroborates the same server Z cell; it does not add a
duplicate matrix cell. Client-side early transmission now passes the native diagnostics below; official client Z passed as described below.
Blackhole passed both candidate directions and its unchanged Neqo control at
`e33e9df1` in [run 37269130471](https://github.com/hibanaworks/hibana-quic/actions/runs/37269130471).
This adds the server B cell to the previously qualified client B cell (run37263917795).

The unchanged Neqo/Neqo control in [run 37259858685](https://github.com/hibanaworks/hibana-quic/actions/runs/37259858685)
transferred all files, but the unchanged trace verdict measured 22,726 bytes of
0-RTT payload and 7,626 bytes of client 1-RTT payload, exceeding its 5,000-byte
limit. The candidate was not executed in that run. In the subsequent
[run 37260959576](https://github.com/hibanaworks/hibana-quic/actions/runs/37260959576),
the unchanged runner passed Neqo client to hibana-quic server: forty files,
10,698 bytes of 0-RTT and 1,834 bytes of client 1-RTT payload. The Neqo control
still failed, so that combined run remains NOT_PASSED. The server Z cell is now counted once after
the independent successful quiche control/candidate run, without counting peer
duplicates or fabricating a successful Neqo self-control. The successful quiche control/candidate pair above is recorded separately from the Neqo matrix. A completed negative control
may now be followed by candidate diagnostics, only after valid case results,
compliance and cleanup. A combined run is PASSED only when its control and
all selected candidate directions pass; setup/cleanup failures stop execution.

Native control diagnostics need two additional precautions: Neqo's normal
server rejects early data for its first ten seconds, so the fixture waits eleven
real seconds without changing its clock or anti-replay implementation. Its
negotiated greased fixed bit must also remain in the packet-byte accounting;
unknown client datagrams invalidate the bound. Three repeated forty-file native
runs passed after these corrections. These controls use numeric 250-byte names
and generated bodies of 32..71 bytes, rather than the runner's exact random
32-byte files, and cannot replace its trace verdict or explain its failure alone.

## Implemented and locally exercised prerequisites

- Host `--session resume` retains the actual ticket cache/key across two fresh
  connection scopes. The first request warms the ticket; the remaining requests
  use the authenticated ticket. A failed/non-resumed second connection is an error.
- Post-handshake CRYPTO flights use the shared application packet-number/recovery
  ledger, exact retained plaintext binding and real short-header protection.
- Real UDP two-connection transfers passed with two files, then forty files with
  250-byte names and 32-byte bodies. This was ordinary resumed 1-RTT transfer.
- Unmodified pinned Neqo also passed native resumption in both directions. The
  candidate reported two connections, actual TLS resumption and completed close;
  downloaded content hashes matched. This is not an ns-3/official trace verdict.
- Real TLS-derived AES and ChaCha early keys now protect full QUIC long headers.
  Tampering, wrong destination, discarded keys and duplicate receipt extraction
  are rejected. Actual Finished gates the projected quarantine release.
- Early and ordinary application packets share one monotonic PN allocator.
  Cancelled early submissions burn their PN. An ACK for early data cannot mint
  a 1-RTT key-update grant; an ordinary ACK still requires its recorded epoch.

## Receive integration under verification

The server's optional `--early buffered` requires file mode and `--session resume`.
The same caller-backed quarantine storage is checked by TLS and given to the
connected owner. The prefix retains bounded *untrusted ciphertext*, then the
connected global runs an explicit optional early bridge after authenticated
startup. Each packet must authenticate and be wholly retained before its owned
stored-packet proof exists. Only an accepted, same-generation server Finished
can turn that proof into ACK history. Delivery and consumer acknowledgment run
through the existing early owner, before the ordinary file handler starts.

The complete-request queue has one slot per admitted stream (64). A response
source can wait for network ACKs, so an eight-entry queue was insufficient:
backpressuring RX there could prevent those ACKs from being consumed. The exact
capacity regression is documented in `proofs/request-admission-capacity/`.
Large caller-owned host allocations are explicit; no Pico RAM-fit or performance
claim follows from this host configuration.

Native 0-RTT testing exposed an ordinary-close race: RX key-control retirement
could remove the write key while the parallel transmitter still had work to
settle. The control-retirement receipt now leaves the actual key in its owner.
Transfer of that key requires the joined ordinary-retirement receipt at the
finite closing boundary. A copied stopped flag is not the permission. The
isolated projected key-role tests cover this ownership distinction.

A real peer close need not carry the server's final response ACK. The report
preserves `all_streams_acked=false` in that case; peer-authorized retirement is
not reported as acknowledgment. Client completion still requires actual ACKs.

Native server receive passed unmodified Neqo's forty-file early-data workload
with 250-byte names and 32-byte files. The latest run retained 12 accepted early
packets, 10,023 early stream bytes and 39 fully early-delivered requests after
the warmup request. All file hashes matched, true resumption and close completed,
and the measured client 1-RTT protected-payload upper bound was 1,609 bytes,
below the runner's 5,000-byte limit. This remains a native diagnostic, not the
official runner's packet-trace verdict.

## Remaining qualification gates

- Preserve the locally passing forty-file early receive behavior in the pinned
  official server-direction test, including its packet-trace verdict.
- Preserve the new client prefix, accepted-publication handoff and authenticated
  rejection replay in the same ordinary stream and packet-number ledgers.
- Run the pinned official `zerortt` case in both directions. Two connections and
  file delivery alone are insufficient: the runner requires early packets and
  bounds the client's 1-RTT payload volume.

The QNS adapter selects `--session resume --early buffered` for server reception
and `--session resume --early replay-safe` for client GET transmission. The runner
request names both candidate directions and the pinned quiche reference; its
unchanged same-image baseline and actual candidate verdicts remain mandatory.
Unselected directions are never counted as passes. No raw environment logs, generated keys or
session tickets belong in this source ledger.

## Preserved early-owner contract

`early_data::protocol` projects INPUT, OWNER, TLS and APPLICATION roles. Reject
and cancel wipe the owned bytes without refunding the consumed replay claim.
The deleted independent `Phase`, per-slot permission flags, early-send journal
and phase dispatcher must not return as compatibility paths. `HeldBytes` is a
private numeric byte/final-size ledger, not a public lifecycle API.

Input consumes actual AEAD evidence binding scope, packet number and plaintext.
A copied Verified label cannot release bytes without the owned Finished receipt.
The owner returns that receipt after checking scope, server side, accepted status
and generation. Focused projected tests cover absent Finished, premature release,
reject/cancel, deferred-control acknowledgment and data delivery. The zero-allocation
measurement covers the encrypted-input/projected-release component fixture; it is
not a whole-connection allocation or memory-fit claim.

## Performance acceptance

The requested performance target is processing speed comparable to Neqo, not
merely interop completion. Compare release builds under identical payload,
connection/concurrency, cipher, network and logging conditions. Report useful
transfer throughput, handshake/request latency, CPU time, peak resident memory
and retransmission volume separately from the final draining wait. The native
Neqo numeric-response server generates bytes while the candidate reads files;
that setup is an interoperability diagnostic and is not yet an apples-to-apples
server performance benchmark. The fair performance comparison remains open.

## Explicit join validation and completion bookkeeping

The dependency is now the exact published Hibana snapshot
`4b3e23248e6156563050bb2bcc735ac1f707fd11` (1,257 files, no local patches).
Its explicit-join contribution adds executable endpoint regressions and scoped
Lean/Z3 validation; it does not add a runtime resource API or change `par`.

The ordinary connection task set already waits for actual RX key-control
retirement, independent TX completion, adapter settlement, and other ordinary
roles. Its private `OrdinaryRetired` value then travels through the existing
finite retirement/close-authority choreography.

The extra `KeyControlQuiesced` object, completion inbox, optional result, and
`RetiredKeys` wrapper were therefore redundant and have been removed. The
actual `KeysRetire`/`KeysRetired` send/receive remains. Keys remain privately
owned until `take_closing` checks the existing joined receipt's scope and
takes the actual key once. The independent TX role is not stopped by early
key-control completion. There is no new per-packet synchronization.

## Client early transmission candidate (2026-10-05)

The optional early prefix uses actual projected send/recv/route/resolver edges.
Its ClientHello is published before the early packets. The next handshake TX
role receives an explicit causal handoff; a seq alone is not a substitute for
that communication. No packet-level control FSM or Hibana API was added.

Caller-owned bounded GET slots retain request intent. Early packets use the
real scoped TLS key, shared application PN allocator, congestion/ledger budgets
and actual UDP publication results. After accepted Finished, a finite admission
prefix materializes those exact requests and packet references before ordinary
RX can consume their ACKs. The source's production receipts cross the same
collector used by ordinary streams. On authenticated rejection only the early
epoch is cancelled, without resetting packet numbers, forging ACKs/loss or
refunding physical path bytes; replay uses the fresh peer limits and ordinary
source. The caller's started callback runs once per original request.

The unchanged native Neqo forty-file diagnostic passed all three directions.
The candidate client accepted 39 early packets/requests (10,023 stream bytes),
matched all forty file hashes, resumed two connections and closed. The measured
conservative client 1-RTT protected-payload upper bound was 754 bytes. The native
fixture now permits exactly two sequential loopback client endpoints for this
resumption test; previously it dropped the candidate's new UDP source port as
foreign, so that failed attempt did not measure early protocol correctness.
The one-endpoint default, foreign-IP rejection and old-port rejection remain.

An actual Neqo startup anti-replay rejection produced zero accepted early
requests and delivered all forty files through 1-RTT replay. A separate test
lost the first actual early datagram, then recovered every file under fresh
1-RTT publication (940-byte conservative upper bound). These are native
observations, not official runner passes or exactly-once application guarantees.

## Official client 0-RTT and next key-update check

At commit 6c20cf86, [run37272347426](https://github.com/hibanaworks/hibana-quic/actions/runs/37272347426)
passed the unchanged quiche control and both candidate Z directions. The unique
aggregate is 20/44 (24 remaining), without counting server Z twice. The actual
candidate-client trace measured 10,826 bytes of 0-RTT and 769 bytes of 1-RTT;
the reverse direction measured 11,125 and 4,981 respectively, so that latter
pass is not a claim of repeated margin under the 5,000-byte threshold. Runtime
run37272347413 also passed. Remaining cases and three repeated release attempts
are not claimed.

The next server keyupdate native attempt exposed an actual stale timestamp:
RX observed a packet, awaited the projected peer-key installation while other
roles progressed, then submitted the old observation time to shared recovery.
The monotonicity guard correctly rejected it. Recovery now reads the actual
clock at its synchronous commit after that await; it does not clamp time or
relax the rollback check. The failed-before native evidence and fixed 3 MiB
byte-exact transfer are separate from the pending official key-phase verdict.
