# 0-RTT integration status

This is an implementation ledger, not an official interop result.

The published control-migration checkpoint `aae9f1f176ba49f124e9764d929c2ed4aee2d382`
passed runtime run [37201207456](https://github.com/hibanaworks/hibana-quic/actions/runs/37201207456).
The metadata-only request at `a680b2e77efb357ed94ab49db5bd0411c73fe86c` passed the seven
existing cases in both directions in official run
[37201556694](https://github.com/hibanaworks/hibana-quic/actions/runs/37201556694).
The qualified scope remains **14/44**. Neither resumption nor 0-RTT adds a cell yet.

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

The forty-request bound is independent of the eight-entry complete-request work
queue. Queue backpressure is handled by the concurrent source; it does not reduce
stream admission to eight. Large caller-owned host allocations are explicit;
no Pico RAM-fit or performance claim follows from this host configuration.

Native 0-RTT testing exposed an ordinary-close race: RX key-control retirement
could remove the write key while the parallel transmitter still had work to
settle. The control-retirement receipt now leaves the actual key in its owner.
Transfer of that key requires the joined ordinary-retirement receipt at the
finite closing boundary. A copied stopped flag is not the permission. The
isolated projected key-role tests cover this ownership distinction.

A real peer close need not carry the server's final response ACK. The report
preserves `all_streams_acked=false` in that case; peer-authorized retirement is
not reported as acknowledgment. Client completion still requires actual ACKs.

Native server receive now passed unmodified Neqo's early-data mode with two
files (3 accepted early packets), then forty 250-byte-name/32-byte files
(11 accepted early packets, all content hashes equal, actual resumption and
completed close). This is a native diagnostic, not the official runner's packet
trace verdict. Per-stream early-delivery counters are being added to distinguish
whole-request early delivery from ordinary retransmission fallback.

## Remaining qualification gates

- Demonstrate accepted 0-RTT bytes against native Neqo, then the exact forty-file
  workload; keep negative/replay/capacity/close behavior fail-closed.
- Connect the client's early source/transmit ownership and rejection/recovery
  continuation to the same ordinary stream and packet-number ledgers.
- Run the pinned official `zerortt` case in both directions. Two connections and
  file delivery alone are insufficient: the runner requires early packets and
  bounds the client's 1-RTT payload volume.

The QNS adapter continues to reject unsupported cases until their actual endpoint
path and qualification are ready. No raw environment logs, generated keys or
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
