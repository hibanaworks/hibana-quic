# Whole-provider roles

`roles::tls_owner` owns an actual `tls::Provider` in one local task. The underlying provider remains responsible for TLS parsing, certificate/Finished verification, key derivation, AEAD limits, and its coupled application-key lifecycle. The actor is not a second TLS state machine and exposes no mutable provider handle.

`ApplicationKeys` cannot be split into independent receive/send keys: authenticated peer updates advance the write key before the resulting ACK, and confirmation, ACK eligibility, generation counters, precomputed successors, and retained prior keys share one owner. The whole-provider design preserves that coupling.

## Visible operations

The concrete `protocol_tls::tls_choreography::<CLIENT, OWNER>()` fragment is composable under one global `g::par`. The local roles use literal endpoint `send`, `recv`, and `offer` awaits. Requests are specific: CRYPTO input/output, Handshake or phase-aware 1-RTT open/seal, header mask, confirmed-handshake evidence, validated one-RTT ACK evidence, timer maintenance, key update, Handshake-key discard, integrity loan, and retirement. There is no universal opaque event envelope or manual endpoint poll.

Provider work decides result branches. Large packet/transcript temporaries are scoped before result publication, and `ResultTaken` records transfer from the shared slot. Caller-owned mailboxes and arenas bound storage. `take_crypto_flight(max_len).await` honors the transport's actual flight-fragment capacity, independently of packet-buffer size; the current endpoint uses 900-byte fragments. Incoming contiguous reassembly must be chunked to the configured capacity and consumed only after `CryptoAccepted`.

Every reply includes a copied bounded snapshot: TLS progress, key availability, phase, independent receive/send generations, negotiated group, and peer parameters. Snapshots are observations. They cannot grant authentication, validate an ACK, or authorize a key update. `ConfirmHandshake` must come from QUIC handshake-confirmation evidence, not merely TLS completion; `ValidatedAck` still requires actual sent-history/range validation at its source.

## Affine Initial integrity loan

The initial-key actors and the TLS owner must use the same actual connection budget for a bounded backend. A loan follows a projected sequence:

LoanIntegrity → IntegrityGranted → ResultTaken → IntegrityReturned → IntegrityRestored → ResultTaken

The provider replaces its budget with an exhausted tombstone, transfers a private non-Clone grant, and directly awaits the matching return before accepting any other operation. The client-side loan exclusively borrows the TLS client. Its only consuming crypto use is a sealed `InitialOpen` capability; there is no public raw-budget accessor, arbitrary callback, or replacement-budget constructor. Generation and sequence correlate the return. Dropping a loan or cancelling its operation closes admission and terminates its owner. A backend with no transferable budget takes `LoanUnavailable`; no fallback budget is invented.

The crate-owned `InitialProtection` facade implements the sealed `InitialOpen` boundary. The live endpoint uses this loan for Initial authentication and preserves the actor-produced affine Open receipt through authenticated parsing.

## Remaining control migration

The actor exposes real owned-provider 0-RTT seal/open/header-mask operations and moves the provider's non-Clone replay claim unchanged into the receive quarantine. Early Open produces separate affine evidence only after actual AEAD succeeds, bound to the provider's early generation and the actor operation. A successful CRYPTO input that actually changes TLS from handshaking to finished produces one affine Finished receipt. Ordinary Handshake/1RTT Open receipts cannot be manufactured from snapshots or substituted with early receipts.

Snapshots also carry remembered early limits, early generation, optional resumed/suite/integrity-count observations, and bounded UTF-8 failure diagnostics. These are copied before suspension and expose no mutable provider escape.

The exported live control grammar is now the staged graph: `protocol_tls`
re-exports `protocol_tls_phases`, and the production root consumes private
Initial, Handshake, Unconfirmed, Confirmed and Application capabilities while
moving its provider between literal phase-local continuations. There is no
universal-loop fallback. See [TLS phase ownership](tls-phase-ownership.md) for
the operation map, exact runtime evidence and elastic-roll limit.

This wiring is not complete runtime qualification. The full staged integrity
test target was killed during compilation, while separate real-provider prefix
slices passed. Existing exact-vendor core failures remain unresolved. The independent 0-RTT lifetime is now explicit in a narrow Application
residual receive/claim/cleanup group. Actual key destruction remains enforced
by the one Provider, not by a copied readiness flag or a second shared-owner
loop. Runtime qualification of that correction remains separately reported.

The legacy receive/ACK/delivery driver remains a separate migration. An authenticated receive result must lead to actual ACK validation/accounting and stream delivery in those resource-owning roles, rather than replaying markers after caller-owned effects. Wire parsing, packet-number restoration/replay bounds, ACK ranges, congestion arithmetic, stream offsets, and TLS cryptography remain data/algorithm obligations. No full QUIC/TLS reachability, interoperability, or Pico memory-fit claim follows from this actor alone.

The vendored elastic roll does not graph-seal a completed continuation. Retirement therefore destroys the actual provider and consumes/closes its capability, with the enclosing owner retaining endpoint values until all sibling actors finish.

## Verification

`tests/tls_owner_roles.rs` uses real deterministic test-only certificates, actual bounded TLS client/server providers, real certificate validation and packet protection, and counted allocation checks. Routine coverage includes 900- and 17-byte fragments; the one-byte debug stress is explicit and expensive. `tests/tls_integrity_loan.rs` exercises the same budget across real Initial AEAD, return/reloan, loan cancellation, and optional capability absence. These are local actor results, separate from network interoperability. `tests/managed_zero_peer_cid.rs` additionally drives paired live endpoints with each connection's Initial RX/TX and whole TLS owner facets in one `g::par`: real full bounded handshake, bidirectional 1-RTT, ACK/ECN/path accounting, graceful retirement and authenticated CID-error handling, with counted zero allocations. The three cases must be rerun after this staged-control cutover; their prior evidence does not qualify the new grammar.
