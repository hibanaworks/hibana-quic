# TLS phase-local production ownership

`roles::protocol_tls_phases::tls_choreography` is the production TLS global.
The old `roles::protocol_tls` import path only re-exports this graph; it does
not retain another protocol. Existing connection/bootstrap globals compose
this TLS graph with other independently repeating services using `g::par`.

`tls_owner::run_borrowed` starts two actual role locals. Their roots execute
installation, then these literal continuations in order:

| Local continuation | Admitted packet/key operations | Authority to advance |
| --- | --- | --- |
| Initial | Early packet crypto and replay-claim ownership | Successful TLS input/output produced Handshake keys |
| Handshake | Early and Handshake packet crypto | Successful TLS input/output produced 1-RTT keys and TLS finished authenticating its peer |
| Unconfirmed | Early, Handshake and 1-RTT crypto; validated ACKs | A consumed Path-owner `HandshakeConfirmation` accepted by the provider |
| Confirmed | Previous operations plus local key updates | Explicit Handshake key discard |
| Application | 1-RTT crypto, validated ACKs and local updates; retained early receive/claim/cleanup | Final retirement only |

Every phase also has TLS input/output, maintenance, a unique integrity-budget
loan, and retirement. Its direct `send`, `recv` and `offer` operations match
its own projected selectors. There is no universal provider operation loop.
The public mailbox `Client` does not grant phase admission: an out-of-phase
request fails closed before invoking the provider. Provider-level numeric,
key-use, replay and cryptographic checks still apply to admitted requests.

The private `CommandAuthority<Phase>` and `OwnerAuthority<Phase, T>` are
non-Clone and move into the corresponding continuation. Each has only its
specific forward conversion. `OwnerAuthority` owns the provider by value.
An advance consumes the old capability and returns only the next one. The
root consumes the announced typed grant before entering that continuation.
No mutable provider handle, raw key handle, or old phase capability is
returned to a mailbox client.

The phase locals preserve the authority-bearing operation bodies:

- `HandshakeConfirmation` and `KeyAckGrant` are consumed and connection-
  generation checked; copied snapshots cannot substitute for them
- Successful opens carry plaintext-bound `OpenReceipt` or distinct
  `EarlyOpenReceipt`; successful seals carry `SealedPacket` integrity
- Finished transitions retain parameter-bound receipts and early rejection
  grants; replay claim, remembered limits and early generation move together
- Integrity loans move the sole budget out and block all further provider
  work until the exact affine return; cancellation leaves no reusable loan
- Request/reply slots clear on cancellation, packet scratch uses `Zeroizing`,
  and the provider is dropped before final retirement is announced

## Elastic-roll limit

The current exact vendored Hibana revision is
`a9371bea437bbc1f4303ceeb3fc833f605efe730`, a performance-only successor to
`3aef31ba015c75ea824b8b41f5603b03f5dd336b`. No external correctness repair is
included. Its unchanged elastic `roll` semantics permit global
re-entry into an old body. The graph alone therefore does **not** prove that
an arbitrary raw endpoint cannot choose an old phase again. Production
past-phase finality depends on the consuming role-local capabilities and
exclusive root sequencing described above. At an announced boundary the
client directly receives the grant; it does not ask `offer` to preview an
elastic old roll tail.

This is an explicit implementation boundary, not a claim that the Hibana
core has been repaired or that its failing legal traces are qualified.
Compilation, focused runtime tests, allocation tests and full connection
qualification must be reported separately. The existing core trace blockers
remain blockers; no provider operation, dummy command or priming exchange is
inserted to work around them.

## Scoped verification checkpoint

The frozen exact-3aef checkpoint (before the residual early correction)
source-checked the production library. A full `tls_integrity_loan` runtime
build with the new complete staged graph was killed by the environment during
Rust compilation; no test from that invocation ran. Its original test and
failure log remain present.

`tests/tls_initial_phase_prefix.rs` separately projects the exact installation
and complete Initial work body, retaining the real grant-vs-retirement
boundary while ending the unselected grant branch after its grant. It calls
the unchanged production `run_borrowed` root and a real `BoundedTls` provider.
Four tests qualify only this Initial-prefix slice. A fifth keeps the complete
Initial and Handshake bodies and their grant/retirement boundaries, receives
a real ServerHello-derived HandshakeKeyGrant, and retires immediately in the
new phase. That verifies this one consuming capability transition, while
explicitly checking that TLS still awaits certificate/Finished authentication.
Neither slice qualifies the complete production projection. No dummy commands are inserted. The prefix
covers fragmented real ClientHello output, first retirement, stale queued
commands, Q1 cancellation/drop, and rejection of unavailable Handshake work
before provider crypto. The latest five-test run passed with zero-allocation
assertions in 29.94 seconds total (compile plus tests), with 789,140 KiB maximum
child RSS. Logs live in `artifacts/tls-phase-production/`.

After adding the four residual early arms, expanded source size is 333 sends,
140 routes and five rolls. The frozen checkpoint was 318/133/five. A possible
future optimization is factoring the shared final `ResultTaken` after each
phase's request route, keeping the integrity loan's intermediate receipt in
place. That would remove about 74 sends without changing visible label
sequences, but could alter event identities and elastic-roll masks. It has
not been implemented or established equivalent; it is not a core fix.

## Remaining integration risks

- `ConfirmHandshake` is admitted only in Unconfirmed. Reusing confirmation in
  Confirmed or Application terminates admission. The current Path owner mints
  its confirmation once under `!confirmed` and transfers it with `Option::take`;
  callers must preserve this one-shot behavior
- Handshake discard is admitted only in Confirmed and consumes the transition
  into Application. The transport's `discard_requested` / `discarded` guard
  must continue preventing a second discard
- Early-key lifetime remains independent of Handshake retirement. Application
  now explicitly retains `OpenEarly`, `EarlyHeaderMask`, `TakeEarlyReplayClaim`
  and `DiscardEarly`, grouped as `RetainedEarlyReceiveWork`. Its single owner
  still holds the whole Provider. Early sending, Handshake operations and
  reconfirmation remain excluded. The graph admits residual requests after
  early discard, but the Provider's actual destroyed key makes subsequent
  opens/masks return `KeysUnavailable`; the graph does not itself seal that
  independent lifetime. No copied key-presence state grants crypto authority
- Live first-1-RTT, close and rejection cleanup retains its actual `DiscardEarly`
  operation. Handshake discard never substitutes for it or destroys server
  early keys prematurely. The first-1-RTT path follows authenticated packet
  processing; rejection follows the affine TLS rejection grant through Recovery.
  The discard operation destroys authority rather than creating any. See
  [RFC 9001 §4.9.3](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.9.3)
  for the independent key lifetime
- An out-of-phase operation now terminates the owner before invoking TLS,
  rather than returning a provider-level `KeysUnavailable` or
  `KeyUpdateNotAllowed`. Low-level TLS rejection tests belong at the provider
  boundary; live callers must not depend on those rejected operations for
  ordinary progression
- Cancellation closes the mailbox client and drops the owned phase/provider.
  It does not restore an old phase or allow a caller to retry with consumed
  confirmation, ACK, receipt, or integrity-loan authority. Initial cancellation
  has runtime evidence here; later-phase cancellation awaits full qualification

## Performance-vendor and residual-lifetime checkpoint

On exact performance-only revision
`a9371bea437bbc1f4303ceeb3fc833f605efe730`, the unchanged five production-root
prefix tests passed after adding the residual Application early arms. The
fresh compile plus tests took 34.56 seconds; maximum child RSS was 789,724 KiB.
This is still prefix evidence, not residual Application runtime qualification.

One bounded full `tls_integrity_loan` build was stopped by its memory guard
at 2,637,548 KiB sampled process-group RSS after 52.95 seconds during const
lowering. No test ran and no runtime pass is claimed. Logs are separate in
`artifacts/tls-phase-a9371/`; the exact-3aef source archive and old failure logs
remain under `artifacts/tls-phase-production/`.

`tls_owner/application_early_tests.rs` adds pending private source coverage for
real late 0-RTT after actual server Handshake-key discard. Its setup directly
drives real ticket issuance and resumed BoundedTls through Finished, calls
provider confirmation and Handshake discard, then runs the unchanged
Application-local command and provider functions. It checks genuine early
receipt/mask/replay-claim behavior and `KeysUnavailable` after actual early
key destruction. It does not manufacture Finished/Path grants or qualify the
full root transition. The aggregate private test target has not been rerun;
this fixture is not yet a runtime result.
