# Direct-control audit and feature boundary

The inventory below records earlier migration checkpoints. For the latest
qualified commit, see ACTIVE-IMPLEMENTATION.md; whole-codebase completion is
not claimed. Current finite-handshake work removes pure progress echo IDs while
retaining actual schedule revisions, packet numbers and scope-bound resources.

This audit separates protocol-control authority from arithmetic, observed facts
and resource occupancy. A boolean search alone cannot establish migration.
The static guard in ci/audit_control.py only prevents the specifically deleted
controllers from returning under their old definitions. Renaming a controller
would evade that guard; actual global/local review and runtime tests are required.

## Removed control paths

- Early-data Phase and slot flags: the direct four-role projected lifetime moves
  actual AEAD/Finished resources. Host 0-RTT routing remains a future capability.
- Combined ApplicationKeys and the provider Legacy branch: deleted.
- Write-key confirmation/current-ACK flags: actual scoped receipts retained.
- Read-key Pending enum: the actual receive PacketKey moves through the
  authenticated update/readiness receipt and returns only with its outcome.
- Key-owner/RX retirement flags: actual closing-key transfer and consuming retire.
- Duplicate closing flag: the finite post-parallel global owns closing.
- Recovery close_only: the ledger retains the actual OrdinaryRetired graph proof.
  Its redundant terminal flag is replaced by the existing terminal-accounting
  snapshot; burned packet numbers remain available and ordinary reuse stays shut.
- Transcript retirement consumes the transcript.
- KeySource Finished/integrity/early handoff flags: actual verified Finished,
  actual integrity budget and actual early key are each taken once.
- Stored key-schedule Stage: observation is derived from retained secret material;
  secret replacement/drop performs the real destruction.
- CID retirement_acked and copied live-CID admission: deleted. A unique owned
  Retirement leaves the history table once. There is no old CID retry/ACK driver.
- Unconnected Paths, PathEcn and ClientRetry controllers: deleted, not hidden
  behind compatibility APIs. Address types, counter validation, packet integrity,
  token cryptography and bounded identity history remain numerical kernels.

## Remaining data representations

PacketState/ReferenceState record reservation, accepted send, loss and ACK facts
for bounded accounting; they do not run socket futures or choose choreography
continuations. Wire FIN/key-phase/ECN bits are packet data. BoundedTls State is an
observational verification/failure result, not the handshake operation dispatcher.
TLS handshake order is in bounded_tls protocol globals/direct locals. Allocation
occupancy, nonce/replay tombstones and RAII cancellation guards retain fail-closed
resource safety. Removing them would not be a control migration.

## Future endpoint features, not retained alternate controllers

The dynamic CID retransmission/ACK path, local key-update trigger policy,
path migration/ECN/Retry endpoint behavior and host 0-RTT are not qualified by
numeric or isolated role tests. LocalUpdate/Installed/Rejected/Settled exists in
RX_KEYS/TX_KEYS; both branches have real-endpoint tests, but positive ACK evidence
is explicitly synthetic there. New capability integration must use those actual
contracts/resources, never restore an independent phase dispatcher.

The existing implemented connection-control migration and the removal of the
unused alternate controllers passed the final local source review and regression:
385 unit,70 integration,26 compile-fail,29 reference TLS,100 host,thumbv6m and
47 Python plus4 impairment tests. This is a migration checkpoint, not a claim
that the future endpoint capabilities above are implemented or verified. Official
qualification remains14/44 at the last published checkpoint; this exact replacement
requires its own runner result, followed by 0-RTT and subsequent case development.
