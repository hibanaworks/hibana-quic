# TLS owner authority test mapping

The affine Path and Recovery permissions have no public constructors. Tests
requiring them therefore live in the crate-private
`roles::tls_owner::authority_tests` module, not an integration-test escape hatch.
All three original full-handshake tests retain their names:

- `real_full_handshake_packets_metadata_and_key_updates_allocate_zero`
- `fragmented_full_handshake_packets_and_key_updates_allocate_zero`
- `one_byte_full_handshake_actor_stress_allocates_zero` (still explicitly ignored)

`tests/tls_owner_roles.rs` still contains the real certificate rejection,
four-boundary cancellation, and terminal-retirement integration tests.

## Evidence and negative cases

- Before ownership transfer, the same fresh real client provider rejects
  confirmation with `KeysUnavailable`.
- Actual Finished receipts authenticate the exact CID-bearing transport
  parameters. Path consumes real Initial AEAD evidence when learning the peer.
  A server obtains confirmation from verified client Finished; a client remains
  unconfirmed until its real TLS owner opens a `HANDSHAKE_DONE` packet.
- Successful ACK authority originates in a Recovery reservation, real TLS AEAD
  sealing, immutable protected datagram, awaited adapter acceptance, and a real
  authenticated ACK frame. Recovery independently rejects an authenticated ACK
  for an unsent PN with `AccountingError::UnsentPacket`.
- A delegating test provider preserves both original `InvalidInput` checks for
  an unsent PN and unseen receive generation in the exact actor-owned state,
  immediately before forwarding the genuine valid grant. These negative probes
  do not construct capabilities, substitute crypto results, or modify a success.
- The pre-confirmation `KeyUpdateNotAllowed` and post-discard
  `KeysUnavailable` checks occur at the provider seam because those operations
  are intentionally absent from the corresponding public phase selectors.
  The post-confirmation/pre-ACK update refusal remains an actor request.
- `retired_handshake_selectors_close_admission_without_calling_crypto` separately
  checks seal, open, and header-mask requests after retirement. Each must produce
  `UnexpectedCommand` in the owner, close client admission, reject subsequent
  work, and make zero post-retirement crypto calls.
- Private-construction and affine-use compile-fail examples accompany
  `HandshakeConfirmation` and `KeyAckGrant`.

The full-handshake allocation guard still starts before the real provider
constructors and ends after both actors finish, covering the original work plus
Path/Recovery policy and protected adapter submission. The existing counter's
thread-local semantics were copied into the local `actor-test-allocator`
dev-dependency so the production crate can keep `#![forbid(unsafe_code)]`.
Additional Initial setup evidence and test-thread allocation occur before the
guard; neither existed in the old measured scenario.

The sent payloads use valid PING frames instead of arbitrary non-frame strings
so the production protected-datagram encoder can validate them. Packet numbers
start at Recovery's actual allocated PN 0; delayed generation-0, updated
phase-1, wrapped phase-0, integrity failure, replay/nonce-reuse, old-key expiry,
header-key stability, time-regression, and copied-snapshot assertions remain.
