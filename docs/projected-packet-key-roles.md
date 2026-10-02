# Projected packet-key roles

## Implemented boundary

`src/roles/protocol.rs` defines the actual key service. `src/roles/packet_protection.rs` runs two readable local async roles with direct Endpoint operations. The crypto role owns one non-Clone `PacketKey`; callers can request work but cannot submit an authenticated outcome. The initial-key constructor returns owned directional keys that can be moved into independent role facets.

The service is a production foundation, not yet a claim to express all QUIC/TLS reachable states. Packet-number restoration/replay checks, authenticated reserved bits, TLS peer authentication, key-update policy, path/ACK arithmetic, and whole-connection close/drain remain distinct integration obligations.

The global shape is:

- Install → Installed
- rolled request route:
  - Open → (Opened | OpenFailed) → ResultTaken
  - Seal → (Sealed | SealFailed) → ResultTaken
  - HeaderMask → (HeaderMaskReady | HeaderMaskFailed) → ResultTaken
  - Retry-authorized RekeyInitial → (InitialRekeyed | InitialRekeyFailed) → ResultTaken
  - RetireRequested
- Retired → RetirementAcknowledged

The Open success/failure choice originates in the crypto actor after `PacketKey::open`. An `AuthenticationFailed` detail and other crypto/numeric errors are carried in the actor-produced failed result; they do not need another control route. Only `Opened` publishes authenticated plaintext. Initial protection is publicly derivable and does not authenticate peer identity.

`ResultTaken` is the transfer acknowledgment for the one shared result slot: the command role moves the packet/budget out of the arena before sending it, and the key actor waits for it before accepting more work. All RefCell borrows end before an await. Request/reply payloads own fixed copied bytes; no transient packet pointer is retained. `Packet` wipes its array on drop.

## Actual terminality

The vendored `roll` has elastic reentry. A following continuation does not, by itself, seal prior rolled entries against future endpoint operations. An executed exact-source counterexample is preserved under `artifacts/projected-role-control`.

Accordingly, this implementation does not claim graph-only terminal retirement. Receiving `RetireRequested` destroys the real owned key before `Retired` is sent. The command receiver closes admission and drops queued requests. The acknowledgment finishes both local tasks. The external client is consumed by retirement; stale sends fail at the closed mailbox. Dropping/cancelling the aggregate also drops the owned key and clears its request/result arena. There is no added `KeyState` ledger mirroring these async continuations.

Retry rekey derives new Initial keys inside the owning actor and destroys the old key only after derivation and guard transfer succeed. Even re-deriving the same CID preserves the key’s packet-number high-water mark and conservative confidentiality count. The connection owner still validates Retry and retains packet-number-space policy; requesting rekey is not Retry authentication. Other key kinds reject Initial rekey without losing their live key.

An Open moves the connection-wide `IntegrityBudget` into the request and returns that same budget on every cryptographic outcome. If its task or client call is cancelled, the enclosing connection must terminate; it must not replace the lost budget with a fresh one and continue.

## One global session with independent facets

The public concrete fragment is composable, for example:

```rust
let global = g::par(
    key_choreography::<16, 17>(),
    key_choreography::<18, 19>(),
);
```

Project this same global for all four roles. Run `run_borrowed` for each pair, retaining all four endpoint values in the enclosing owner until both services finish. This is important: dropping one owned endpoint can close the shared carrier while another facet remains live. The standalone `run` convenience owns its endpoint pair and is intended for a one-service session.

The test `one_global_par_keeps_other_owned_key_live_when_first_facet_retires` retires one directional key, then successfully seals with the other while the shared carrier remains open.

An endpoint cannot be mutably borrowed by multiple actors. Use distinct role facets within the one choreography for independent tasks. `offer` is projected route preview, not an arbitrary receive-any operation across unrelated parallel service prefixes.

## Numeric state versus protocol control

State that remains necessary includes buffer bounds, descriptor generation/sequence correlation, the actual key's nonce-use/confidentiality counters, and the connection-wide integrity counter. These are data/resource checks. Install/use/result/retirement sequencing belongs to projected endpoint progress and role continuations; there is no second manually polled six-endpoint driver inside this service.

Intrinsic route selection is intentional: the actor that owns the real outcome sends its typed first message, and passive roles consume `offer().await` through `branch.recv`. A synchronous external resolver is appropriate only when its decision is available at the route decision point. It is not an async readiness waiter, and `ResolverError` is a rejection, not Pending.

## Verification

`tests/packet_protection_roles.rs` exercises actual Initial-key AES-GCM, repeated forged packet rejection with the same integrity budget, nonce-reuse rejection across same/changed-CID Retry rekey, real header-mask work, zero-use retirement, queued/post-retirement stale work, cancellation, one-session parallel key facets, fixed packet bounds, and zero allocations on the measured path. Root-crate tests, Clippy with warnings denied, and thumbv6m library compilation are separate checks from interoperability and full-protocol reachability.
