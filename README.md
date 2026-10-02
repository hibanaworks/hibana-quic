# hibana-quic (implementation in progress)

A standard QUIC v1 implementation using Hibana internally. No existing QUIC
transport engine is a product dependency. **Not a complete QUIC endpoint or
release candidate.** HTTP/3 and QUIC v2 are outside the requested acceptance set.

## Async architecture checkpoint (2026-10-02)

Initial protection now runs in actual projected async key roles using direct
`send`, `recv`, and `offer` awaits, composed with `g::par` and rolled request
routes. The Linux host drives one epoll/eventfd reactor for UDP and deadlines.
The runtime and mailboxes use fixed caller-owned task/buffer storage.

This is a **partial migration**: non-Initial TLS/control paths still use the
legacy synchronous Driver in a separate session. Whole-connection choreography,
all legacy synchronous test fixtures, and embedded deployment remain unfinished.
The frozen historical interoperability checkpoint `7a58d80` passed four distinct
handshake/transfer cells in three runs; those results do not qualify this source.

Focused checks for this checkpoint:

```sh
cargo test --locked --lib --test runtime_async --test mailbox_async --test packet_protection_roles --test async_initial_endpoint
cargo test --locked --manifest-path reference-tls/Cargo.toml --test async_bounded_wire
cargo test --locked --manifest-path adapters/host/Cargo.toml --bin hq
cargo build --locked --release --manifest-path adapters/host/Cargo.toml --bin hq
python3 ci/audit_source.py --check
```

Older aggregate test commands below describe the full target, not a current
all-target pass: synchronous endpoint fixtures still need async migration.
Pico fitting is deferred while interoperability is prioritized.

## Working now

- Bounded v1 packet/frame codecs, all base frame shapes, PN restoration and
  malformed-input limits
- RustCrypto packet protection, real RFC 9001 Appendix A vectors, nonce/key-use
  limits, header protection and Retry integrity
- Caller-owned lease storage, PN/sent history and anti-amplification reservations,
  flow/final-size kernels, CRYPTO reassembly and transport-parameter validation
- Actual bounded local Hibana carrier and independently repeating raw `g::par`
  services, including real key installation/use/retirement, authenticated receive,
  validated ACK release, stream delivery and stream retirement authorities
- Bounded authenticated TLS 1.3 client/server with P-256 and RSA certificate verification,
  AES-128-GCM/ChaCha20-Poly1305, HRR, Finished and explicit unsupported-feature errors
- Real encrypted QUIC handshake, CRYPTO retransmission, RTT/PTO/loss detection,
  NewReno accounting, key-space retirement and bounded STREAM/control ownership
- HTTP/0.9 file transfer with caller-owned buffers, backpressure and stream reuse;
  direct Neqo development transfers in both directions with certificate verification
- Standalone Lean/Z3 accounting models and a proof-gated minimal Hibana core fix

The release remains incomplete. Retry, 1-RTT resumption, ECN and explicit encrypted
close/drain have development evidence. 0-RTT, migration, automatic error-to-close
mapping and complete recovery policy remain under development. Idle timeout and
v1-only Version Negotiation now have encrypted endpoint and negative-test evidence.
Application key updates and enlarged certificate chains have real endpoint
coverage. Direct Neqo key-update transfers verify exact 5MiB content and an
authenticated new receive generation in both roles. Direct UDP evidence
is recorded separately from the required container-runner matrix.

## Verification

Rust 1.95 or newer. The Hibana source is vendored without local patches from the user-selected
`development/dots-causality` head `3aef31ba015c75ea824b8b41f5603b03f5dd336b`.
`vendor/hibana-provenance.json` and Cargo package metadata pin that exact source.
The earlier proof-gated local correction is now incorporated upstream; its
history remains in `artifacts/hibana-offer-repro/` and `artifacts/upstream-history/`.
See `vendor/README.md` for scope.

```sh
cargo test --locked
cargo clippy --locked --lib --tests -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo test --locked --manifest-path reference-tls/Cargo.toml
rustup target add thumbv6m-none-eabi
bash scripts/check_no_alloc.sh
lean proofs/lean/Accounting.lean
python3 proofs/z3/accounting.py  # requires z3-solver
```

`check_no_alloc.sh` counts allocations for implemented component paths including
both AEAD suites and the real Hibana runtime, then links an allocation-free
thumbv6m component smoke image. **It does not run a full bounded TLS handshake,
produce bootable Pico firmware, or establish complete board memory/stack usage.**
The separate `adapters/host` bounded-wire and bounded-streams tests measure an
actual authenticated TLS/QUIC/Hibana handshake and 5MiB transfer, corruption/PTO,
rejected-send recovery, key updates, stream retirement and runtime/provider drops.
Both successful transfer and terminal wrong-CA paths record zero allocations.
Fixture PKI construction and caller-buffer setup are outside the measured interval.
A separate bounded-wire counter now covers explicit CONNECTION_CLOSE/draining;
provider resumption has allocation tests and actual direct Neqo resumption has
separate evidence. Full lifecycle/resumption/early-data allocation closure remains
an open release gate.
The `reference-tls` Rustls backend intentionally allocates and is excluded from
bounded-backend allocation assertions.

`interop/targets.json` reconstructs the supplied PLAN's 20 cases and both
directions; the separate manifest mentioned in the handoff was not supplied.
The results validator checks the pinned runner's exact schema, with no skip,
unsupported, missing, or failure-to-success conversion. It is not evidence that
any interop case has run. Current complete gate statuses are in
`artifacts/acceptance-status.json`.

## Remaining release gates

1. Remaining TLS/transport features, including complete early-data integration
2. Full QUIC recovery, stream, lifecycle, path and host harness integration
3. Neqo 20-case × both-direction matrix, three complete recorded attempts,
   independently verified result JSON/file content/required pcap assertions
4. Full QUIC/TLS no-allocation closure, allocation counter and target link
5. Actual Pico board/driver/entropy and HIL, RAM/stack/flash/time measurements
6. Required negative tests, proof audit, dependency/license audit

See `docs/assumptions.md`, `docs/tls-decision.md`,
`proofs/ACCOUNTING-MODEL.md`, `THIRD_PARTY_NOTICES.md`, and `reference-tls/README.md`. The included Hibana core correction was made only after both Lean and Z3 gates
executed successfully. These scoped models are not a complete Rust refinement proof.
