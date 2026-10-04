Current status: see [ACTIVE-IMPLEMENTATION](../../docs/ACTIVE-IMPLEMENTATION.md). Earlier entries below are chronological and superseded where noted.

# Rolled-route runtime continuation

## Source and scope

- QUIC starting point: `d49769c9d98e2e729262fea4c3505eea35737c92`, the newest published implementation on `recovery/direct-wire-20261003`. The default `main` is a manual workflow bootstrap, not the implementation.
- Requested Hibana branch: `development/rolled-route-ownership`, pinned at `9fbb84cdc932cbd0a81ee995a8689393f322763e`. Its complete tracked tree is vendored without local patches. Runtime sources are unchanged from the prior adea684 import; proof links and regression-test hygiene differ.
- Work branch: `development/rolled-route-runtime`.

The control protocol must be visible as Hibana global `g::send`, `g::route`, `g::par`, and `g::roll` and directly written local `send`, `recv`, and `offer`/resolver operations. No parallel handwritten protocol state machine or wrapper-only migration is acceptable. The existing caller-owned task scheduler and Linux epoll/eventfd reactor are the starting async implementation, not a claim of complete qualification.

## Execution plan

1. Reproduce focused and broad current-source tests on Rust 1.95.0 in the assistant's cloud environment.
2. Audit the readable correspondence between global and local roles, runtime wake/cancellation behavior, and currently failing regressions.
3. For Hibana defects or guarantees outside Hibana, retain Lean AND Z3 models, old-behavior witnesses where applicable, and source-linked regression tests before claiming a fix.
4. Run fresh local interoperability checks if the official Docker runner cannot execute here. Keep each local case's conditions and omissions explicit. After passing the corresponding local gates, execute the official runner in GitHub CI on the exact published SHA.
5. Push source/evidence checkpoints regularly. Do not count skip, unexecuted scenarios, local diagnosis, or stale results as official passes.

## Initial environment

Fresh Linux x86_64, unprivileged UID 1000. Rust 1.95.0, rustfmt and Clippy installed in the writable task workspace. Docker/daemon socket are not present. Approximate available resources at setup: 10 GiB RAM, 30 GiB disk. No claim that Docker topology is runnable here. No host security settings were changed.

Validation is in progress. No fresh interoperability result is claimed in this checkpoint.

## Current-source inspection and fresh checks

The crate retains `#![no_std]` and `#![forbid(unsafe_code)]`. Caller-owned fixed storage and no-heap core futures are requirements; Linux adapters and test fixtures are a separate allocation boundary. Complete lifecycle zero-allocation is still not qualified.

Fresh results: the initial focused run passes application wire 4, connected application 7, and runtime 9 tests. Host library 30, HQ 27, async I/O 11 and waker reentrancy 5 tests pass. Full library execution remains RED: early-owner Finished/retirement returns `recv / PhaseInvariant`; path-owner pending-cancellation overflows the default test stack. Neither assertion nor stack limit was relaxed.

The 23 connection implementation files have been rustfmt-formatted to make the actual global/local operations readable. The Python source-model parser previously treated a legal trailing generic comma as an empty type. Four new parser regressions cover rustfmt output and reject empty non-trailing arguments. Both source models retain exactly 173 events, 306 markers, 4 lanes and zero modeled causality failures. This is not proof of Rust execution.

### Blocking architectural debt: TLS is not yet migrated

`bounded_tls::State`, `expected_level`, `handle_message`, and synchronous `Provider::receive` still implement a handwritten TLS message-order machine. `connection::transcript::Numbers` delegates to it, so the outer choreography is not a complete replacement. Do not claim migration complete. The next architectural change must move hello/retry, full-certificate versus resumed branch, Finished and post-handshake ticket ordering into explicit global and local roles. Preserve stateless parsers, transcript hashing, certificate verification, key derivation, strict encryption-level checks and negative tests. Delete the old dispatch once all callers use those roles; do not merely rename its state or wrap the dispatch.

The installed native Neqo peer is the pinned unmodified revision. Native byte-transfer diagnostics and CI runner qualification remain separate.

## TLS numerical extraction (intermediate, not migration completion)

The per-message transcript/crypto implementations now reside in `bounded_tls/operations.rs`. They do not access the handwritten phase field. Hello operations report the actual retry outcome; certificate, CertificateVerify and Finished operations apply their existing validation and cryptographic effects. The legacy dispatcher still exists and delegates to those operations until the asynchronous choreography is integrated. No claim of removing TLS state control is made at this checkpoint.
