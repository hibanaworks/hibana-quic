# hibana-quic

An experimental, bounded QUIC v1 implementation in Rust, driven by
[Hibana](https://github.com/hibanaworks/hibana) global choreography and explicit
asynchronous local roles.

The core is `no_std`, does not allocate, and forbids unsafe Rust. Callers provide
fixed storage and pinned tasks. The Linux host adapter supplies a real
`epoll`/`eventfd` reactor, UDP I/O and file handling; it is a separate `std` boundary.

## Design criterion

Hibana owns protocol control. Each local writes the corresponding `send`,
`recv`, `offer` and resolver operations directly, with its real processing
between them. Independent progress flags, replacement state machines, and
helpers hiding those protocol exchanges are not the intended architecture.
Numerical kernels, cryptography, parsing and physical I/O remain ordinary Rust.
The migration is not complete merely because a test passes or endpoints appear
in a wrapper; see [the direct-local checkpoint](docs/direct-locals.md).

## Read the implementation

- [Connection choreography](src/connection/protocol.rs): parallel receive,
  publication, timers and retirement, composed with `g::send`, `g::route`,
  `g::par` and `g::roll`.
- [Connection locals](src/connection/locals.rs): the corresponding explicit
  `send`, `recv`, `offer` and resolver operations.
- [TLS choreography](src/bounded_tls/protocol.rs) and
  [TLS locals](src/bounded_tls/locals.rs): full/resumed authentication,
  HelloRetry, certificates and Finished. No synchronous handshake dispatcher.
- [Application roles](src/connection/application): bounded stream transfer,
  packet-key ownership, recovery and close.
- [Application assembly](src/connection/application/assembly): caller-owned role
  futures, their owned results and joins; local protocol exchanges remain direct.
- [Core scheduler](src/runtime.rs) and
  [host reactor](adapters/host/src/async_io.rs): actual wake, backpressure,
  fairness and cancellation behavior.

Cryptographic parsing, counters and storage calculations are numerical
components. Recovery and publication consume distinct affine installation
capabilities tied to the actual key scope. The obsolete mailbox/phase actor
implementation is removed rather than retained as a compatibility path.

**Architecture migration is incomplete.** Source production now spells out
stream opening, rolled data exchange, and a finite FIN/abandon boundary in the
global and direct local code; data slots no longer carry a hidden FIN flag.
A one-shot, scope-borrowing production lease now moves to ingress; ordinary chunks
cannot select a stream, and the lower `send_final` admission field is deleted.
The lower FIN/RESET completion flags and automatic retirement API are deleted.
Delivery now crosses explicit Hibana receipt edges; remaining stream-control work includes real
control obligations, not merely arithmetic and not guarantees supplied by Hibana
alone. Passing interop does not complete this migration.

## Status

This is **not production-ready** and is not yet a fully qualified QUIC stack.
The latest complete CI attempt on `9019c17` reports **43 of 44 candidate cells
passed**, with client `handshakeloss` still failed. All 44 cells ran and all
22 reference controls passed. See
[run 37611115420](https://github.com/hibanaworks/hibana-quic/actions/runs/37611115420).
This is not a passing qualification of all 44 cells. Local fixes and new tests
still require qualification on their exact resulting commit.

See [active implementation and evidence](docs/ACTIVE-IMPLEMENTATION.md).
Lean and Z3 models cover explicitly scoped obligations; they are not proofs of
the complete Rust implementation, cryptography or interoperability.

## Build and test

Rust 1.95.0 is pinned. Hibana is vendored from
`development/rolled-route-ownership` at `b92a1fe4153e6b2404a183c9231245efd58e3237` without local patches.

```sh
cargo test --locked
cargo check --locked --lib --target thumbv6m-none-eabi
cargo test --locked --manifest-path reference-tls/Cargo.toml \
  --test bounded_tls --test rsa_tls --test resumption --test early_tls
cargo test --locked --manifest-path adapters/host/Cargo.toml
python3 vendor/check_hibana.py
python3 ci/audit_source.py --check
```

Host tests and reference TLS peers can allocate; core allocation-sensitive tests
measure only their stated boundaries. Test certificates are public fixtures or
generated ephemerally, never deployment credentials.

## License

MIT OR Apache-2.0. See the license files and [third-party notices](THIRD_PARTY_NOTICES.md).
