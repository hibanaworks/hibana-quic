# hibana-quic

An experimental, bounded QUIC v1 implementation in Rust, driven by
[Hibana](https://github.com/hibanaworks/hibana) global choreography and explicit
asynchronous local roles.

The core is `no_std`, does not allocate, and forbids unsafe Rust. Callers provide
fixed storage and pinned tasks. The Linux host adapter supplies a real
`epoll`/`eventfd` reactor, UDP I/O and file handling; it is a separate `std` boundary.

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
The lower stream table still uses RESET/ACK control fields. Those are real remaining
control obligations, not merely arithmetic and not guarantees supplied by Hibana
alone. Passing interop does not complete this migration.

## Status

This is **not production-ready** and is not yet a fully qualified QUIC stack.
The pinned, unmodified quic-interop-runner passed `handshake`, `transfer`,
`longrtt`, `transferloss`, `transfercorruption` and `ipv6` against unmodified Neqo
in both directions: **12 of 44 candidate cells**, with six separate passing
Neqo/Neqo controls in
[run 37181080895](https://github.com/hibanaworks/hibana-quic/actions/runs/37181080895).
That result applies to commit `1369ffbd7583b3600fe25537986655d1de340db0`.
The subsequent reset-application changes require fresh runner qualification.
The other 32 candidate cells, repeat runs and embedded hardware remain unqualified.

See [active implementation and evidence](docs/ACTIVE-IMPLEMENTATION.md).
Lean and Z3 models cover explicitly scoped obligations; they are not proofs of
the complete Rust implementation, cryptography or interoperability.

## Build and test

Rust 1.95.0 is pinned. Hibana is vendored from
`development/rolled-route-ownership` at `9fbb84c` without local patches.

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
