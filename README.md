# hibana-quic

QUIC v1/v2 and HTTP/3 in Rust, with protocol order and resource handoff expressed
by [Hibana](https://github.com/hibanaworks/hibana) globals and direct async locals.
The core is `no_std`, allocation-free and forbids unsafe Rust. Host allocation
and OS effects live in the separate `hibana-quic-host` crate.

Experimental software: test coverage is not a complete cryptographic proof.
The latest verified baseline is **5c58cec**: official Neqo/quiche interoperability
**44/44 twice**, plus runtime, Host, embedded, Clippy and Miri CI. Current local
reorganization must pass its own checks before inheriting any qualification.
See [verification and limits](docs/QUALIFICATION.md).

## Read the Hibana program first

- QUIC handshake: [global](src/quic/global.rs) → [local composition](src/quic/local/mod.rs) → [receive](src/quic/local/receive.rs), [transmit](src/quic/local/transmit.rs), [publication](src/quic/local/publication.rs).
- Connected QUIC application: [global](src/quic/application/global.rs) → [local composition](src/quic/application/local/mod.rs) → [affine handoff](src/quic/application/local/ownership.rs), [source/ingress/sink](src/quic/application/local/io.rs), [three-way reclaim](src/quic/application/local/reclaim.rs).
- TLS message ordering: [canonical TLS global](https://github.com/hibanaworks/hibana-tls/blob/99e933efbcb7d164b7f6aa9fc598f240a3772661/src/handshake/global.rs) → [direct TLS locals](https://github.com/hibanaworks/hibana-tls/blob/99e933efbcb7d164b7f6aa9fc598f240a3772661/src/handshake/local.rs).

The first two local entry files contain the actual composed operations and joins,
not a forwarding controller. Follow `send`, `recv`, and `offer` into their role
files. Stream buffers, flow/retransmission arithmetic and receipt bookkeeping
live below [stream/imp](src/quic/stream/imp/mod.rs); packet encoding
and numeric kernels remain below [kernel](src/quic/kernel/mod.rs). The old
`quic::application_stream` import is a direct re-export, not another implementation.

## Choose your starting point

- **Run HTTP/3 now:** [build and run the client/server CLI](docs/GETTING-STARTED.md).
- **Build an application:** [available APIs and the application design](docs/APPLICATION-API.md).
  The complete ergonomic Hibana-over-network application API is still unfinished.
- **Read the implementation:** [global → local → mechanism map](docs/ARCHITECTURE.md).
- **Review safety:** [guarantees](docs/GUARANTEES.md) and
  [TLS validation](https://github.com/hibanaworks/hibana-tls/blob/99e933efbcb7d164b7f6aa9fc598f240a3772661/SECURITY-VALIDATION.md).
- **Contribute:** [current work](docs/WORKING-STATUS.md), [CI requirements](CI-REQUIRED.md).

## Crates and ownership

| Crate | Responsibility |
|---|---|
| `hibana` | Global projection, endpoint progression and affine communication authority |
| `hibana-tls` | QUIC-specific TLS, canonical TLS locals, keys and Finished material |
| `hibana-quic` | QUIC/HTTP/3 globals and locals, bounded transport mechanisms, executor-neutral I/O |
| `hibana-quic-host` | OS I/O, bounded buffer allocation, file-service effects and the `hq` CLI |

QUIC depends on the immutable owned Hibana/TLS revisions in `Cargo.toml`.
Third-party reference implementations are confined to the separate test workspace
and interop tools. They are not production TLS dependencies.

A `global.rs` defines legal order; its locals contain the actual `send`, `recv`,
`offer` and joins. Numerical code cannot advance that order. Startup supplies
storage and endpoints rather than running another connection state machine.
The internal `runtime::carrier` is not a network transport for applications.

## Build and verify

Rust 1.95.0 is pinned. For paired development/ZIPs, keep `hibana-quic/` and the
pinned `hibana-tls/` checkout adjacent; see [CI instructions](CI-REQUIRED.md).

```sh
cargo test --locked
cargo check --locked --lib --target thumbv6m-none-eabi
cargo test --locked --manifest-path host/Cargo.toml
cargo test --locked --manifest-path tests/tls-reference/Cargo.toml --all-targets
python3 tools/ci/check_dependencies.py
python3 tools/ci/audit_source.py --check
```

For official interop, run all 22 cases in both directions on the same commit and
attempt, and inspect `qualification`; selected passing jobs are insufficient.

MIT OR Apache-2.0. [Third-party notices](THIRD_PARTY_NOTICES.md).
