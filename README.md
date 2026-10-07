# hibana-quic

Bounded QUIC v1/v2 and HTTP/3 in Rust, with protocol control expressed as
[Hibana](https://github.com/hibanaworks/hibana) globals and direct asynchronous locals.
The core is `no_std`, does not allocate, and forbids unsafe Rust. Linux execution
and allocation live in a separate host adapter.

**Selected interop matrix: 44/44, controls 22/22 on `b8c0d305`.**
[Exact qualification and limits](docs/QUALIFICATION.md). Later restructuring is
not qualified merely because that baseline passed. This is experimental software.

## Start here

- [Run a real HTTP/3 transfer](docs/GETTING-STARTED.md)
- [Understand the globals, locals and module layout](docs/ARCHITECTURE.md)
- [What Hibana, Rust and formal models actually guarantee](docs/GUARANTEES.md)
- [Current implementation and remaining application API work](docs/ACTIVE-IMPLEMENTATION.md)

## Code map

- [QUIC global](src/quic/global.rs) → [direct locals](src/quic/local/mod.rs)
- [TLS global](src/tls/handshake/global.rs) → [direct locals](src/tls/handshake/local.rs)
- [Application global](src/quic/application/global.rs) → [role implementation](src/quic/application)
- [HTTP/3 global](src/http3/global.rs) and [wire codecs](src/http3/wire.rs)
- [Physical IO contracts](src/io.rs), [executor-neutral runtime](src/runtime.rs),
  [Linux effects](adapters/host/src/io.rs), [host buffers](adapters/host/src/storage.rs)

Applications themselves should be writable as Hibana global/local choreography.
The complete easy-to-embed application API is still in progress; the internal
message carrier is not a network transport. See the architecture's explicit
remaining deliverables rather than treating file moves as API completion.

## Verify

Rust 1.95.0 and exact, unpatched Hibana `b92a1fe4` are pinned.

```sh
cargo test --locked
cargo check --locked --lib --target thumbv6m-none-eabi
cargo test --locked --manifest-path adapters/host/Cargo.toml
cargo test --locked --manifest-path reference-tls/Cargo.toml \
  --test bounded_tls --test rsa_tls --test resumption --test early_tls
python3 vendor/check_hibana.py
python3 ci/audit_source.py --check
```

Native loopback tests, selected formal models and the official interop runner
have different scopes. Earlier reconstruction and cumulative results are retained
under [history](docs/history/qualification-through-c586.md).

MIT OR Apache-2.0. [Third-party notices](THIRD_PARTY_NOTICES.md).
