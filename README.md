# hibana-quic

**Unvalidated development snapshot.** See [working status](docs/WORKING-STATUS.md)
for unfinished cleanup, current failures and verification limits.

Bounded QUIC v1/v2 and HTTP/3 in Rust, with protocol control expressed as
[Hibana](https://github.com/hibanaworks/hibana) globals and direct asynchronous locals.
The core is `no_std`, does not allocate, and forbids unsafe Rust. Linux execution
and allocation live in a separate host adapter.

**Latest published commit `593e78d1`: normal CI passed; selected interop 43/44.**
Client handshakeloss is unresolved. The earlier `b8c0d305` baseline passed 44/44.
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
- [Physical IO contracts](src/io/mod.rs), [executor-neutral runtime](src/runtime/mod.rs),
  [Linux effects](host/src/io.rs), [host buffers](host/src/storage.rs)

Applications themselves should be writable as Hibana global/local choreography.
The complete easy-to-embed application API is still in progress; the internal
message carrier is not a network transport. See the architecture's explicit
remaining deliverables rather than treating file moves as API completion.

## Verify

Rust 1.95.0 is pinned. The exact, unpatched Hibana revision is recorded in
[Cargo.toml](Cargo.toml) and checked against Cargo/CI metadata.

```sh
cargo test --locked
cargo check --locked --lib --target thumbv6m-none-eabi
cargo test --locked --manifest-path host/Cargo.toml
cargo test --locked --manifest-path tests/tls-reference/Cargo.toml \
  --all-targets
python3 tools/ci/check_dependencies.py
python3 tools/ci/audit_source.py --check
```

Native loopback tests, selected formal models and the official interop runner
have different scopes. See [qualification](docs/QUALIFICATION.md) for the exact published run and
[working status](docs/WORKING-STATUS.md) for unqualified local changes.

MIT OR Apache-2.0. [Third-party notices](THIRD_PARTY_NOTICES.md).


## Paired TLS development snapshot

This work-in-progress source snapshot uses sibling `hibana-quic/` and
`hibana-tls/` directories. Extract both from the checkpoint ZIP before running
Cargo. QUIC embeds the canonical TLS global from the separate crate; the TLS
locals and production cryptographic handoff are still being migrated.
Before publishing a standalone repository revision, the temporary sibling path
must become an actually published immutable TLS Git dependency and pass a clean
checkout test. No TLS repository URL or revision is fabricated in this snapshot.
