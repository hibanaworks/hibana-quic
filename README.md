# hibana-quic

QUIC v1/v2 and HTTP/3 for Rust, using [Hibana](https://github.com/hibanaworks/hibana)
to express protocol order and transfer ownership between roles.
TLS is provided by [hibana-tls](https://github.com/hibanaworks/hibana-tls).

The core is `no_std`, allocation-free, and forbids unsafe Rust. The separate
Host crate supplies Linux UDP, a reactor, entropy and allocated buffers.
This is experimental software; passing interoperability tests does not establish
complete cryptographic security.

## Try a real transfer

You need Linux, Rust 1.95, and a server certificate/key with `DNS:localhost` and
its trusted CA certificate. From the repository root:

```sh
./examples/http3-transfer.sh chain.pem key.pem ca.pem
```

The example builds the client/server, transfers `hello.txt` over HTTP/3, waits
for both processes and compares the file contents. Logs and output are kept in
the temporary directory printed on success. Port 4433 must be free.
It never disables certificate or hostname verification.

For separate terminals and CLI options, see [Host usage](host/README.md).

## Write an application

Start with [a response handler and borrowed body](examples/response_body.rs):

```sh
cargo run --locked --example response_body
```

This small example exercises the application effects without a network. The
HTTP/3 example above exercises the actual network client/server.


- [Host application client/server](host/src/application/local/mod.rs) connect
  caller-owned request, response-body and receive-sink implementations to the
  actual QUIC application choreography.
- [Application effects](src/quic/application/mod.rs) define `ClientRequests`,
  `StreamSink`, `ServerHandler` and `BodyReader`.
- [Core I/O contracts](src/io/mod.rs) permit other operating systems and bare-metal
  adapters. Host Linux support is not a core requirement.

The current application profile is bounded request/response transfer. A general
bidirectional HTTP/3 application framework is not yet available. The in-process
Hibana carrier is not a QUIC network transport for arbitrary application globals.

## Find the protocol and its implementation

Every protocol directory puts ordering first, execution second, and computation
below `imp/`:

| Protocol | Order | Execution | Implementation |
|---|---|---|---|
| QUIC handshake | [global.rs](src/quic/global.rs) | [local/](src/quic/local/mod.rs) | [imp/](src/quic/imp/mod.rs) |
| Application | [global.rs](src/quic/application/global.rs) | [local/](src/quic/application/local/mod.rs) | [imp/](src/quic/application/imp/mod.rs) |
| Early data | [global.rs](src/quic/early_data/global.rs) | [local/](src/quic/early_data/local/mod.rs) | [imp/](src/quic/early_data/imp/mod.rs) |
| ECN | [global.rs](src/quic/ecn/global.rs) | [local/](src/quic/ecn/local/mod.rs) | [imp/](src/quic/ecn/imp/mod.rs) |
| Path validation | [global.rs](src/quic/path/global.rs) | [local/](src/quic/path/local/mod.rs) | [imp/](src/quic/path/imp/mod.rs) |
| Retry client | [global/client.rs](src/quic/retry/global/client.rs) | [local/](src/quic/retry/local/mod.rs) | [imp/](src/quic/retry/imp/mod.rs) |

Server Retry admission uses the same core [global](src/quic/retry/global.rs)
with the [Host input/owner/output locals](host/src/retry/local/mod.rs).

`local/mod.rs` contains the composition or direct role entry. The role files
contain the actual endpoint operations; `imp/` contains buffers, codecs and
arithmetic. Use these canonical module paths directly. Legacy module aliases are removed.

## Build

```sh
cargo check --locked --lib
cargo test --locked
cargo check --locked --lib --target thumbv6m-none-eabi
```

For development tests that use the sibling TLS sources, place `hibana-tls/`
next to `hibana-quic/` at the revision pinned in Cargo.toml.

Licensed under MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.
