# hibana-quic

QUIC v1/v2 and HTTP/3 for Rust, using [Hibana](https://github.com/hibanaworks/hibana)
to express protocol order and transfer ownership between roles.
TLS is provided by [hibana-tls](https://github.com/hibanaworks/hibana-tls).

The core is `no_std`, allocation-free, and forbids unsafe Rust. The separate
Host crate supplies Linux UDP, a reactor, entropy and allocated buffers.
This is experimental software; passing interoperability tests does not establish
complete cryptographic security.

## Why Hibana

The protocol order is executable: the same global choreography that explains
who may act next is projected into the programs enforced by the running roles.
QUIC receive, TLS, transmit, UDP publication, timers and retirement are separate
participants in that choreography.

1. **Declare the order.** [QUIC `choreography()`](src/quic/global.rs) composes
   Retry, early data, receive/transmit, timers and Initial-key retirement with
   `seq`, `par`, `route` and `roll`.
2. **Project and attach.** The same file's `programs()` derives each
   `RoleProgram` with `project`. [Role attachment](src/quic/local/attach.rs)
   binds those programs to one session and installs the physical-send resolver.
3. **Execute the localsides.** [The local composition](src/quic/local/mod.rs)
   runs the actual [receive](src/quic/local/receive.rs),
   [transmit](src/quic/local/transmit.rs),
   [publication](src/quic/local/publication.rs) and
   [timer](src/quic/local/timer.rs) continuations. Their `send`, `recv` and
   `offer` operations must follow the projected programs.
4. **Move resources with the protocol.**
   [Application admission](src/quic/application/local/ownership.rs) moves the
   transmit continuation, authenticated Finished receipt and transcript through
   owned slots. It checks their connection scope before admitting application
   traffic. A message label alone is not a substitute for those resources.

### What is enforced

At each attached endpoint, Hibana checks the permitted operation, peer,
direction, lane, label and schema before committing progress. A successful
operation advances once; rejected or uncommitted operations do not grant a
second transition. Affine endpoint ownership prevents cloning an endpoint to
publish the same progress twice. These are runtime protocol checks combined
with Rust ownership, not a claim that every invalid program fails to compile.

Rust moves and scoped borrows separately enforce resource ownership. For example,
[stream reclamation](src/quic/application/local/reclaim.rs) joins source, input
and delivery receipts for the same identity before releasing storage;
[key ownership](src/quic/application/local/keys.rs) separates receive-side
control from transmit-side sealing authority.

Hibana does not prove the QUIC algorithms, certificate validation, cryptographic
arithmetic, constant-time execution or network reliability. Progress also depends
on a live carrier and fair scheduling. Cancellation must settle or quarantine
accepted native I/O. A submitted datagram is not evidence of peer delivery.

### How the remaining obligations are checked

- **Lean:** abstract invariants for [body ownership and EOF](proofs/owned-body-input/Body.lean),
  [stream-slot binding](proofs/stream-slot-binding/Binding.lean),
  [cancellation](proofs/tls-input-cancellation/Cancellation.lean) and
  [reclamation](proofs/stream-reclaim/Reclaim.lean).
- **Z3:** counterexample searches over the corresponding constraints, including
  [body completion](proofs/owned-body-input/check_body.py) and
  [resource identity and drain conditions](proofs/stream-reclaim/reclaim.py).
  Unsatisfiability establishes the encoded property under its model assumptions.
- **Miri:** the TLS secret-memory boundary tests execute under Rust's interpreter
  to check the exercised unsafe memory operations and aliasing obligations. The
  source and tests live in `hibana-tls/src/secret.rs` and `src/secret/memory.rs`.
- **Rust and interoperability tests:** actual endpoint execution, cancellation,
  loss/corruption and transfer tests connect those models to concrete behavior;
  Neqo/quiche peers check wire interoperability.

The Lean/Z3 models are not an extraction or end-to-end proof of the Rust code.
Miri checks the executions it runs; it does not prove cryptographic strength or
constant-time machine code. See [Hibana's guarantee boundary](https://github.com/hibanaworks/hibana/blob/6fccdbf81038b00d99ec1bb2b9c43a487521628e/README.md#guarantees)
for the underlying runtime and carrier assumptions.

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
arithmetic.

## Build

```sh
cargo check --locked --lib
cargo test --locked
cargo check --locked --lib --target thumbv6m-none-eabi
```

For development tests that use the sibling TLS sources, place `hibana-tls/`
next to `hibana-quic/` at the revision pinned in Cargo.toml.

Licensed under MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.
