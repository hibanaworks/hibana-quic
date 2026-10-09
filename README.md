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

## Write an application with Hibana

**Client and server project the same application global.** The library connects
those projected endpoints over authenticated QUIC streams or HTTP/3 exchanges.
Application locals use Hibana `send` and `recv`; they do not implement a carrier,
manage frame queues, encode HTTP/3 envelopes, or drive transport phases.

The two examples calculate a square across a real network connection:

- [Raw QUIC application](examples/hello-quic/global.rs), using ALPN `hibana/1`.
- [HTTP/3 application](examples/hello-http3/global.rs), using authenticated
  HTTP/3 POST request/response bodies on `/hibana`.

Each has one `global.rs`, `local/client.rs`, `local/server.rs`, and small native
`client.rs` / `server.rs` launchers. The HTTP/3 and raw examples have identical
application conversations; the launcher's `session::Protocol` selects the carrier.

### Shared global

```rust
use hibana::g;
pub const CLIENT: u8 = 0;
pub const SERVER: u8 = 1;
pub type Number = g::Msg<0, u64>;
pub type Square = g::Msg<1, u64>;
pub type Exchange = g::Seq<g::Send<CLIENT, SERVER, Number>, g::Send<SERVER, CLIENT, Square>>;
pub type Conversation = g::Seq<Exchange, Exchange>;
pub fn choreography() -> g::Program<Conversation> {
    g::seq(
        g::seq(
            g::send::<CLIENT, SERVER, Number>(),
            g::send::<SERVER, CLIENT, Square>(),
        ),
        g::seq(
            g::send::<CLIENT, SERVER, Number>(),
            g::send::<SERVER, CLIENT, Square>(),
        ),
    )
}
```

### Client localside

```rust
use crate::global::*;
use hibana::Endpoint;
#[derive(Debug)]
pub enum Error {
    Protocol(hibana::EndpointError),
    IncorrectSquare,
}
pub async fn run(client: &mut Endpoint<'_, CLIENT>) -> Result<(), Error> {
    for number in [42_u64, 7] {
        client
            .send::<Number>(&number)
            .await
            .map_err(Error::Protocol)?;
        let square = client.recv::<Square>().await.map_err(Error::Protocol)?;
        if square != number * number {
            return Err(Error::IncorrectSquare);
        }
    }
    Ok(())
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "{error:?}"),
            Self::IncorrectSquare => f.write_str("incorrect square"),
        }
    }
}
impl core::error::Error for Error {}
```

### Server localside

```rust
use crate::global::*;
use hibana::Endpoint;
#[derive(Debug)]
pub enum Error {
    Protocol(hibana::EndpointError),
    Overflow,
}
pub async fn run(server: &mut Endpoint<'_, SERVER>) -> Result<(), Error> {
    for _ in 0..2 {
        let number = server.recv::<Number>().await.map_err(Error::Protocol)?;
        let square = number.checked_mul(number).ok_or(Error::Overflow)?;
        server
            .send::<Square>(&square)
            .await
            .map_err(Error::Protocol)?;
    }
    Ok(())
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "{error:?}"),
            Self::Overflow => f.write_str("square overflow"),
        }
    }
}
impl core::error::Error for Error {}
```

The client launcher projects `CLIENT`; the server launcher projects `SERVER`
from that same global. `session::client` and `session::server` own the carrier,
TLS connection, native reactor, bounded buffers and teardown. They join the
application local with the real network driver, without an application-side
phase flag or replacement state machine.

### Raw QUIC client launcher

[Complete executable](examples/hello-quic/client.rs); `global` and `local` refer to the files above.

```rust
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: client REMOTE CA.pem (DNS:localhost)".into());
    }
    let config = session::Client {
        remote: args[0].parse().map_err(|e| format!("{e}"))?,
        server_name: "localhost".into(),
        ca: args[1].clone().into(),
        protocol: session::Protocol::Quic,
        timeout: Duration::from_secs(30),
    };
    session::client(
        config,
        global::SERVER,
        &project::<{ global::CLIENT }, _>(&global::choreography()),
        local::run,
    )?;
    println!("42 squared = 1764\n7 squared = 49");
    Ok(())
}
```

### Raw QUIC server launcher

[Complete executable](examples/hello-quic/server.rs); `global` and `local` refer to the files above.

```rust
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: server LISTEN CERT.pem KEY.pem".into());
    }
    let config = session::Server {
        listen: args[0].parse().map_err(|e| format!("{e}"))?,
        certificate: args[1].clone().into(),
        key: args[2].clone().into(),
        protocol: session::Protocol::Quic,
        timeout: Duration::from_secs(30),
    };
    session::server(
        config,
        global::CLIENT,
        &project::<{ global::SERVER }, _>(&global::choreography()),
        local::run,
    )
}
```

### HTTP/3 client launcher

[Complete executable](examples/hello-http3/client.rs); `global` and `local` refer to the files above.

```rust
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: client REMOTE CA.pem (DNS:localhost)".into());
    }
    let config = session::Client {
        remote: args[0].parse().map_err(|e| format!("{e}"))?,
        server_name: "localhost".into(),
        ca: args[1].clone().into(),
        protocol: session::Protocol::Http3,
        timeout: Duration::from_secs(30),
    };
    session::client(
        config,
        global::SERVER,
        &project::<{ global::CLIENT }, _>(&global::choreography()),
        local::run,
    )?;
    println!("42 squared = 1764\n7 squared = 49");
    Ok(())
}
```

### HTTP/3 server launcher

[Complete executable](examples/hello-http3/server.rs); `global` and `local` refer to the files above.

```rust
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: server LISTEN CERT.pem KEY.pem".into());
    }
    let config = session::Server {
        listen: args[0].parse().map_err(|e| format!("{e}"))?,
        certificate: args[1].clone().into(),
        key: args[2].clone().into(),
        protocol: session::Protocol::Http3,
        timeout: Duration::from_secs(30),
    };
    session::server(
        config,
        global::CLIENT,
        &project::<{ global::SERVER }, _>(&global::choreography()),
        local::run,
    )
}
```

### Run both sides

The Host implementation requires Linux and Rust 1.95. Supply a development
certificate chain/key for `DNS:localhost` and its CA. Verification stays enabled;
do not use production keys for a demonstration.

```sh
cargo build --locked --release --manifest-path host/Cargo.toml --examples
```

Raw QUIC, in separate terminals:

```sh
host/target/release/examples/quic-server 127.0.0.1:4433 chain.pem key.pem
host/target/release/examples/quic-client 127.0.0.1:4433 ca.pem
```

HTTP/3, in separate terminals:

```sh
host/target/release/examples/http3-server 127.0.0.1:4433 chain.pem key.pem
host/target/release/examples/http3-client 127.0.0.1:4433 ca.pem
```

Or verify both exchanges automatically:

```sh
python3 examples/check-transfers.py host/target/release/examples chain.pem key.pem ca.pem
```

With `CARGO_TARGET_DIR`, use that directory's `release/examples/` instead.
The client checks `42 squared = 1764` and `7 squared = 49` on the same stream;
both launchers require normal transport
close and native resource retirement. A 30-second deadline bounds each example.

### Carrier scope and guarantees

The session API attaches two projected roles to one ordered bidirectional
stream. Multiple Hibana messages share that stream; message boundaries do not
open new QUIC streams or new HTTP requests. The projected endpoint owns the
application's send/receive order. The transport preserves session, lane, source,
destination and label, and checks the configured peer before admitting a frame.
Each message has at most 256 payload bytes and the queue holds four frames.

Raw QUIC uses ALPN `hibana/1`. The HTTP/3 profile opens one streaming POST on
`/hibana`; its request and 200 response bodies carry the two message directions.
This profile is a two-role application channel, not a general web router or
multiparty connection manager.

The shared attachment and stream effects live in the `no_std` core, using
caller-owned storage and ordinary Rust futures. Native UDP sockets, file-based
certificate loading and the reactor live in Host. Bare-metal integrations supply
packet I/O, clock, entropy, connection storage and their executor through the
core contracts. They can reuse the application global and localsides; the core
does not supply a board-specific network driver.

Endpoint send completion means the bounded carrier accepted ownership; it does
not mean the remote application consumed the value. The response in the shared
global provides application-level causality. The session launcher separately
waits for actual QUIC termination and resource retirement. Failure cancels the
joined futures and their owned resources rather than inventing a reply.

Hibana validates local operations against the projected program. Network peers
are still untrusted inputs, and matching message labels do not establish that a
peer runs the same source code. TLS, strict frame parsing and the receiver's
projected endpoint enforce their respective boundaries.

- [Network session entry points](host/src/session/mod.rs) own native resources.
- [Network session execution](host/src/session/local/mod.rs) joins a caller's
  localside with the QUIC/HTTP/3 driver.
- [OS-independent role attachment](src/session/local/mod.rs) joins the localside
  and its stream driver.
- [Stream effects](src/session/local/stream.rs) and [framing](src/session/imp/wire.rs)
  remain below the application interface.
- [Core I/O contracts](src/io/mod.rs) support OS and bare-metal adapters.
- [CLI file transfer](host/README.md) and its
  [single-command script](examples/http3-transfer.sh) are additional examples.

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
