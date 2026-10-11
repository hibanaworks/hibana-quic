# hibana-quic

QUIC v1/v2 and HTTP/3 for Rust, using [Hibana](https://github.com/hibanaworks/hibana)
to express protocol order and transfer ownership between roles.
TLS is provided by [hibana-tls](https://github.com/hibanaworks/hibana-tls).

The library is `no_std`, forbids unsafe Rust, and does not link the `alloc` crate.
Connection entry points borrow their stream slots and runtime arenas from the caller.
TLS, routing and protocol futures use bounded storage. [hibana-quic-pal](pal/) supplies Linux/macOS UDP,
readiness, clocks, entropy and file access; it contains no protocol choreography.
This is experimental software; passing interoperability tests does not establish
complete cryptographic security.

## Why Hibana

The protocol order is executable: the same global choreography that explains
who may act next is projected into the per-role programs enforced by the running endpoints.
QUIC receive, TLS, transmit, UDP publication, timers and retirement are separate
participants in that choreography.

1. **Declare the order.** [QUIC `choreography()`](src/quic/global.rs) composes
   Retry, early data, receive/transmit, timers and Initial-key retirement with
   `seq`, `par`, `route` and `roll`.
2. **Project and attach.** [`localside::Endpoints::attach`](src/quic/localside/mod.rs)
   takes that global directly, derives each `RoleProgram` with `project`,
   and enters the session to obtain each affine `Endpoint`. It also installs the
   physical-send resolver. There is no separate connection-program bundle.
3. **Execute the localsides.** [The local composition](src/quic/localside/run.rs)
   runs the actual [receive](src/quic/localside/receive.rs),
   [transmit](src/quic/localside/transmit.rs),
   [publication](src/quic/localside/publication.rs) and
   [timer](src/quic/localside/timer.rs) continuations. Their `send`, `recv` and
   `offer` operations must follow the role projections.
   [Handshake packet storage and decoding](src/quic/imp/handshake_wire.rs)
   perform authentication and CRYPTO reassembly without advancing endpoints.
4. **Move resources with the protocol.**
   [Application admission](src/quic/application/localside/ownership.rs) moves the
   transmit continuation, authenticated Finished receipt and transcript through
   owned slots. It checks their connection scope before admitting application
   traffic. A message label alone is not a substitute for those resources.

### Where are the running roles?

A role identifier names a participant in the global. A projected `RoleProgram`
describes its permitted operations. An `Endpoint` is that participant's affine,
attached protocol capability. The actual computation is an async localside that
owns or exclusively borrows endpoints and resources. A role identifier is not a
thread, and an endpoint does not spawn or poll its localside.

For a complete connection, follow these concrete definitions:

- [Application global](src/quic/application/global.rs): role identifiers,
  choreography and role projections, including the TLS/QUIC prefix.
- [Application locals](src/quic/application/localside/mod.rs): `Endpoints`, the
  endpoint-to-consumer inventory, and `Endpoints::attach` in the same file.
- [Application execution](src/quic/application/localside/run.rs): construction of
  each receive, source, sink, key, timer, publication and retirement future;
  the `TaskSet` listing those futures is the actual concurrent execution set.
- [Caller-owned session](src/quic/application/localside/borrowed.rs): session storage,
  program projection, endpoint attachment and the call into that execution.
- [Handshake locals](src/quic/localside/mod.rs) and
  [their execution](src/quic/localside/run.rs): the same ownership/attachment and
  execution split for the authenticated prefix.

Some localsides hold several endpoints; for example, application receive holds
`receive`, `rx_keys` and `peer_event`. Startup and retirement also borrow these
endpoints in the order required by the global. Their fields document the
consumers rather than pretending there is one task for every endpoint.

[`runtime::TaskSet`](src/runtime/mod.rs) polls the composed local futures; it does
not choose QUIC/TLS protocol transitions. On native systems, the PAL
[`Reactor::block_on`](pal/src/unix/reactor.rs) supplies polling and I/O wakeups.
The command-line examples use std for arguments and diagnostics; positional file access is supplied by PAL. Their application endpoints and connection storage follow the same allocator-free library API. With caller-owned storage, another executor can poll the same connection future.
For an application defined with its own global, [session execution](src/session/localside/mod.rs)
attaches its projected endpoint and joins its application localside with the
network localside. The [raw QUIC example](examples/hello-quic/client.rs) passes
its projected program and an inferred async application localside directly into that entrypoint.

### Public entrypoints and implementation storage

Application code starts with `session`, a shared application global and its
client/server localsides, as shown in the examples below. Endpoint projection
and application execution use the same types on native and caller-owned paths.

For a custom connection, `quic::application::{Buffers, Setup}` supplies storage
and parameters. Use `quic::application::localside::Endpoints` for attachment,
`Buffers` and `Setup` for caller-owned resources, and the corresponding localside
to run them. Caller-owned stream arrays and arenas are grouped by `session::ConnectionMemory`;
`session::Memory` additionally owns the application carrier arena.
Packet codecs (`quic::packet`), transport parameters (`quic::transport_parameters`),
recovery receipts (`quic::recovery`) and publication capabilities
(`quic::publication`) are the low-level public interfaces used by diagnostic tools.
Their definitions remain with the implementation components under `imp/`; the
`imp` module itself is private. Public exports name the actual types and functions,
without a second wrapper or an alternate protocol owner.

### Follow each protocol group

Each protocol group has a `global` for permitted communication, a `localside/` for
actual endpoint-owning execution, and `imp` for byte storage and computation.
An embedded group reuses endpoints from the containing connection; it does not
create a duplicate session or a second controller.

- **QUIC handshake and connected application:** their `localside/mod.rs` defines
  and attaches the endpoint set; `localside/run.rs` assembles the actual futures.
- **Retry admission:** [global](src/quic/retry/global.rs) →
  [server locals](src/quic/retry/localside/server.rs). `receive` attaches INPUT,
  OWNER and OUTPUT and joins incoming, admission and outgoing operations.
- **ECN:** [global](src/quic/ecn/global.rs) → [owner local](src/quic/ecn/localside/mod.rs).
  Its owner and the publication local share the complete connection projection.
- **Path validation:** [global](src/quic/path/global.rs) →
  [owner local](src/quic/path/localside/mod.rs); address and probe observations are
  separate [implementation data](src/quic/path/imp/observations.rs).
- **Early data:** [global](src/quic/early_data/global.rs) →
  [quarantine owner](src/quic/early_data/localside/mod.rs), composed with the
  [connected early locals](src/quic/application/localside/early.rs).
- **HTTP/3 control:** [global](src/http3/global.rs) →
  [actual control owner](src/http3/localside/mod.rs). The connection's source and sink
  share that choreography. [Codecs and retained bytes](src/http3/imp/mod.rs) do
  not select the next endpoint operation.
- **HTTP/3 message exchange:** [global](src/http3/message/global.rs) →
  [reader/writer locals](src/http3/message/localside/mod.rs) →
  [attachment and join](src/http3/message/localside/run.rs).
- **User application:** [shared example global](examples/hello-quic/global.rs) →
  [client](examples/hello-quic/client.rs) or
  [server](examples/hello-quic/server.rs) →
  [session attachment](src/session/localside/mod.rs). The HTTP/3 example uses the
  same application-level structure.

The scheduler and PAL supply polling, wakeups and physical I/O. The above globals
and endpoint operations enforce protocol progress. The concrete checks and their
limits follow below.

### What is enforced

At each attached endpoint, Hibana checks the permitted operation, peer,
direction, lane, label and schema before committing progress. A successful
operation advances once; rejected or uncommitted operations do not grant a
second transition. Affine endpoint ownership prevents cloning an endpoint to
publish the same progress twice. These are runtime protocol checks combined
with Rust ownership, not a claim that every invalid program fails to compile.

Rust moves and scoped borrows separately enforce resource ownership. For example,
[stream reclamation](src/quic/application/localside/reclaim.rs) joins source, input
and delivery receipts for the same identity before releasing storage;
[key ownership](src/quic/application/localside/keys.rs) separates receive-side
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
constant-time machine code. See [Hibana's guarantee boundary](https://github.com/hibanaworks/hibana/blob/af69def928f498ad474a4d2add238615e175a49b/README.md#guarantees)
for the underlying runtime and carrier assumptions.

## Write an application with Hibana

The examples keep native initialization in one [environment module](examples/environment.rs).
It selects credentials, capacities and addresses. PAL supplies file access,
UDP, clocks, entropy and the executor. The CLI uses `std` for arguments and
output; the protocol library and PAL require neither `std` nor `alloc`.

### Raw QUIC: one shared application global

Client and server project the same application conversation. The ordered QUIC
stream carries its typed messages using ALPN `hibana/1`. The application writes
`send` and `recv`; it never implements a carrier or drives transport phases.

```rust
//! One application choreography projected by both client and server.
//! Each launcher projects its role and supplies an inferred application localside.
use hibana::g;
use hibana::runtime::program::Projectable;
pub const CLIENT: u8 = 0;
pub const SERVER: u8 = 1;
pub type Number = g::Msg<0, u64>;
pub type Square = g::Msg<1, u64>;
pub fn choreography() -> impl Projectable {
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

### Raw QUIC client

[Complete executable](examples/hello-quic/client.rs). The endpoint argument is inferred.

```rust
//! Application global and localside; native initialization is in ../environment.rs.
#[path = "../environment.rs"]
mod environment;
mod global;
use global::{Number, Square};
use hibana::runtime::program::project;
use hibana_quic::session::Protocol;
fn main() -> Result<(), String> {
    environment::client(Protocol::default(), async |client| {
        client
            .run(
                project::<{ global::CLIENT }>(&global::choreography()),
                async |client| -> Result<(), ApplicationError> {
                    for number in [42_u64, 7] {
                        client
                            .send::<Number>(&number)
                            .await
                            .map_err(ApplicationError::Protocol)?;
                        let square = client
                            .recv::<Square>()
                            .await
                            .map_err(ApplicationError::Protocol)?;
                        if square != number * number {
                            return Err(ApplicationError::IncorrectSquare);
                        }
                    }
                    Ok(())
                },
            )
            .await
    })?;
    println!("42 squared = 1764\n7 squared = 49");
    Ok(())
}

#[derive(Debug)]
pub enum ApplicationError {
    Protocol(hibana::EndpointError),
    IncorrectSquare,
}
```

### Raw QUIC server

[Complete executable](examples/hello-quic/server.rs). The endpoint argument is inferred.

```rust
//! Application global and localside; native initialization is in ../environment.rs.
#[path = "../environment.rs"]
mod environment;
mod global;
use global::{Number, Square};
use hibana::runtime::program::project;
use hibana_quic::session::Protocol;
fn main() -> Result<(), String> {
    environment::server(Protocol::default(), async |server| {
        server
            .run(
                project::<{ global::SERVER }>(&global::choreography()),
                async |server| -> Result<(), ApplicationError> {
                    for _ in 0..2 {
                        let number = server
                            .recv::<Number>()
                            .await
                            .map_err(ApplicationError::Protocol)?;
                        let square = number
                            .checked_mul(number)
                            .ok_or(ApplicationError::Overflow)?;
                        server
                            .send::<Square>(&square)
                            .await
                            .map_err(ApplicationError::Protocol)?;
                    }
                    Ok(())
                },
            )
            .await
    })?;
    println!("served two requests");
    Ok(())
}

#[derive(Debug)]
pub enum ApplicationError {
    Protocol(hibana::EndpointError),
    Overflow,
}
```

### HTTP/3: native request and response choreography

HTTP/3 applications consume ordinary headers, body chunks and trailers. The
[message global](src/http3/message/global.rs) describes their storage ownership
and receipt order. The server's request reader, application and response writer
project that same global. The client uses distinct upload and download roles so
either direction can progress independently under backpressure.

The global is a value returning `impl Projectable`; it can be composed with
`g::seq` and `g::par`. Each application closure gets its inferred real endpoint.
The supplied graph must include the corresponding HTTP message fragment, and
its localsides must execute any additional projected steps. The existing End/Done
messages complete the HTTP fragments. Endpoints stay alive until role and network
work drains; transport failures and cancellation terminate unfinished exchanges.
A closure returning success is not a separate proof that arbitrary additional
projected steps were executed.

The reader transfers the actual validated request method to the response writer.
On the client, the request writer transfers it to response consumption. Peer
SETTINGS arrive with authenticated admission and bound decoded field-section
sizes. The application does not supply a separate HEAD flag or negotiated limit.

These native bindings currently run one exchange on stream zero. The buffers
bound in-flight storage, not total body length. They do not implement a router
or an independent multi-request application scheduler. Local body loans are
borrowed; outgoing data is copied into bounded exchange/transport storage, so
this API does not claim end-to-end zero-copy.

### HTTP/3 client

[Complete executable](examples/hello-http3/client.rs).

```rust
//! A native HTTP/3 request with independent upload and response localsides.
#[path = "../environment.rs"]
mod environment;
use hibana_quic::{
    http3::{
        Storage,
        localside::client::{DOWNLOAD, READ, UPLOAD, WRITE},
        message::{self, Consumer, FieldSection},
    },
    session::Protocol,
};

struct Print;
impl Consumer for Print {
    async fn headers(&mut self, fields: FieldSection<'_>) -> message::Result<()> {
        println!("HTTP/3 {}", fields.metadata.status.ok_or("missing status")?);
        Ok(())
    }
    async fn data(&mut self, _: u64, bytes: &[u8]) -> message::Result<()> {
        use std::io::Write;
        std::io::stdout()
            .write_all(bytes)
            .map_err(|_| "stdout failed")?;
        Ok(())
    }
    async fn complete(&mut self, length: u64) -> message::Result<()> {
        println!("\n{length} response bytes");
        Ok(())
    }
}

fn main() -> Result<(), String> {
    environment::client(Protocol::Http3, async |client| {
        let global = message::global::client::<UPLOAD, WRITE, READ, DOWNLOAD>();
        let mut storage = const { Storage::<4096>::new() };
        client
            .http3(
                &global,
                &mut storage,
                async |upload, mut request| {
                    request
                        .headers(upload, b"POST", b"localhost", b"/echo", &[])
                        .await?;
                    request.write(upload, b"hello from Hibana").await?;
                    request.finish(upload).await
                },
                async |download, response| {
                    response.receive(download, &mut Print).await?;
                    Ok(())
                },
            )
            .await
    })
}
```

### HTTP/3 server

[Complete executable](examples/hello-http3/server.rs).

```rust
//! A native HTTP/3 streaming echo application. No application-message tunnel.
#[path = "../environment.rs"]
mod environment;
use hibana_quic::{
    http3::{
        Storage,
        localside::server::{APP, READ, WRITE},
        message,
    },
    session::Protocol,
};

fn main() -> Result<(), String> {
    environment::server(Protocol::Http3, async |server| {
        let global = message::global::server::<READ, APP, WRITE>();
        let mut storage = const { Storage::<4096>::new() };
        server
            .http3(
                &global,
                &mut storage,
                async |app, mut request, mut response| {
                    let headers = request.headers(app).await?;
                    let method = headers.fields().metadata.method;
                    headers.release(app).await?;
                    response
                        .headers(app, 200, &[(b"content-type", b"application/octet-stream")])
                        .await?;
                    while let Some(chunk) = request.chunk(app).await? {
                        if method != Some(hibana_quic::http3::Method::Head) {
                            response.write(app, chunk.bytes()).await?;
                        }
                        chunk.release(app).await?;
                    }
                    request.trailers(app, |_| Ok(())).await?;
                    request.finish(app).await?;
                    response.finish(app).await
                },
            )
            .await
    })?;
    println!("served HTTP/3 echo");
    Ok(())
}
```

### Run both sides

The native launchers target Linux/macOS with Rust 1.95. Supply a development
certificate chain/key for `DNS:localhost` and its CA. Verification stays enabled.

```sh
cargo build --locked --release --manifest-path examples/Cargo.toml --examples
# In separate terminals:
examples/target/release/examples/quic-server 127.0.0.1:4433 chain.pem key.pem
examples/target/release/examples/quic-client 127.0.0.1:4433 ca.pem
# Or run the HTTP/3 pair:
examples/target/release/examples/http3-server 127.0.0.1:4433 chain.pem key.pem
examples/target/release/examples/http3-client 127.0.0.1:4433 ca.pem
```

Use the actual target directory when setting `CARGO_TARGET_DIR`. The raw example
calculates two squares; HTTP/3 echoes `hello from Hibana` through a streaming POST.
Both bindings require normal connection termination, separately from local
message completion. A 30-second launcher deadline bounds each demonstration.

```sh
python3 tests/check_examples.py examples/target/release/examples chain.pem key.pem ca.pem
```

### Completion and guarantee boundaries

An endpoint send publishes to bounded carrier storage; it is not a remote ACK.
A message storage receipt permits that borrowed buffer to be reused. Actual
stream FIN, authenticated connection close and resource retirement remain QUIC
obligations. Cancellation drops the joined futures and their owned resources;
it never fabricates a missing application reply or successful stream EOF.

Network peers remain untrusted. Hibana checks local projected operations; TLS,
HTTP field validation and QUIC's receive rules check their respective inputs.
Raw typed messages preserve the session, source, destination, lane and label,
with up to 256 payload bytes per frame and four queued frames. HTTP/3 carries
standard HTTP/3 frames without that raw application-message envelope.

- [Raw session attachment](src/session/localside/mod.rs)
- [Native HTTP/3 server roles](src/http3/localside/server.rs)
- [Native HTTP/3 client roles](src/http3/localside/client.rs)
- [HTTP message order](src/http3/message/global.rs)
- [Borrowed request actions](src/http3/message/localside/request.rs)
- [Response production](src/http3/message/localside/producer.rs)
- [Shared HTTP storage](src/http3/imp/storage.rs) and [QUIC byte grants](src/http3/imp/stream.rs)
- [Core platform contracts](src/io/mod.rs)
- [PAL native executor](pal/src/unix/reactor.rs)

## Find the protocol and its implementation

Every protocol directory puts ordering first, execution second, and computation
below `imp/`:

| Protocol | Order | Execution | Implementation |
|---|---|---|---|
| QUIC handshake | [global.rs](src/quic/global.rs) | [localside/](src/quic/localside/mod.rs) | [imp/](src/quic/imp/mod.rs) |
| Application | [global.rs](src/quic/application/global.rs) | [localside/](src/quic/application/localside/mod.rs) | [imp/](src/quic/application/imp/mod.rs) |
| Early data | [global.rs](src/quic/early_data/global.rs) | [localside/](src/quic/early_data/localside/mod.rs) | [imp/](src/quic/early_data/imp/mod.rs) |
| ECN | [global.rs](src/quic/ecn/global.rs) | [localside/](src/quic/ecn/localside/mod.rs) | [imp/](src/quic/ecn/imp/mod.rs) |
| Path validation | [global.rs](src/quic/path/global.rs) | [localside/](src/quic/path/localside/mod.rs) | [imp/](src/quic/path/imp/mod.rs) |
| Retry client | [global/client.rs](src/quic/retry/global/client.rs) | [localside/](src/quic/retry/localside/mod.rs) | [imp/](src/quic/retry/imp/mod.rs) |

Server Retry admission uses the same core [global](src/quic/retry/global.rs)
with the [Retry input/owner/output localsides](src/quic/retry/localside/server.rs).

`localside/mod.rs` contains the composition or direct role entry. The role files
contain the actual endpoint operations; `imp/` contains buffers, codecs and
arithmetic.

## Optional HQ profile

Enable `hq` explicitly to use HTTP/0.9 GET interoperability. It is disabled by
default in both QUIC and TLS. Enabling it keeps the libraries `no_std` and does
not link `alloc`. The profile borrows request paths, parses targets in-place,
and transfers caller-provided response storage through the existing connection
and stream choreography.

[`hq::Requests`, `hq::Response` and `hq::Service`](src/hq/mod.rs) provide bounded
wire/storage effects. `session::Client::transfer` and `session::Server::serve`
own connection execution. `Response` accepts one response on stream 0;
multi-request clients provide their own `StreamSink` for per-stream storage.
Path authorization and percent-decoding policies belong to the application.
The [HQ client](examples/hello-hq/client.rs) and [server](examples/hello-hq/server.rs)
show a one-file exchange. Their Unix launchers use `std` for CLI/file setup;
[the board entry points](pal/examples/pico/src/hq.rs) use the same operations
without `std` or `alloc`. The larger `tests/interop/driver` binary is the interoperability
runner adapter, with filesystem and test-scenario handling.

```sh
cargo test --locked --features hq
cargo check --locked --lib --features hq --target thumbv6m-none-eabi
cargo build --locked --release --manifest-path examples/Cargo.toml --features hq --example hq-client --example hq-server
```

## Build

```sh
cargo check --locked --lib
cargo test --locked
cargo check --locked --lib --target thumbv6m-none-eabi
```

For development tests that use the sibling TLS sources, place `hibana-tls/`
next to `hibana-quic/` at the revision pinned in Cargo.toml.

Licensed under MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.

## Environment boundary

The protocol implementation has one home in `src/`:

- [QUIC global](src/quic/global.rs) and [localsides](src/quic/localside/mod.rs) own the handshake and its affine continuations.
- [Connected global](src/quic/application/global.rs) and [localsides](src/quic/application/localside/mod.rs) own streams, keys, close and retirement.
- [Retry global](src/quic/retry/global.rs), [server localsides](src/quic/retry/localside/server.rs) and [packet arithmetic](src/quic/retry/imp/admission.rs) perform admission with injected I/O.
- [HTTP/3 message global](src/http3/message/global.rs), [localsides](src/http3/message/localside/mod.rs) and [bounded codec](src/http3/message/imp/input.rs) consume message storage without filesystem assumptions.
- [Application session](src/session/localside/mod.rs) connects user-projected localsides to the common stream implementation.

[Borrowed connection attachment](src/quic/application/localside/borrowed.rs) consumes
caller-owned slabs, buffers, keys and physical capabilities without allocating.
[Connection attachment](src/quic/application/localside/owned/mod.rs) borrows the
caller-owned stream array and arena and calls that same attachment. There is no
`alloc` feature or allocator-backed alternative. Both OS and bare-metal callers
supply the same physical capabilities and poll the same Rust futures.

The environment supplies [DatagramRx, DatagramTx, DatagramSocket and Clock](src/io/mod.rs),
[cryptographic Entropy](https://github.com/hibanaworks/hibana-tls/blob/d1806e9c4a6d6c59294d15b671e72a637165691a/src/entropy.rs),
and an executor that polls ordinary Rust futures. Native implementations and
minimal environment examples are under [pal/](pal/README.md).

For a board or custom OS, [the Pico integration example](pal/examples/pico/src/lib.rs)
reuses the exact native example's application global and client/server localsides.
It accepts board I/O, credentials and caller-owned connection memory. It builds
without `std` or `alloc`; it is not a boot image, network driver, or evidence that
a particular board has enough RAM for a chosen connection profile.

```sh
cargo check --locked --manifest-path pal/examples/pico/Cargo.toml --target thumbv6m-none-eabi
```
