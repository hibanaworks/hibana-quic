# Application API: capabilities and acceptance criteria

This document separates available interfaces from the unfinished application SDK.
The user-facing surface is Rust API, examples, CLI diagnostics and documentation.
No graphical dashboard is required to write QUIC/HTTP/3 applications.

## Available today

- `hibana_quic::quic::application::{client, server, client_early}` run the existing
  composed connection with caller-owned setup and role endpoints.
- `ClientRequests`, `StreamSink`, `ServerHandler`, `BodyReader` are bounded
  application effect contracts. They do not yet constitute a general duplex
  QUIC-stream API or an arbitrary-method HTTP/3 framework.
- `quic::Roles::attach` and `quic::application::Roles::attach` bind their entire
  projected role set to a caller-owned Hibana rendezvous, including the actual
  resolver references. The CLI uses this same initialization. They do not send
  messages or create a second progress owner.
- `quic::application_stream::App::consume` exposes scoped borrowed receive slices
  for synchronous processing. Async retention still requires owned storage; see
  [buffer ownership and remaining copies](ZERO-COPY.md).
- `hibana_quic::io` supplies executor-neutral clock/datagram contracts.
- `hibana_quic_host::{io, storage}` supply Linux effects and owned buffers.
- `hibana_quic_host::connection::handshake` allocates and attaches the canonical
  handshake roles; the CLI calls this same public entry. It returns owned RX/TX
  continuations. Application-loop construction is still being extracted.
- `hibana_quic_host::http3::{decode_request, decode_response}` provide the existing
  bounded GET/file profile outside the CLI. Response decoding requires a
  FIN-complete unpublished staging file. It is not live network streaming.
- `runtime::carrier` transports in-process control descriptors only. It must not
  be advertised as carrying application choreography across the network.

## Module responsibilities

| Area | Sole responsibility | Forbidden duplication |
|---|---|---|
| Application API | Typed input/output and caller-owned resources | A second connection phase or key owner |
| `global.rs` | Communication order, branches, parallel composition and retirement | Host-selected next protocol stage |
| `local/` or `local.rs` | Literal endpoint sends, receives, offers and scoped joins | Wrappers hiding exchanges or manufacturing receipts |
| `imp/` (wire encoding, numerical recovery, cryptography) | Bounded bytes and numeric transformations | Advancing protocol order |
| `runtime/` | Polling, wake registration, fairness, cancellation and local carrier | TLS/QUIC phase decisions |
| `io/`, Host OS modules | Actual datagram acceptance, clock and readiness observations | Claiming network delivery from a local write |
| CLI | Arguments, file-service policy, reporting and process exit | The only reusable connection constructor |

Preserve existing public import paths when a direct module re-export suffices.
Do not maintain separate compatibility forwarding functions. Group code around
one resource owner and one comprehensible operation, rather than making a file
for every tiny arithmetic function. A file named `State` is not evidence of a
state machine by itself; audit who can advance it and whether authority is
stored twice. Replacing a bool with an enum without removing duplicated authority
is not progress.

## Required application journeys

1. **Authenticated request/reply:** user defines a Hibana global and direct locals;
   application setup supplies identity/trust, address, capacity and executor.
   No private CLI modules, raw connection IDs or manually installed internal role
   resolvers should be needed for the standard path.
2. **Parallel requests:** compose `par` in the application global; bounded stream
   capacity creates real backpressure rather than another pending/ready flag map.
3. **Streaming:** bounded chunks with ownership retained until actual acceptance.
   The first chunk must reach the consumer before producer EOF; buffering the
   whole body on disk does not satisfy this journey.
4. **Cancellation and failure:** cancel while waiting for readiness, after partial
   send, during a body, and during retirement. Never replay an accepted prefix or
   expose a success receipt on the error path.
5. **Ordinary HTTP/3 peers:** expose headers/body/trailers using standard HTTP/3
   framing. Neqo/quiche must not need a proprietary Hibana header to interoperate.

For a Hibana application protocol over raw QUIC, define explicit bounded message
framing, stream/lane/session binding and a documented negotiated protocol. Do not
silently put that framing inside arbitrary HTTP/3 response bodies. Both peers
must agree on that application protocol; it is separate from plain HTTP/3.

## Implementation order

1. Clean documentation and canonical ownership imports; preserve behavior.
2. Move connection allocation/attachment from CLI into the Host library and make
   it accept application effects. Move existing logic instead of wrapping the
   CLI or adding a forwarding controller. Keep secret scopes and roles owned
   through the existing aggregate completion.
3. Provide the bounded stream application boundary, then bind actual Hibana
   transport operations to it. Specify partial-send cancellation and closure
   before introducing an ergonomic constructor.
4. Add direct local HTTP/3 streaming progression using the shared primitives.
5. Compile and run the five journeys above as examples in CI. Keep the CLI on
   the same public API so examples cannot rot behind a private alternate path.

## Usability gates

Compare against the pinned quiche examples with the same trust verification,
streaming, concurrency, cancellation and error behavior. Count application-owned
configuration and control code, not blank lines. Hiding complexity in a wrapper
or disabling authentication does not count as simpler.

A fresh user must be able to run one documented command, see an authenticated
response, find the application's global and both locals, and understand where
its buffers and keys are owned. Errors must identify the failed operation without
printing secrets. Advanced limits remain explicit; the basic path should not
require learning the implementation's internal role graph.

No claim of “as easy as or easier than quiche” until these examples compile,
run against independent peers and pass interruption/backpressure tests.


## Ownership compatibility change in this reorganization

`quic::handshake` exclusively borrows `&mut Storage`, rather than accepting a
shared slot reference and maintaining a claimed flag. Rust prevents concurrent
operations on these exchange slots. Actual TLS/key ownership and the projected
roles remain the only protocol-progress authority. Pending ciphertext transfers
in the private handshake result before cleanup; failure/cancellation clears it.
Use fresh exchange memory for a new connection.

An initial by-value-storage candidate overflowed the default test stack. It was
rejected rather than increasing the test stack limit. Exclusive borrowing keeps
large bounded storage outside the nested future while preserving one borrower.
