# Read globals, then direct locals

## Protocol control

| Domain | Global definition | Local implementation |
|---|---|---|
| QUIC handshake, parallel roles and retirement | `src/quic/global.rs` | `src/quic/local/{receive,transmit,publication}.rs`, `timer.rs`, `retry_client.rs` |
| TLS transcript ordering | `src/tls/handshake/global.rs` | `src/tls/handshake/local.rs` |
| Connected stream/application lifecycle | `src/quic/application/global.rs` | `src/quic/application/{io,receive,transmit,keys,termination}.rs` |
| HTTP/3 control and SETTINGS | `src/http3/global.rs` | `src/quic/application/http3.rs` and explicit IO continuations |
| Path, ECN, Retry, early-data subprotocols | each domain's `global.rs` | the adjacent ownership/effect implementation |

Locals contain actual `send`, `recv`, `offer`, route decisions and joins. The
assembly layer supplies storage, endpoints and task pinning; it is not an
alternative protocol dispatcher. Helpers may calculate bytes/numbers, not hide
protocol communication or fabricate its completion.

HTTP/3 locals currently remain next to the QUIC resources they privately own.
Moving them solely for a prettier folder tree must not require widening access
to affine handles or introducing another coordinator.

## Mechanisms and execution

- `src/io.rs`: executor-neutral datagram metadata, UDP acceptance and monotonic clock contracts.
- `src/runtime.rs`: fixed, caller-pinned future execution and cancellation, independent of an OS reactor.
- `adapters/host/src/{async_io,io,udp,path_socket}.rs`: actual Linux readiness and physical effects.
- `adapters/host/src/storage.rs`: host allocation of bounded buffers and matching limits.
- `src/tls/{wire,certificate,schedule,ticket,rsa}.rs`: TLS encodings, validation and numerical/cryptographic mechanisms.
- `src/http3/wire.rs`: bounded frame and static-QPACK/Huffman interpretation.
- `src/quic/local/sealing.rs`: packet preparation and numerical admission; no hidden endpoint exchanges.
- `src/{packet,accounting,recovery,streams,path,crypto}.rs`: wire/kernel mechanisms. Their further grouping is a separate mechanical step, not a new FSM.
- `src/carrier.rs`: internal descriptor carrier. It is **not** a QUIC network transport for user applications.

## Application-facing target

Applications should define their own Hibana global and direct role locals.
Host setup should supply transport, configuration, buffers and execution without
requiring a copy of the hq CLI. The intended examples are request/reply, parallel
requests, streaming and cancellation, with visible failure and completion edges.

This API is not complete yet. The current `quic::application` traits and file
adapter are usable lower-level boundaries, not a finished easy application SDK.
A real Hibana-over-QUIC transport must retain framing, lane/session binding,
partial-send cancellation, requeue, peer closure and bounded backpressure.
Ordinary HTTP/3 peers must remain interoperable without proprietary framing.
