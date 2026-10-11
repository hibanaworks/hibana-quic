# hibana-quic-pal

Platform access for hibana-quic. The library is no_std with and without an OS.
The Linux/macOS implementation uses core and confined native ABI calls, without
the alloc crate. The caller provides static WakeStorage to Reactor::new. Cloned
wakers keep the native wake writer alive until their last owner drops; storage
cannot be reused while old wake handles remain. Socket and timer registries are bounded.
There are no Rust libc or nix dependencies.

## Common capabilities

The canonical contracts are in [hibana-quic::io](../src/io/mod.rs):
DatagramSocket, Clock and RandomAccess, with Entropy in
[hibana-quic::entropy](../src/lib.rs).
PAL exposes these same traits without a second contract or adapter state machine.

A platform supplies physical datagrams, monotonic time, secure randomness and
the executor that polls futures. Protocol projection, authentication, retransmission,
path admission, stream ownership and closing are implemented in hibana-quic.
Applications use the same projected Hibana localsides on each platform.

`Reactor::run_udp` owns a registered socket, clock, entropy source and deadline
for an application future. It releases readiness and timer registrations when
that future completes or is cancelled. It does not select ALPN, load a TLS
identity, run a handshake or decide when a QUIC connection has closed.

`unix::files::File` implements positional `RandomAccess` without a heap or a
shared sequential cursor. `open` refuses a final symlink; `create_new` refuses
an existing destination. Reads and writes use the supplied offset. Concurrent
file modification follows ordinary OS semantics; reading the current length
does not create a snapshot. File operations are synchronous, so applications
must account for storage latency when choosing their executor.

## Source map

- [unix/udp.rs](src/unix/udp.rs): datagram bytes and actual IP/ECN metadata.
- [unix/reactor.rs](src/unix/reactor.rs): readiness, timers and wakeups.
- [unix/clock.rs](src/unix/clock.rs): monotonic deadlines and observed Unix wall-clock time.
- [unix/entropy.rs](src/unix/entropy.rs): kernel randomness without a weak fallback.
- [unix/files.rs](src/unix/files.rs): owned positional files and descriptor-relative file operations.
- [sys/wake.rs](src/sys/wake.rs): counted ownership of native wake descriptors in caller-provided static storage.
- [sys/os.rs](src/sys/os.rs) and [sys/udp.rs](src/sys/udp.rs): native descriptors and ABI layouts.

The native ABI implementation currently covers x86_64 and aarch64 Linux/macOS.
Other targets can implement the common no_std contracts directly.

## Native capability examples

These exercise loopback UDP, randomness and descriptor retirement:

```sh
cargo run --locked --manifest-path pal/Cargo.toml --example linux
# On macOS:
cargo run --locked --manifest-path pal/Cargo.toml --example macos
```

The command-line QUIC/HTTP3 application is a separate
[examples package](../examples/Cargo.toml). See the
[application guide](../README.md#write-an-application-with-hibana).

## Bare metal

The [Pico integration](examples/pico/src/lib.rs) is no_std/no_alloc.
The board supplies its network driver, monotonic clock, secure entropy,
executor and bounded memory. A target check does not establish device execution
or RAM feasibility.

```sh
cargo check --locked --manifest-path pal/Cargo.toml --lib --target thumbv6m-none-eabi
cargo check --locked --manifest-path pal/examples/pico/Cargo.toml --target thumbv6m-none-eabi
```
