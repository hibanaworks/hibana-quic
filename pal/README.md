# hibana-quic-pal

Platform access for hibana-quic. The library is no_std with and without an OS.
The Linux/macOS implementation uses core and alloc, plus confined native ABI calls.
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

## Source map

- [unix/udp.rs](src/unix/udp.rs): datagram bytes and actual IP/ECN metadata.
- [unix/reactor.rs](src/unix/reactor.rs): readiness, timers and wakeups.
- [unix/clock.rs](src/unix/clock.rs): monotonic clock and physical deadline waiting.
- [unix/entropy.rs](src/unix/entropy.rs): kernel randomness without a weak fallback.
- [unix/files.rs](src/unix/files.rs): descriptor-relative file operations.
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
