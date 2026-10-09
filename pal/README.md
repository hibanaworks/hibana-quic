# hibana-quic-pal

Linux/macOS environment access and a command-line client/server for hibana-quic. TLS comes from
hibana-tls. The normal dependency graph consists of the Hibana projects; PEM
decoding and certificate validation belong to hibana-tls; native ABI bindings live here.

## Application examples

See the [raw QUIC and HTTP/3 client/server applications](../README.md#write-an-application-with-hibana).
Each client/server pair projects the same application global. Carrier construction and framing stay inside the library.

## Build

From the repository root:

```sh
cargo build --locked --release --manifest-path pal/Cargo.toml --bin hq
pal/target/release/hq --help
```

If CARGO_TARGET_DIR is set, the executable is in its `release/` directory instead.

## Serve and fetch a file

Use a certificate chain and private key for `localhost`. The client must trust
the certificate's CA. Prepare the served directory:

```sh
mkdir -p www downloads
printf 'hello from Hibana\n' > www/hello.txt
```

Server terminal:

```sh
pal/target/release/hq server --listen 127.0.0.1:4433 \
  --cert chain.pem --key key.pem --www www --max-requests 1 --http 3
```

Client terminal:

```sh
pal/target/release/hq client --connect 127.0.0.1:4433 \
  --server-name localhost --ca ca.pem --request /hello.txt \
  --downloads downloads --http 3
cmp www/hello.txt downloads/hello.txt
```

The [single-command example](../examples/http3-transfer.sh) runs these together.
Never use a production private key for a local demonstration.

`--timeout-seconds` bounds the whole CLI operation (1–300 seconds).
`--idle-timeout-seconds` independently sets the local QUIC idle timeout
(0–300 seconds; defaults to half the operation budget). A zero local idle
timeout still permits the peer to negotiate a nonzero idle timeout.
Closing and draining retain the protocol’s PTO-based timing.

## Environment responsibilities

- [udp.rs](src/udp.rs), [async_io.rs](src/async_io.rs): physical datagrams, readiness and executor wakeups.
- [io.rs](src/io.rs): monotonic clocks and actual I/O observations.
- [entropy.rs](src/entropy.rs): the operating system's secure randomness.
- [fs.rs](src/fs.rs): file storage and descriptor-relative operations.
- [pem.rs](src/pem.rs): credential file reads; `hibana-tls` decodes their contents.
- [launch.rs](src/launch.rs): native socket/credential setup and execution of the common library entrypoint.
- [sys/](src/sys.rs): the small native ABI boundary; no external `libc` or `nix` crate.

Protocol globals, localsides, admission, packet arithmetic, buffer profiles and
resource handoffs live in `hibana-quic/src/`. The CLI application itself lives in
[examples/hq/](../examples/hq/main.rs).

## Platform examples

Linux and macOS use the same safe UDP/reactor code, with the native ABI selected
inside `sys/`. Their small examples exercise real loopback datagrams and entropy:

```sh
cargo run --locked --manifest-path pal/Cargo.toml --example linux
# On macOS:
cargo run --locked --manifest-path pal/Cargo.toml --example macos
```

The [Pico integration](examples/pico/src/lib.rs) supplies a `no_std`/`no_alloc`
entrypoint for the same application global and localsides. The board supplies
its network driver, clock, secure entropy, executor and bounded memory. A target
check does not demonstrate board execution or RAM feasibility:

```sh
cargo check --locked --manifest-path pal/examples/pico/Cargo.toml --target thumbv6m-none-eabi
```
