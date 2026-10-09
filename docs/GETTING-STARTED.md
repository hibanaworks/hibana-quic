# Run a real HTTP/3 transfer

Requirements: Linux, pinned Rust 1.95.0, and an ECDSA P-256 certificate/key with
`localhost` in the subject alternative name. Use a certificate you control;
never disable CA or hostname verification to make a demo pass.

From the repository root:

```sh
cargo build --locked --release --manifest-path host/Cargo.toml --bin hq
host/target/release/hq --help
mkdir -p www downloads
printf 'hello from Hibana\n' > www/hello.txt
```

Start the server with the certificate chain and private key, then run the client
in another terminal with its trusted CA certificate:

```sh
host/target/release/hq server --listen 127.0.0.1:4433 \
  --cert chain.pem --key key.pem --www www --max-requests 1 --http 3
host/target/release/hq client --connect 127.0.0.1:4433 \
  --server-name localhost --ca ca.pem --request /hello.txt \
  --downloads downloads --http 3
cmp www/hello.txt downloads/hello.txt
```

These are actual CLI options. If `CARGO_TARGET_DIR` is set, use that directory's
`release/hq` instead. A TLS-prefix-only invocation without file options does not
establish HTTP transfer, application completion or clean connection close.

For library development, start at [the global/local map](ARCHITECTURE.md).
Core IO contracts are in `hibana_quic::io`; concrete Linux effects and bounded
buffer construction are in `hibana_quic_host::{io,storage}`. A complete ergonomic
application-choreography API is still being built; don't copy private CLI support
modules into a public dependency and call that finished SDK support.


## Library entry points

Do not import `host/src/bin/support` files. Public effects and bounded storage
are in `hibana_quic_host::{io, storage}`. FIN-complete file-service HTTP/3
validation is in `hibana_quic_host::http3`; its response decoder mutates only the
unpublished staging file. Live streaming and a minimal application connection
constructor remain work in progress: [application API](APPLICATION-API.md).

The TLS modules under `hibana_quic::tls` directly re-export canonical
`hibana_tls` modules. Their source is in that crate, not a copied QUIC TLS tree.
