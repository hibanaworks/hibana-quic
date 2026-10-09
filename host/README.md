# hibana-quic-host

Linux adapters and a command-line client/server for hibana-quic. TLS comes from
hibana-tls. The normal dependency graph consists of the Hibana projects; PEM
parsing, certificate import and OS bindings are implemented in this workspace.

## Build

From the repository root:

```sh
cargo build --locked --release --manifest-path host/Cargo.toml --bin hq
host/target/release/hq --help
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
host/target/release/hq server --listen 127.0.0.1:4433 \
  --cert chain.pem --key key.pem --www www --max-requests 1 --http 3
```

Client terminal:

```sh
host/target/release/hq client --connect 127.0.0.1:4433 \
  --server-name localhost --ca ca.pem --request /hello.txt \
  --downloads downloads --http 3
cmp www/hello.txt downloads/hello.txt
```

The [single-command example](../examples/http3-transfer.sh) runs these together.
Never use a production private key for a local demonstration.

## Library entry points

- [application/local/](src/application/local/mod.rs): execute the connected
  client/server graph with your request source, body reader and response sink.
- [connection/local/mod.rs](src/connection/local/mod.rs): attach and execute a handshake.
- [retry/local/](src/retry/local/mod.rs): projected server address admission.
- [io.rs](src/io.rs): asynchronous UDP and clock effects.
- [storage.rs](src/storage.rs): caller-selected bounded connection storage.
- [http3/](src/http3/mod.rs): FIN-complete HTTP/3 file response framing.

Host owns allocation and OS effects. Protocol order and key ownership remain in
Hibana global/local code. The CLI's file handling is one application of that API.
The present profile is request/response file transfer, not a general HTTP/3 SDK.
