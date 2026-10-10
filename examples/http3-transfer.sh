#!/usr/bin/env bash
# Transfer one file over verified QUIC/TLS and HTTP/3 on Linux.
set -euo pipefail
if [ "$#" -ne 3 ]; then
    printf 'Usage: %s SERVER_CHAIN.pem SERVER_KEY.pem TRUSTED_CA.pem\nThe server certificate must contain DNS:localhost.\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
chain=$(realpath "$1"); key=$(realpath "$2"); ca=$(realpath "$3")
cargo build --locked --release --manifest-path "$root/examples/Cargo.toml" --bin hq
hq="${CARGO_TARGET_DIR:-$root/examples/target}/release/hq"
work=$(mktemp -d)
server_pid=
cleanup() { if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi; }
trap cleanup EXIT
mkdir "$work/www" "$work/downloads"
printf 'hello from Hibana\n' > "$work/www/hello.txt"
"$hq" server --listen 127.0.0.1:4433 --cert "$chain" --key "$key" --www "$work/www" --max-requests 1 --http 3 > "$work/server.log" 2>&1 &
server_pid=$!
# Allow socket binding before starting the client; QUIC handles packet retries.
sleep 1
"$hq" client --connect 127.0.0.1:4433 --server-name localhost --ca "$ca" --request /hello.txt --downloads "$work/downloads" --http 3 > "$work/client.log" 2>&1
wait "$server_pid"
server_pid=
cmp "$work/www/hello.txt" "$work/downloads/hello.txt"
printf 'HTTP/3 file matched. Output and logs: %s\n' "$work"
