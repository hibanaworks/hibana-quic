#!/usr/bin/env bash
# Exact focused suites; preserve every assertion and each real exit status.
set -u
cargo test --locked --test application_wire -- --test-threads=1
wire=$?
cargo test --locked --test connected_application -- --test-threads=1
connection=$?
cargo test --locked --manifest-path adapters/host/Cargo.toml --bin hq -- --test-threads=1
host=$?
cargo test --locked --release --test connection_publication_route -- --test-threads=1
publication=$?
printf '{"application_wire_exit":%d,"connected_application_exit":%d,"host_hq_exit":%d,"publication_route_exit":%d,"interop":"NOT_RUN"}\n' "$wire" "$connection" "$host" "$publication" > /results/runtime-status.json
(( wire == 0 && connection == 0 && host == 0 && publication == 0 ))
