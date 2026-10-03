#!/usr/bin/env bash
# Exact focused suites; preserve every assertion and each real exit status.
set -u
cargo test --locked --test application_wire -- --test-threads=1
wire=$?
cargo test --locked --test connected_application -- --test-threads=1
connection=$?
cargo test --locked --manifest-path adapters/host/Cargo.toml --bin hq -- --test-threads=1
host=$?
printf '{"application_wire_exit":%d,"connected_application_exit":%d,"host_hq_exit":%d,"interop":"NOT_RUN"}\n' "$wire" "$connection" "$host" > /results/runtime-status.json
(( wire == 0 && connection == 0 && host == 0 ))
