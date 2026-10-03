#!/usr/bin/env bash
# Component audit only. End-to-end bounded-wire/stream counters are separate tests.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --locked --test no_alloc
cargo tree --locked --target thumbv6m-none-eabi -e normal,features
cargo check --locked --lib --target thumbv6m-none-eabi
# A dedicated target-specific example, not a real board startup/driver image.
cargo rustc --locked --release --example thumb_link --features target-link-smoke --target thumbv6m-none-eabi -- -C link-arg=-e_start
printf '%s\n' 'Implemented component checks passed; complete QUIC/TLS lifecycle allocation gate remains unpassed.'
