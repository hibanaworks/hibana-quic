#!/usr/bin/env bash
# Component and complete in-memory QUIC/HQ lifecycle allocation checks.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo test --locked --test no_alloc
# Optional libtest-captured diagnostics are host-fixture allocations. Keep the
# measured execution unchanged and run this gate without per-poll tracing.
unset HIBANA_TRACE_POLLS
lifecycle_tests="$(cargo test --locked --test connected_application -- --list)"
for test in \
  full_in_memory_tls_application_and_normal_close_do_not_allocate \
  full_lifecycle_allocation_counter_detects_a_real_allocation; do
  if ! grep -Fqx "${test}: test" <<< "${lifecycle_tests}"; then
    printf 'Missing required allocation regression: %s\n' "${test}" >&2
    exit 1
  fi
  cargo test --locked --test connected_application "${test}" -- --exact
done
cargo tree --locked --target thumbv6m-none-eabi -e normal,features
cargo check --locked --lib --target thumbv6m-none-eabi
# A dedicated target-specific example, not a real board startup/driver image.
cargo rustc --locked --release --example thumb_link --features target-link-smoke --target thumbv6m-none-eabi -- -C link-arg=-e_start
printf '%s\n' \
  'Passed: component allocation checks, in-memory QUIC/HQ TLS setup through normal close and protocol-owner drop, allocator positive control, and component thumb link.' \
  'Not qualified by this gate: native OS I/O allocation behavior or the complete native HTTP/3 lifecycle.'
