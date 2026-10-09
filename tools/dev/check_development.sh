#!/usr/bin/env bash
# Run local build and test checks.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo test --locked
cargo clippy --locked --lib --tests -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 tools/ci/check_dependencies.py
cargo test --locked --release --manifest-path host/Cargo.toml --lib --bin hq
cargo test --locked --manifest-path tests/tls-reference/Cargo.toml --test bounded_tls --test certificate_depth
if [[ -n "${HIBANA_RUNNER_CERTS_DIR:-}" ]]; then
  cargo test --locked --manifest-path tests/tls-reference/Cargo.toml --test certificate_depth -- --include-ignored
else
  printf '%s\n' 'NOT RUN here: external runner-generated certificate fixture (set HIBANA_RUNNER_CERTS_DIR).'
fi
bash tools/dev/check_no_alloc.sh
printf '%s\n' 'Local build and test checks passed.'
