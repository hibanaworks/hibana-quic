#!/usr/bin/env bash
# Reproducible implemented-scope checks; never labels the external release gates passed.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --locked
cargo clippy --locked --lib --tests -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 vendor/check_hibana.py
python3 vendor/check_webpki.py
# Deleted central-endpoint targets have no compatibility fallback.
cargo test --locked --release --manifest-path adapters/host/Cargo.toml --lib --bin hq
cargo test --locked --manifest-path reference-tls/Cargo.toml --test bounded_tls --test certificate_depth
if [[ -n "${HIBANA_RUNNER_CERTS_DIR:-}" ]]; then
  cargo test --locked --manifest-path reference-tls/Cargo.toml --test certificate_depth -- --include-ignored
else
  printf '%s\n' 'NOT RUN here: external runner-generated certificate fixture (set HIBANA_RUNNER_CERTS_DIR).'
fi
bash scripts/check_no_alloc.sh
printf '%s\n' 'Implemented development checks passed. Full runner matrix and Pico HIL are separate, unpassed gates.'
