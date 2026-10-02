#!/usr/bin/env bash
# Layout-only diagnostic. Does not execute target code or assert firmware fit.
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${1:-release}"
case "$profile" in
  release) flags=(--release);;
  debug) flags=();;
  *) printf '%s\n' 'usage: measure_async_storage.sh [release|debug] [output-directory]' >&2; exit 2;;
esac
out="${2:-artifacts/async-storage-budget/$profile}"
mkdir -p "$out"
snapshot() {
  python3 - <<'PY'
import hashlib,json
from pathlib import Path
paths = list(Path('src').rglob('*.rs'))
paths += [Path(p) for p in ('Cargo.toml', 'Cargo.lock', '.cargo/config.toml',
    'examples/async_storage_budget.rs', 'scripts/read_async_storage_budget.py',
    'scripts/measure_async_storage.sh', 'vendor/hibana-provenance.json')]
print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(paths)}, indent=2))
PY
}
snapshot > "$out/source-hashes-before.json"
rustc -Vv > "$out/rustc.txt"
printf '%s\n' "$profile" > "$out/profile.txt"
cargo rustc --locked "${flags[@]}" --example async_storage_budget \
  --target thumbv6m-none-eabi -- -C link-arg=-e_start 2>&1 | tee "$out/build.log"
snapshot > "$out/source-hashes-after.json"
cmp "$out/source-hashes-before.json" "$out/source-hashes-after.json" || {
  printf '%s\n' 'Sources changed during measurement; rerun after edits settle.' >&2
  exit 1
}
elf="${CARGO_TARGET_DIR:-target}/thumbv6m-none-eabi/$profile/examples/async_storage_budget"
cp "$elf" "$out/async-storage-budget.elf"
python3 scripts/read_async_storage_budget.py "$out/async-storage-budget.elf" > "$out/budget.json"
printf '%s\n' "Layout report: $out/budget.json (not a firmware-fit result)"
