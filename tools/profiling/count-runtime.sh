#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  printf 'Usage: %s OUTPUT_DIRECTORY [cargo options...]\n' "$0" >&2
  exit 2
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$1"
out=$(cd "$1" && pwd)
shift
if [[ -e "$out/runtime.profraw" || -e "$out/coverage.json" ]]; then
  printf 'Use a fresh output directory: %s\n' "$out" >&2
  exit 2
fi
cd "$root"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$out/target}"
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
export RUSTFLAGS='-C instrument-coverage'
unset CARGO_ENCODED_RUSTFLAGS
rustc +stable -Vv > "$out/rustc.txt"
sysroot=$(rustc +stable --print sysroot)
host=$(sed -n 's/^host: //p' "$out/rustc.txt")
llvm="$sysroot/lib/rustlib/$host/bin"
for tool in llvm-cov llvm-profdata; do
  if [[ ! -x "$llvm/$tool" ]]; then
    printf 'Missing %s. Install llvm-tools-preview for stable.\n' "$tool" >&2
    exit 1
  fi
done
cargo +stable test --release --test connected_application --no-run \
  --message-format=json "$@" > "$out/build.jsonl" 2> "$out/build.log"
binary=$(jq -ers '[.[] | select(.reason == "compiler-artifact" and .target.name == "connected_application" and .executable != null)] | if length == 1 then .[0].executable else error("expected one connected_application executable") end' "$out/build.jsonl")
[[ -x "$binary" ]]
shasum -a 256 "$binary" > "$out/binary.sha256"
LLVM_PROFILE_FILE="$out/runtime.profraw" "$binary" \
  actual_get_selects_encrypted_body_and_completes_close --exact --test-threads=1 \
  > "$out/runtime.log" 2>&1
"$llvm/llvm-profdata" merge -sparse "$out/runtime.profraw" -o "$out/runtime.profdata"
"$llvm/llvm-cov" export "$binary" --instr-profile="$out/runtime.profdata" \
  --skip-expansions --skip-branches > "$out/coverage.json"
jq -r '.data[].functions[] | [.count, .name] | @tsv' "$out/coverage.json" \
  | sort -nr > "$out/function-counts.tsv"
jq '.data[].functions[] | select(.name | test("source_precedes|source_route_bounds|route_scope_slot|event_enabled|source_predecessor_wait|parallel_region_covers_frontier|complete_roll_body_scope_for_index")) | {name, count, filenames, regions}' \
  "$out/coverage.json" > "$out/admission-counts.json"
shasum -a 256 --check "$out/binary.sha256"
printf 'Runtime call and region counts: %s\n' "$out"
