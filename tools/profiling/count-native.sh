#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
  printf 'Usage: %s OUTPUT_DIRECTORY NEQO_SERVER CREDENTIAL_DIR SAMPLES [cargo options...]\n' "$0" >&2
  exit 2
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir "$1"
out=$(cd "$1" && pwd)
neqo=$2
credential_source=$3
samples=$4
shift 4
credentials="$out/credentials"
mkdir "$credentials"
for file in cert.der cert.pem key.pem body; do
  cp "$credential_source/$file" "$credentials/"
done
cp -R "$credential_source/nssdb" "$credentials/nssdb"
[[ $(uname -s) == Darwin ]] || { printf 'Continuous native snapshots require macOS\n' >&2; exit 1; }
page_hex=$(printf '%x' "$(getconf PAGESIZE)")
profile_link_args=()
for section in cnts data names bits; do
  profile_link_args+=("-C" "link-arg=-Wl,-sectalign,__DATA,__llvm_prf_$section,$page_hex")
done
cd "$root"
cp examples/Cargo.lock "$out/original-examples.lock"
trap 'cp "$out/original-examples.lock" "$root/examples/Cargo.lock"' EXIT
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
unset CARGO_ENCODED_RUSTFLAGS LLVM_PROFILE_FILE HIBANA_NATIVE_STACKS
export CARGO_TARGET_DIR="${HIBANA_NATIVE_DRIVER_TARGET:-$out/driver-target}"
env -u RUSTFLAGS cargo +stable build --offline --locked --release \
  --manifest-path tools/profiling/native-peers/Cargo.toml > "$out/driver-build.log" 2>&1
driver="$CARGO_TARGET_DIR/release/native-peer-comparison"
export CARGO_TARGET_DIR="${HIBANA_NATIVE_SERVER_TARGET:-$out/server-target}"
export RUSTFLAGS='-C instrument-coverage -C link-dead-code=yes'
rustc +stable -Vv > "$out/rustc.txt"
sysroot=$(rustc +stable --print sysroot)
host=$(sed -n 's/^host: //p' "$out/rustc.txt")
llvm="$sysroot/lib/rustlib/$host/bin"
for tool in llvm-cov llvm-profdata; do
  [[ -x "$llvm/$tool" ]] || { printf 'Missing %s\n' "$tool" >&2; exit 1; }
done
cargo +stable rustc --offline --release --manifest-path examples/Cargo.toml \
  --features hq --example hq-server --message-format=json "$@" \
  -- "${profile_link_args[@]}" \
  > "$out/server-build.jsonl" 2> "$out/server-build.log"
server=$(jq -ers '[.[] | select(.reason == "compiler-artifact" and .target.name == "hq-server" and .executable != null)] | if length == 1 then .[0].executable else error("expected one hq-server executable") end' "$out/server-build.jsonl")
cp examples/Cargo.lock "$out/resolved-examples.lock"
cp "$out/original-examples.lock" "$root/examples/Cargo.lock"
shasum -a 256 "$driver" "$server" "$neqo" > "$out/binaries.sha256"
HIBANA_NATIVE_COVERAGE="$out/profiles" "$driver" "$server" "$neqo" "$credentials" "$samples" \
  > "$out/measurements.tsv" 2> "$out/packets.tsv"
shasum -a 256 --check "$out/binaries.sha256"
for iteration in $(seq 0 "$((samples + 1))"); do
  prefix="$out/profiles/hibana-$iteration-"
  for cut in ready response; do
    "$llvm/llvm-profdata" merge -sparse "$prefix.$cut.profraw" -o "$prefix.$cut.profdata"
    "$llvm/llvm-cov" export "$server" --instr-profile="$prefix.$cut.profdata" \
      --skip-expansions --skip-branches > "$prefix.$cut.json"
  done
  jq -nr --slurpfile before "$prefix.ready.json" --slurpfile after "$prefix.response.json" '
    def counts($input): [$input[0].data[].functions[] | {key: .name, value: .count}]
      | group_by(.key) | map({key: .[0].key, value: (map(.value) | add)}) | from_entries;
    counts($before) as $b | counts($after) as $a |
    if ($a | keys) != ($b | keys) then error("profile function sets differ") else
      $a | keys[] as $name |
      if $a[$name] < $b[$name] then error("profile counter went backwards") else
        [$a[$name] - $b[$name], $name] | @tsv
      end
    end' | sort -nr > "$prefix.response-counts.tsv"
  awk -F '\t' '$1 > 0 && $2 ~ /6hibana/ { found=1 } END { exit !found }' \
    "$prefix.response-counts.tsv" || {
      printf 'No live Hibana counters in response interval %s\n' "$iteration" >&2
      exit 1
    }
done
printf 'Ready-to-response server counters: %s\n' "$out"
