# CI handoff: owned QUIC/TLS and native pseudo-interop

**Required CI acceptance instructions: [CI-REQUIRED.md](CI-REQUIRED.md).**

Check out `hibana-quic/` and `hibana-tls/` as siblings. The owned TLS Git
revision in Cargo.toml is immutable; CI reads it and checks out that exact
commit from https://github.com/hibanaworks/hibana-tls. The TLS workspace patch
only keeps its integration tests on its own source; product consumers use Git. Use Rust 1.95.0, the thumbv6m-none-eabi target,
Python 3 and an OpenSSL CLI. Keep build/test outputs outside both source trees.
No new remote push or CI run was performed on your behalf.

```sh
export CARGO_TARGET_DIR=/absolute/writable/output/target
OUT=/absolute/writable/output
cargo test --locked --manifest-path hibana-quic/Cargo.toml
cargo test --locked --manifest-path hibana-tls/Cargo.toml --features alloc
cargo test --locked --manifest-path hibana-quic/host/Cargo.toml
cargo test --locked --manifest-path hibana-quic/tests/tls-reference/Cargo.toml
cargo clippy --locked --manifest-path hibana-quic/Cargo.toml --lib --tests -- -D warnings
cargo clippy --locked --manifest-path hibana-tls/Cargo.toml --all-targets --features alloc -- -D warnings
cargo clippy --locked --manifest-path hibana-quic/host/Cargo.toml --all-targets -- -D warnings
cargo check --locked --manifest-path hibana-quic/Cargo.toml --target thumbv6m-none-eabi
python3 hibana-quic/tools/ci/check_dependencies.py
python3 hibana-quic/tools/ci/audit_control.py
python3 hibana-quic/tools/ci/audit_source.py --check
cargo build --locked --release --manifest-path hibana-quic/host/Cargo.toml --bin hq
python3 hibana-quic/tools/ci/run-pseudo-interop.py --binary "$CARGO_TARGET_DIR/release/hq" --output "$OUT/pseudo-interop"
```

The isolated reference workspace has necessary independent Rustls/ring/DER
oracles. QUIC, TLS, and Host (including Host tests) have no external Cargo
packages other than owned Hibana crates. Published test-vector data and system
OpenSSL are separate test inputs/tools, not a product TLS implementation.

`pseudo-interop/summary.json` records each command, exit and elapsed time plus
one actual binary SHA-256. It is same-implementation native loopback with real
UDP, actual certificates/AEAD and fault injection. It does NOT certify official
quic-interop-runner, independent Neqo QUIC compatibility or remote CI.

The external reference-workspace certificate test remains opt-in and is not
counted as passed merely because cargo skips it. The owned TLS suite includes
the actual nine-certificate runner chain and strict negative cases; the native
quiche amplification case invokes the unchanged runner certificate generator.
Follow tools/ci/local/README.md for the separate official CI environment.

## Security gates requiring your CI environment

```sh
export XDG_CACHE_HOME=/absolute/writable/output/cache
cargo +nightly-2026-10-08 miri test --manifest-path hibana-tls/Cargo.toml --features alloc --lib secret::
```

Install that nightly/Miri/rust-src in CI if absent. The fresh local secret::
Miri run passed all five selected tests after resolving an initial registry
setup failure. The current evidence log, compiler identity and scope are retained;
this does not cover every cryptographic path or all target platforms.
Read hibana-tls/SECURITY-VALIDATION.md for target timing, arithmetic-temporary
erasure, formal-refinement and independent-review limits. Local test success is
not a complete cryptographic safety guarantee or authorization to deploy.

## Why a few Clippy design exceptions remain

Large error values return actual affine key/reservation ownership without
allocation; boxing them changes the intended no_alloc API. The bounded packet
union similarly owns its storage. A few locals explicitly take independent
endpoint/resource arguments. Affine test tokens are deliberately consumed.
These exceptions are narrowly documented; correctness/authentication tests are
not disabled. In particular, a stateful HTTP/3 match arm must consume a recognized
pseudo-field even when its insertion is fresh; a side-effecting guard that falls
through changes acceptance semantics and is intentionally not used.

## Loss model and retained failed runs

The default global counter applies 30% loss/corruption in three-packet bursts
across all 50 routes. It does not bound consecutive loss for any individual
connection. A separate `--loss-scope per-connection` run applies the same rate,
burst length, delay and assertions independently to each route and direction;
it is a different model and cannot overwrite a failed global result.

Native global stress has exposed intermittent idle-expired outcomes. Retain
failed reports as well as subsequent passes. A pass is a result for that run,
not proof of guaranteed completion under arbitrary packet loss. Process exit,
file arrival, resource retirement and clean close are checked separately.

PTO STREAM selection now uses the existing accepted-publication cursor so an
outstanding FIN is not starved behind the first data range. Selection is pure;
only accepted publication advances the cursor. The regression preserves queued
ownership and verifies that probes never fabricate ACKs or loss declarations.

## Native independent-reference matrix (without Docker)

`tools/ci/run-native-reference-matrix.py` executes the catalog's 22 scenarios in
both candidate directions using separately built, unmodified Neqo and quiche.
Provide `--hq`, `--neqo-client`, `--neqo-server`, `--nss` (the NSS dist/Release
folder), `--quiche-client`, `--quiche-server`, `--runner` (the pinned runner
source for its certificate generator), and `--output` outside the source tree.
It records binary hashes and every command/result. Native UDP proxy diagnostics
are not ns-3/tshark verdicts: retain the exact native network-model differences
and failed attempts. Do not substitute same-implementation cells for missing
independent-reference results or combine different candidate binaries as one run.

A second regression reproduces retained HANDSHAKE_DONE starving an outstanding
FIN when both application PTO credits always select retained control flights.
The second existing credit now permits an actual pending STREAM/control range;
its count comes from recovery's existing reservation/acceptance bookkeeping.
Cancellation restores the credit and selection alone does not advance ownership.


## Random impairment and the periodic diagnostic

The native independent matrix now uses the distribution implemented by QNS
commit e557a54510e3578868f8c14cf3aa37e0fc6c76d0 (drop-rate and corrupt-rate):
a per-direction uniform 0..99 draw below the configured percentage, with a
forced forward after three consecutive mutations. The configured percentage is
30 for handshake cases and 2 for transfer cases. This is not a fixed three-packet
burst every ten packets. Corruption replaces one actual byte in the first 51
UDP payload bytes; Version Negotiation packets are exempt and reset the burst.
The Python RNG seed is 20261009 (the other direction uses seed+1), rather than
QNS's C++ random_device seed. This is a seeded analogue, not the same ns-3 trace.
Neither model makes per-connection delivery guarantees under aggregate loss.

The periodic diagnostic remains available, unchanged, in the direct self-peer
script. Its repeated failures are preserved. For example, a recorded route had
six 1057-byte server datagrams dropped at 2.204, 3.179, 7.927, 7.930, 17.424 and
17.425 seconds; its first such forwarded datagram arrived at 36.415 seconds,
after a client had expired at about 33.9 seconds. Packet sizes alone are not a
decryption proof, and route/file identity is not established by this metadata.
Another failed periodic native run had one quiche client receive zero packets
and expire after 30 seconds. These observations do not justify extending idle
limits arbitrarily or inventing an ACK. Exact raw failure summaries are retained.

The handshake loss/corruption official runner criteria require the fifty real
handshakes and matching files. They do not require every server to observe a
best-effort CONNECTION_CLOSE. The native harness retains the actual candidate
idle and close fields and a separate strict_lifecycle_pass, while enforcing
actual file hashes, successful independent client exits, authenticated TLS and
resource retirement. A missing file or failed client remains a failed cell.

Primary sources:
- https://github.com/quic-interop/quic-network-simulator/tree/e557a54510e3578868f8c14cf3aa37e0fc6c76d0/sim/scenarios
- https://github.com/quic-interop/quic-interop-runner/blob/740c05a10b61d65e8abd3ad38d60898004d335d9/testcases_quic.py
- https://www.rfc-editor.org/rfc/rfc9000.html#section-10

The optional client request-FIN coalescing experiment was not adopted. It was
not shown to cause or fix the observed starvation, and its shorter packet train
made one ordinal-based injection test inject no loss. The shipped Rust source
keeps the fully tested packetization, without removing that injection assertion.


Native quiche multiconnect also follows its pinned apps/run_endpoint.sh client
schedule: fifty separate processes invoked sequentially. The earlier native
attempts used fifty concurrent processes, which is an additional stronger
stress and is now explicit via --parallel-clients. Their failed results remain
retained, not reclassified as official-schedule passes. Candidate-client
scheduling remains the implementation's own concurrent schedule. Both versions
still require all fifty independent connections and every expected file.


## ACK receive-time ownership (next candidate)

`Recovery::new` now takes the locally advertised `ack_delay_exponent` as its
fifth argument (default 3, maximum 20). `Rx::apply_packet` and
`Rx::apply_application_packet` take `received_at` before `now`: the former is
the actual local observation time retained with the owned ciphertext, the
latter is the current numerical commit time. A received time later than now
rejects without changing ACK history. Old timestamps never rewind recovery.

The largest acknowledged packet owns its original timestamp; duplicates or
later lower-numbered arrivals cannot replace it. ACK delay is encoded with the
local exponent at packet construction. First short ciphertext and reordered
Handshake ciphertext carry their observation time through their existing
single-use handoff slots. No endpoint messages, phase flags or alternative
controller are added. Unknown OS/kernel delay is not invented.

A finite one-connection diagnostic drops seven actual client Handshake
datagrams and then three selected short datagrams. The preceding implementation
returned ACK delay zero for a packet held about sixteen seconds for its key;
a captured real ACK changed its smoothed RTT from about 41 ms to 2.07 s and
RTT variation to 4.07 s. This inflated its PTO and reproduced a missing file.
This establishes that finite failure mechanism, not a universal explanation
of every earlier stochastic failure.

Run the exact finite injection against a newly built binary, retaining its
JSON and exit status (the script asserts that all requested faults occurred):

```sh
python3 hibana-quic/host/tests/reproduce_key_wait.py 3 \
  --binary "$CARGO_TARGET_DIR/release/hq" --connections 1 --impairment loss \
  --loss-scope global --timeout-seconds 120 --trace-routes \
  --output "$OUT/key-wait.json"
```

The new candidate still needs its own native qualification; the earlier
44/44 result belongs to the preceding recorded binary, not automatically to
this change. The archive's verification report identifies the tested version.

## Imported repository identities

This repository imports the 20261009 paired ZIP on the current remote development
branch. TLS is published at the immutable revision in Cargo.toml and pins.env.
Hibana remains pinned to the latest development/rolled-route-ownership commit
`6fccdbf81038b00d99ec1bb2b9c43a487521628e` observed at import. All three consumer
locks use the same TLS identity. The original ZIP source IDs and file hashes
remain in `docs/handoff-20261009/`; they identify the supplied sources rather
than pretending that locally supplied commit IDs were already on GitHub.
