# 8302a07b integration: fresh QUIC execution evidence

Selected core: `8302a07b5f0f2d224229afdba4d0afef62d6aa2b` on
`development/rolled-route-ownership`, tree
`efcab392330bd331487f4b570a062a6db06a0881`. All 1,207 files and executable
modes match upstream; no local patch is present. Root and host Cargo metadata
each resolves one Hibana package from this snapshot. Pins/provenance agree.
The initial worktrees were clean; the original core checkout remains at
`adea6845`, and verification uses a separate detached worktree.

Published QUIC code: `064af9affb112f20699497d0b5f4faa6ddd6ebc7`, tree
`386d6c27d4d28fb5d96c288fa5f622a07c8b276f`, identical to local code commit
`b0f82f2beede671aba3927a03ab6d066c263ab8f`. Git data API commit metadata
differs; the full tested tree was verified. Tests ran before publication with
the recorded base commit plus working changes. The native candidate runs
execute the freshly built binary from a clean published code checkout.
This subsequent evidence commit adds docs/logs without executable changes.

## Change and scoped contract evidence

The selected ancestry retains previous route/roll/par/offer repairs. The
parallel-offer correction polls independent active receive lanes while the
selected scope awaits physical ingress. Pending-event scanning uses existing
completion words. Event admission shares one checked immutable LocalEventRow
for identity/next/dependency/conflict; dependency, conflict, reentry and
lane-head checks still execute on each operation. No public API, persistent
flag, eligibility cache, FSM, transport wrapper, wire format, capacity or
dependency was added. QUIC's production source itself was not rewritten.

The final 8302 commit is proof-only: Rust/src, Cargo and .github match parent
`cf084d22a473b26c8cd0b8be80631eaf3e7184b4`. It explicitly models optional
route-arm presence. The source comparison/snapshot audit establishes source
identity; execution and proof evidence are separate below. No string/path
scan is presented as behavioral proof or a CI substitute.

Fresh local replay uses Lean 4.30.0 and Z3 4.16.0, all exit 0:

| Contract | Lean theorems | Z3 UNSAT | Z3 SAT |
| --- | ---: | ---: | ---: |
| Immutable event admission | 4 | 6 | 4 |
| Parallel offer ingress | 14 | 8 | 2 |
| Pending-event scan | 7 | 4 | 2 |

The four event-admission theorems depend only on propext. Other actual axiom
inventories are preserved in their logs. Models retain live observations,
full-key matching, missing-row and invalid-lane rejection, and the later
admission's current checks. They are scoped contracts rather than a proof of
all Rust effects or QUIC interop. `option-mutations/result.json` records both
detected mutations: ignoring presence turns check 4 SAT; comparing unused
None payload turns check 10 UNSAT. Replay from the repository root with:

```sh
python3 artifacts/recovery-20261008-event-admission/option-mutations/reproduce.py \
  vendor/hibana/proofs/event-admission/Admission.smt2 /tmp/hibana-option-mutations
```

Upstream CI 37664144837 (parent) and 37668496444 (selected SHA) were both
confirmed `completed/success` via GitHub. This is updated observed evidence;
the delegation's earlier in-progress status is superseded. Broader upstream
Miri, release-integration and full Lean-corpus checks are upstream evidence,
not a claim of fresh execution of those suites in this consumer task.

## Local code generation, runtime and pre-fix reproduction

Rust is 1.95.0. `commands.json` contains 22 captured local commands, source
commit, working diff hash, environment, duration, real exit and log hash.
All six originally requested commands execute in order with exit 0: source
audit, Python causality model, finite Q=1 model, application_wire (4),
connected_application (7), host hq (27). Rust code generation/const evaluation
and 38 actual tests complete. Python success is recorded separately.

Broad QUIC library/all-targets suites were not rerun for this SHA. Earlier
recorded early-owner const-evaluation/retirement and path-owner stack failures
therefore remain unqualified by this focused result. The complete core Lean
corpus and Miri were not replayed locally in this consumer task.

The six capacity-one tests pass in both debug and release/LTO: existing
publication (1), nested visit (4), delayed parallel offer (1). The new test
uses the actual `CarrierStorage<1,32,128>`, a 64 KiB caller-owned slab, the
existing QUIC join/yield executor, projected global and directly written local
send/recv/offer. It delays each of six payloads for five executor turns,
drops the first owned preview, receives it on the next offer, ACKs each value
exactly once, and completes Done/Closed/Retired with an empty queue. The
128-poll bound and real-wake assertion are retained from the upstream trace.

With identical test SHA256
`38694939d4e2344ea92358e60f926e86c53ef91e9239f03b803da2426cfc4c6f`
and the exact previous C3 core on QUIC commit `0b97fc6`, the test exits 101
at the real-wake assertion: peers are parked without a registered wake.
The old source remains in the isolated `hibana-quic-pre-offer8302` worktree.
The new source passes without changing the assertion or transport capacity.

Fresh local core lib tests: 479 passed, 8 existing ignored. The two actual
cursor event-admission tests (identity mismatch without mutation and a fresh
admission after predecessor commit), and the upstream delayed-offer test,
also pass. Core workspace strict Clippy exits 0. QUIC strict Clippy exits 101
on the same 51 existing production diagnostics; default warning-mode Clippy
exits 0 and reports no diagnostic in the new test. No lint/assertion was
suppressed. Compiler and stack limits were not raised.

## Resource limits and performance

The exact current upstream final-form/compile-pressure gate exits 0. Actual
stack is 2,503/3,663 bytes, modeled SRAM 5,202/8,954 bytes, thumb rlib flash
96,826/169,965 bytes, and no-default thumb build passes. Flash is 650 bytes
smaller than the previous C3 observation; this is an artifact observation,
not a QUIC runtime performance improvement claim.

Compile-pressure budgets are unchanged from the prior C3 integration, which
already included upstream's documented four RSS baseline recalibrations.
Comparison of actual new measurements against unchanged adea ceilings still
fails causal_handoff_route_4 (131 > 129 MiB) and causal_handoff_roll_4
(130 > 129 MiB). Route-arm-1 samples 132 MiB against 132 MiB. This legacy
comparison is not a second execution of the full gate, and a sampled maximum
is not an exact high-water mark. See `resource-legacy-comparison.json` and
the raw current gate log. No comparable QUIC throughput/latency benchmark was
run; performance improvement and qualification under old RSS ceilings remain
uncompleted.

## Actual Neqo traffic and unexecuted formal cells

Pinned Neqo remains `ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95`, runner
`740c05a10b61d65e8abd3ad38d60898004d335d9`. Native Neqo/Neqo baseline first
passes handshake and transfer (2/2). Its commands execute Neqo only; the
helper's recorded hq hash is incidental and the baseline does not execute
the older hq binary.

Fresh release hq SHA256:
`02de1e2e8de0d7623c92d2e0eede69cc41c2371e4b966130c3d5d7a01a1fe790`.
With clean source `064af9af`, Hibana client to Neqo server and the reverse
each pass handshake and transfer: 4/4, all client exits 0, actual byte equality
for the 1 KiB handshake fixture and 2/3/5 MiB transfer fixtures. The deadline
is 60 seconds. Each `native-*.json` preserves exact commands/source/binary
hash and every file's size/equality. Neqo persistent server -9 is harness
teardown after success; Hibana server exits 0. Raw logs/fixtures remain at
`/workspace/interop/native-8302-20261007T192930Z`; keys/raw traces are not
published. Fixtures were reused, but binaries and measured results are new.

This is **native hq-interop diagnosis**, not official runner or HTTP/3 success.
The managed local socket check exits 1: `/var/run/docker.sock` is absent,
UID is 1000, and the session has no OS-root command runner. Prior genuine
rootless/user-namespace startup failures remain recorded separately. Real
Docker restoration (`ci/restore-local-docker.sh`) and a passing unchanged
official Neqo baseline are required before pilot/matrix. No runner assertion,
file comparison, interface requirement or verdict was changed; no GitHub
Actions environment was impersonated.

For this source: **0 passed / 0 executed / 120 target** formal cells. Both
directions are 0/0/60; each repetition is 0/0/40; each case-direction is
0/0/3. All cases/directions/repetitions are enumerated in `formal-cells.json`.
Handshake/transfer are implemented (12 target cells), the other 18 cases
unimplemented (108 cells); no upstream UNSUPPORTED verdict or new formal
failure exists for these unexecuted cells. Main was not merged. No subagent
or sound-producing check was used.
