# C3 containing-visit integration: fresh consumer evidence

The tested code was published as `64a7a09cb27f30336520818c66d51e93c65a0343`,
tree `80c617f72dfc48c7e81a2afbf8e5ac939e18cd47`. The GitHub commit has the
same tree as local `bc061849ebf3c773c883190041012359e7a93437`; Git data API
commit metadata differs. Tests ran on the preceding commit plus the recorded
working changes, before publication. This evidence commit adds documentation
and logs without changing executable source.

The exact Hibana snapshot is
`c3d89f787aa1a8e066b310a5307fdf7cb076ee26`, branch
`development/rolled-route-ownership`, tree
`1b15c051557ae740cdb7c92f4e709765781d5561`. All 1,193 tracked files and
executable modes match upstream. Root and host Cargo metadata each resolve
one Hibana instance from this snapshot; pins and provenance agree. There are
no local vendor patches. Initial QUIC and core worktrees were clean; the
original core checkout was preserved and the selected core tested in a new
detached worktree. The preceding `adea6845` fix remains in this ancestry.

## Local Rust and contract validation

`commands.json` preserves command, environment, source commit, working diff
hash, exit, duration and log digest. Rust is 1.95.0. Compiler and stack limits,
carrier capacity, assertions and upstream proof expectations were unchanged.

| Check | Result / exit |
| --- | --- |
| Six requested commands in their specified order | all six 0 |
| application_wire / connected_application / hq | 4 / 7 / 27 passed |
| Existing Q=1 publication trace, debug and release/LTO | 1 passed each / 0 |
| New nested_visit_carrier, debug and release/LTO | 4 passed each / 0 |
| Core nested_input_roll_ regressions | 4 passed / 0 |
| Core workspace strict Clippy | 0 |
| QUIC strict Clippy | 101: 51 existing production Clippy diagnostics |
| QUIC default Clippy with JSON diagnostic inspection | 0; no new test diagnostic |

The four new tests use QUIC's actual `CarrierStorage<1, 32, 128>` with the
existing 256 KiB caller-owned storage fixture, projected global choreography
and direct async local sides. They exercise retained connection prefix across
sample/failure arm changes, early switch rejection, duplicate ACK rejection,
and right-par-lane-first reentry. No endpoint or legacy driver wrapper was
introduced. Release uses the repository's existing LTO profile.

The unchanged first test on exact pre-fix core
`12383a07f7a198031762e3092f6de0e72d8ee68f` exits 101: after one retained
sample, `receiver.send::<FailureRetained>(&1)` is rejected with
`send / PhaseInvariant`. The zero-sample control passes before this failure.
The same test source SHA256 is
`f32a91b5255b8c000d60e3923594d9bf87fdfcc52dc19ab9727130ca49b3b047`.
See `pre-fix-core.json` and `c3-old-core-q1-repro-1.log`. The test does not
change between the failing and passing snapshots.

Fresh `bash proofs/rolled-route-ownership/check.sh` in the exact core
worktree passes (exit 0), Lean 4.30.0: nine supplemental Lean files and Z3
18 UNSAT / 26 SAT. The newly requested NestedVisit part has twelve Lean
theorems, using existing kernel/propext only, and four UNSAT / four SAT
checks. Full replay logs are under `proofs/`; the new theorem/solver logs
also appear at this directory's top level. These scoped contracts and
canonical histories do not prove the whole Rust implementation or QUIC interop.
The delegation's broader workspace/Miri/Pico/709+506-proof results remain
upstream-reported evidence; this consumer task did not rerun all those checks.
Upstream CI 37396155673 is still in progress at the recorded inspection.

## Resource and performance limits

The exact current upstream final-form resource gate exits 0: measured stack
2,503/3,663 bytes, modeled SRAM 5,202/8,954 bytes, thumb rlib flash
97,476/169,965 bytes, and the no-default thumb build passes. Flash is 9,463
bytes larger than the previous snapshot's 88,013-byte observation.

Upstream's snapshot includes RSS observation updates, documented in
`vendor/hibana/.github/measurement_snapshots/compile-pressure-observations.md`.
Four RSS budgets changed: route_arm_heavy_1 132 to 250 MiB, causal_handoff_4
129 to 259, causal_handoff_route_4 129 to 257, causal_handoff_roll_4 129 to
247. These are upstream changes, copied exactly, not new consumer overrides.
The **comparison to the unchanged previous ceilings fails**: measured
route_arm_heavy_1 134 > 132, causal_handoff_route_4 131 > 129, and
causal_handoff_roll_4 130 > 129 MiB. See `resource-legacy-comparison.json`.
The new gate's success therefore does not resolve qualification under those
old ceilings. No performance improvement is claimed. Comparable QUIC
throughput/latency measurements remain uncompleted.

## Fresh Neqo diagnosis and formal matrix

Runner revision remains `740c05a10b61d65e8abd3ad38d60898004d335d9`; Neqo
remains `ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95`. Newly built release hq
SHA256 is `78bb47952075d03f8eb6537a8ee71c2c7bfb9f29f62965166d2f8dc460d87a76`.
Native loopback diagnosis first passes Neqo/Neqo baseline 2/2, then each
candidate direction passes handshake and transfer (4/4 total). Client exits
are 0. Actual downloaded files compare equal: handshake 1 KiB; transfer
2, 3 and 5 MiB at a 60-second deadline. Six `native-*.json` records contain
exact commands, source identity, file sizes and byte-comparison results.
The persistent Neqo server's -9 exit is harness teardown after successful
client completion; Hibana server exits 0. Raw logs/keys/certificates remain
outside Git under `/workspace/interop/native-c3-20261006T010114Z`.

These are hq-interop native diagnoses, **not official runner verdicts** and
not HTTP/3. The original Docker socket is unavailable, and the diagnostic
user-namespace daemon cannot create actual OCI containers (cgroup denial).
The session lacks an OS-root command runner; the previous concrete recovery
script remains `ci/restore-local-docker.sh`. No test, comparison or verdict
condition in the pinned runner was changed. No GITHUB_ACTIONS impersonation
was used. Formal baseline/pilot/matrix must resume only after real Docker
recovery, using `ci/run-local-interop.py`.

For **this C3 source** official counts are 0 passed / 0 executed / 120 target
cells; no new formal failures or unsupported verdicts were produced. Each
direction has 0/0/60, each repetition 0/0/40, each case-direction 0/0/3.
All 20 cases in each of repetitions 1, 2 and 3 remain unexecuted in both
directions. `handshake` and `transfer` are implemented (12 target cells);
the other 18 cases are unimplemented (108 target cells). This implementation
status is not an upstream UNSUPPORTED verdict. Previous formal environment
failures remain historical failures, not C3 results.

`formal-cells.json` enumerates every case, direction and repetition, with
separate execution and implementation status. A -9 native server teardown
is not entered into the official matrix. Main was not merged.
