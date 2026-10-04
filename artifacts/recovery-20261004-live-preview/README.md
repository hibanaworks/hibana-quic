Fresh recovery evidence, 2026-10-04 UTC

Core `adea68456116df8339c76a0d7407889755ae7b87` repairs a completed descendant
selection being reused during the next rolled publication. A standalone framed
transport reproduction, independent of QUIC/TLS, failed Rust 1.95.0 release
execution at `67cbf9f0` with `offer / PhaseInvariant`. Core source-linked Lean
checks now pass eight theorems; Z3 reports four UNSAT obligations and one
historical SAT witness. These are scoped contract proofs, not Rust memory safety
or interop proofs. Original source/Lean/Z3 and failing release logs are in the
vendored `proofs/live-descendant-preview/evidence` directory.

The core workspace passes 874 tests (11 ignored), release regressions pass 22,
the new release/LTO test passes, Clippy passes, and seven subsystem size/API
checks pass. QUIC source `3db5597deccd87f9846a8c86a9edf21f9913c27a` integrates the
exact 1,238-file published core without local patches. Its real capacity-one
carrier test passes debug and release across ten publication sequences, and
all six requested checks pass in order (Rust suites 4 + 7 + 27). `commands.json`
retains actual commands, source/diff identities, environment, durations, exits,
log paths and checksums. Published Git trees were compared with local commits.

The full resource gate is **FAILED**, exit 137: route-arm case 1 uses 135 MiB
against the unchanged 132 MiB ceiling. Its isolated run passes at 132 MiB.
Causal-handoff route case 4 separately fails at 141 MiB against 129 MiB; the
unmodified `67cbf9f0` also fails at 130 MiB. Do not report all gates green or an
RSS improvement. Measured GNU runtime stack 2,519/3,663 bytes, modeled SRAM
5,218/8,954 bytes and thumb library flash 88,013/169,965 bytes are within limits.
Flash increased 157 bytes from 67cbf9f0. Comparable QUIC throughput measurements
and performance improvements remain unfinished.

Native UDP diagnosis uses the untouched pinned Neqo binary with `--qns-test`,
`hq-interop`, NSS and trusted generated certificates. Neqo/Neqo baselines pass.
The release Hibana client/server both complete a 1 KiB request against Neqo.
Both directions transfer the actual 2, 3 and 5 MiB files with exact byte equality
at a 60-second deadline, the unchanged upstream runner's default. The earlier
20-second client transfer fails its deadline after matching two files; it is
retained as a failure. The 20-second server transfer passes. JSON records keep
the binary SHA, commands, real exit codes and byte comparisons. No HTTP/3
result is claimed. Persistent Neqo baseline servers are terminated by the
harness after client completion; their termination exit is recorded separately.

**These native results are not official runner passes.** There is no simulator,
capture-based runner verdict, or substituted upstream checker in this diagnosis.
Runner `740c05a10b61d65e8abd3ad38d60898004d335d9` and Neqo
`ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95` remain unchanged. The formal matrix
has 0 passed / 0 executed / 120 target cells, 60 per direction and 40 per
repetition. Each case/direction has 0/0/3. Handshake/transfer are implemented;
18 other cases remain unimplemented and unexecuted. There are no upstream
unsupported verdicts for those cells. The earlier formal baseline failures in
the Docker routing diagnosis remain failures on their original source.

Docker recovery is blocked by OS privileges: this runtime is UID 1000 without a
privileged command runner. Official RootlessKit plus extracted uidmap helpers
fails to write `uid_map`. A private user-namespace daemon starts its API but a
real OCI container fails to create its cgroup; API health is not container
availability. Existing root-owned images/data were preserved. The actual root
recovery command is `ci/restore-local-docker.sh`: it distinguishes zombies from
live daemons and starts the original engine with `--allow-direct-routing=true`.
It was syntax-checked and its non-root refusal was executed, not represented as
a successful root restart. No GitHub Actions environment was impersonated.
After actual root recovery, use the local official runner baseline, then pilot,
then matrix. Preserve upstream tests, verdicts, comparisons and interface names.
