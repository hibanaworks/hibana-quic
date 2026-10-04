# Historical recovery log

This is historical evidence, not current status. See [the active implementation](docs/ACTIVE-IMPLEMENTATION.md) for current results and remaining work.

# Recovery status

This is source preservation after execution storage was replaced around 2026-10-03 06:18 UTC. Reconstructed source is unverified and incomplete. No current successful build or interoperability claim is made.

Published unchanged baselines remain available:
- QUIC historical checkpoint: d086180079866d83c01ddaef254834ac2e738eb9
- Qualified integrated Hibana: e75d413bb3c3adc6e61ba92f267bd14795d8525e
- Core CI passed: https://github.com/hibanaworks/hibana/actions/runs/37099834655

Before storage loss, a direct-role handshake prefix completed IPv4/IPv6, wrong-hostname/CA rejection and client-to-Neqo authenticated TLS. Original binaries and local logs are unavailable. Those outcomes do not validate reconstructed files. Application transfer and formal runner qualification were not complete.

Restoration must retain the new choreography/local-role design. Legacy Driver, HandshakeEndpoint, TransportEndpoint and the old HQ central loop are not a runtime fallback. Unchanged packet, TLS, cryptographic and numerical kernels may be restored from public history without reintroducing old control.

Open correctness/integration work:
- actual affine prefix-to-application edges in one combined global
- file/stream transfer, ordinary-publication cancellation and close/drain retirement
- exact Initial retirement on client accepted Handshake send/server authenticated Handshake receive
- outstanding Handshake recovery carried into application so lost Finished ACK can be resolved by HANDSHAKE_DONE
- bounded RX work/yields and explicit profile capacity failure
- fresh build, allocation, authentication, cancellation, loss and actual Neqo/runner tests

Numerical/TLS adapter bodies and the connected runner have now been reconstructed. They have not been compiled. Initial retirement role wiring and API reconciliation remain incomplete. Legacy endpoint tests/targets and dead role bridges need final migration/removal before validation.

## Subsequent reconstruction, awaiting first fresh compilation

The current working source now contains the finite Initial-retirement roles, retained Handshake recovery, one affine connected startup, parallel application roles and post-retirement close/drain. The primary host file mode invokes that connected global. Five real-TLS connection tests cover single/multiple transfers and actual authenticated confirmation/ACK loss. These are source-only test bodies, not passing results. Adapter rejection currently terminates the prefix after cancelling its reservation; retry semantics remain unqualified.

The dedicated recovery compile diagnostic records interoperability as NOT_RUN. The standard runner path retains its existing checks and requires the diagnostic marker to be removed.

## First reconstructed-source compiler result

GitHub run 37113879862 checked source29569a5 using official pinned Rust1.95. Source audit passed; compilation failed on four library borrow/lifetime diagnostics and one test error-type inference site. See artifacts/reconstruction/compile-29569a5.json and its source-only compiler log. Runtime tests and interoperability remain NOT_RUN. Subsequent fixes require a fresh compiler run.

Source c8a1809 passed both Rust1.95 cargo-check stages in run37114351857. The next diagnostic stage runs application_wire, connected_application and host hq runtime suites with unchanged assertions/default stack limits. Formal interoperability remains NOT_RUN until the recovery-diagnostics marker is removed.

Run37115827016 on74280de passed type checking but failed code generation when Hibana evaluated the complete choreography: a receive-lane sender change lacks an explicit causal handoff. No runtime tests executed. The global/local capability flow is being corrected; this is not classified as a Hibana core defect.

The next ownership-flow patch replaces the missing handoffs with actual key/Finished/retirement capability transfers. Two source-level Python ports now agree on173events/306markers/4lanes and zero modeled receive-causality violations. This is not a Rust validation or runtime pass. Capacity-one progress and all existing execution assertions remain mandatory.

## Fresh Linux recovery validation, 2026-10-03

The checkout was cloned from GitHub at `9d545bcac7790ad372ba30ba082114c3a2d1702f`.
All results below came from freshly compiled source in this environment, using
Rust 1.95.0; no pre-loss binary or measurement was reused. Safe command records,
logs, source/tree identity mappings and the case/direction/repetition table are
in `artifacts/direct-recovery/20261003/`. Raw runner data remains outside Git.

At published source `02efcac40b85adc165c63e61b758a4afd4ca406f`, the six requested
commands, in order, all exited zero: source audit, the two Python models,
`application_wire` (4 tests), `connected_application` (7), and host `hq` (27).
These Rust suites completed const projection, code generation and execution.
The Python models retain their narrower source-model meaning. Additional direct
connection tests passed 37/37; no-allocation, TLS Initial-prefix and directional
packet-role integration tests passed 13/13 at the recorded source identities.

The original connected fixture overflowed the default test stack. Host fixture
slabs and separately pinned peer futures now live on the host heap, preserving
their capacities and the core's caller-owned, no-alloc storage. Its advertised
receive windows now match backing storage, and client/server peer-stream quotas
reflect their actual roles. Existing loss, FIN, acknowledgement and close
assertions remain. New regressions cover rejecting unbacked credit and opening
three client-initiated streams. The application cancellation fixture's receive
credit was similarly corrected; its allocation/ledger assertions remain.

Hibana was integrated as the exact upstream archive at
`67cbf9f0a57fe89a8486766456a769b646f2a3e1`, including the nested resolver repair,
proof sources and manifests. Pins and provenance agree, and no vendor source
patch is present. Nested resolver regressions passed 8/8, the core workspace
tests and clippy passed, and the controller-offer contract passed 13 Lean
theorems, nine expected Z3 UNSAT checks, two SAT old-behavior counterexamples,
and ten source-hash checks. These results do not prove QUIC interoperability.

Qualification is incomplete. In this environment the unchanged core resource
gate exits 137: `route_arm_heavy_1` reaches 135 MiB against its 132 MiB budget.
The e75 baseline passes the same gate at 130 MiB under the same conditions.
The limit was not increased. Broad QUIC `--all-targets` still exits 101 on
`early_owner_no_alloc` long-running const evaluation. Broad library tests also
encounter an early-owner retirement receive `PhaseInvariant` and a path-owner
pending-cancellation default-stack overflow. The retirement failure was
reproduced individually. No assertion or compiler/stack limit was relaxed.

### Official runner: no interoperability pass

Runner `740c05a10b61d65e8abd3ad38d60898004d335d9` and Neqo
`ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95` remain unchanged. Docker 28.4/API 1.51,
Compose 2.40.3 and tshark 4.6.4 were verified, including the actual required
simulator interface names/addresses. The fresh Neqo build uses the pinned
upstream NSS inputs/build flags; its chef image's Rust version is recorded
separately from the QUIC Rust 1.95.0 builds.

The latest normal Neqo/Neqo baseline ran handshake and transfer: 0 passed,
2 executed, 2 failed. An earlier four-cell candidate diagnosis using the
unchanged official cases also yielded 0 passed/4 executed/4 failed. Its source
was local `4891519`, published with the identical tree as `5fb48d54`; the failed
baseline means it is not environment qualification. No actual file comparison
passed. No HTTP/3 result is claimed.

The 20-case x two-direction x three-repetition formal matrix was **not run**:
0 passed/0 executed/120 target cells, 60 per direction and 20 per repetition.
Endpoint capabilities are a separate axis: handshake/transfer are implemented;
the other 18 cases are not implemented. No upstream unsupported verdict was
obtained for those unexecuted cases.

Two causes were isolated. Hibana's server did not answer the simulator's small
unknown-version WAIT probe; stateless Version Negotiation now reverses the real
CIDs, advertises v1 and respects the amplification bound. A real UDP regression
passes, but this change has not been retested with the official runner. Also,
Docker 28.4's per-endpoint `raw PREROUTING` rule drops cross-network packets
before the simulator. The minimal reproduction observed one 1280-byte DROP;
an unassigned destination and same-bridge UDP/GSO control experiments pass.
The required daemon setting is `allow-direct-routing=true`; upstream tests,
verdicts and file comparisons were not changed.

Docker is currently stopped. The local restart helper incorrectly used
`kill -0` as a liveness check, mistook the terminated dockerd's zombie PID 198
for a running daemon, and refused to launch its replacement. This is a recovery
procedure error. The agent has no remaining root command runner; root recovery
was requested. Source, images, builds and logs remain on disk. Resume by
starting the original daemon with `--allow-direct-routing=true`, then rebuild
the candidate at a clean current SHA and run `ci/run-local-interop.py` in matrix
mode: it gates candidate pilot and matrix execution on a passing Neqo baseline.
Do not kill a replacement daemon based only on the old zombie PID.

The five source commits have been published through GitHub's Git data API and
their trees verified against the locally tested commits. The core integration
branch is published at 67cbf9f0. Main was not merged. Comparable QUIC performance
measurements and performance improvement remain uncompleted.

## 2026-10-04: completed descendant preview correction and fresh native diagnosis

A core defect was isolated without QUIC or TLS: a completed roll descendant
selection was previewed as live when a fresh poll selected a different arm.
Rust 1.95.0 release execution failed with `offer / PhaseInvariant`. Hibana
`adea68456116df8339c76a0d7407889755ae7b87` repairs the preview using the existing
completion predicate, while preserving rejection of live conflicting evidence.
Eight source-linked Lean theorems and four Z3 UNSAT obligations pass; one old
SAT witness is retained. Core workspace tests pass 874 (11 ignored), release
regressions pass 22, release/LTO and Clippy pass. These scoped proofs do not
certify the whole Rust implementation or QUIC interoperability.

QUIC `3db5597deccd87f9846a8c86a9edf21f9913c27a` vendors the exact published core
with no local patches, adds the actual capacity-one carrier regression (debug
and release pass), records bounded failure context, and passes all six requested
local checks in order, including code generation/execution (4 + 7 + 27 tests).
Both publication-only and the combined global are exercised; no storage limit,
assertion, compiler or stack limit was raised.

Fresh release native UDP diagnosis against the pinned Neqo confirms handshake
with a real 1 KiB file in both directions. At the upstream default 60-second
deadline, both directions also compare the actual 2/3/5 MiB files exactly after
passing Neqo/Neqo baseline. The prior 20-second Hibana client transfer timeout
(two files matched, third incomplete) remains a failure; the opposite 20-second
transfer passed. These are local diagnosis results, **not official runner
passes**, and not HTTP/3. The formal 120-cell matrix remains 0 passed/0 executed:
60 target cells per direction, 40 per repetition, 3 per case/direction.
Handshake/transfer are implemented; 18 other cases remain unimplemented and
unexecuted. There is no upstream unsupported verdict for unexecuted cells.

Resource validation is not fully green. The full unchanged gate still fails
route-arm compiler RSS at 135/132 MiB (isolated run passes at 132 MiB). A separate
causal-handoff route check fails at 141/129 MiB; unmodified 67cbf9f0 also fails
that check at 130/129 MiB. Measured stack 2,519/3,663 bytes, modeled SRAM
5,218/8,954 bytes and flash 88,013/169,965 bytes remain within their limits.
Flash increased 157 bytes. Comparable QUIC performance measurement and
performance improvement remain incomplete.

Docker restoration was attempted through genuine RootlessKit/uidmap and a
private user-namespace daemon. The former cannot write uid_map; the latter can
serve the Docker API but cannot start a real OCI container because cgroup
creation is denied. The session has UID 1000 and no OS-root command runner;
reinstalling binaries under that UID does not restore those privileges.
Root-owned Docker data/images remain preserved. `ci/restore-local-docker.sh`
is the concrete actual-root restoration procedure, including direct routing
and zombie-aware liveness checks. It was syntax-checked and exercised for its
non-root refusal. The original `/var/run/docker.sock` remains unavailable.
After actual root restoration, run the unchanged official Neqo baseline,
candidate pilot, then matrix; no runner checks or environment predicates were
weakened. Commands, exits, source identities, failure logs and native byte
comparisons are preserved under `artifacts/recovery-20261004-live-preview/`.
