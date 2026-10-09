# Historical record — not current status

Preserved from the pre-organization snapshot. Dates, source paths, dependencies
and qualification claims below describe their original revisions only.
See [current status](../WORKING-STATUS.md).

# Work-in-progress snapshot

This branch preserves unfinished repository cleanup and dependency work. It is
not a new release or a qualified interoperability result.

- Base: `593e78d1202d821328702effd5f81e4d757f6a99`.
- Base normal CI passed; official interop ran 44 candidate cells, 43 passed.
  Client handshakeloss failed on that published baseline. No reference self-tests are required.
- Repository organization and manifest paths changed; documentation/link cleanup
  and full regression verification are still in progress.
- Hibana is now a Git dependency pinned to `8302a07b5f0f2d224229afdba4d0afef62d6aa2b`.
  The copied Hibana tree is removed. All three manifests/locks/pin agree.
- Project-owned SHA-256 RSA encoding checks replace the extracted RSA helper copy.
  Nine corpus/zero-allocation tests passed. Six Lean layout/acceptance lemmas
  compile; these are not a Rust refinement or cryptographic security proof.
- Webpki's explicit depth-eight patch is still vendored. Other crypto crates
  remain dependencies. The zero-external-dependency goal is not complete.
- Python 87 tests, source inventory and removed-controller guards passed locally.
  Core and Pico regression checks passed after the moves. The independent TLS
  reference suite passed 55 tests, with one existing private-runner-fixture test
  ignored. Host and final whole-tree checks remain part of qualification.
- A separate hibana-tls project is being developed; it is not integrated yet.
  Do not substitute its initial building blocks for the working TLS endpoint.

Future publication must repair stale document links and all test/tool paths,
then requalify the exact new commit. Git history retains removed historical logs;
raw packet captures, TLS secrets and private keys are not part of this snapshot.

## Local ACK-feedback candidate

Initial PTO packets now carry retained, authenticated receive ranges when space
permits, including received ACK-only packets. This does not schedule ACK-only
responses to ACKs, add PTO credits, reset backoff or change completion rules.
The focused regression failed before the change and passes after it, including
preserving a later pending ACK when an older snapshot is physically accepted.

With the same pinned native quiche peer and combined loss policy, local base
`db10b09` failed at 300.024 seconds; the candidate transferred and verified the
file at 53.989 seconds. This is a native controlled reproduction, not the
original ns-3 simulator or a new official 44-cell qualification. All 591 core
tests and the thumbv6m check passed; the new exact-commit remote run is pending.

## Dependency reduction

The runtime no longer depends on futures-util. Its five associated packages
also disappear from all three lock files without unrelated version changes.
Existing fixed-capacity TaskSet scheduling and caller-pinned role futures are
used directly; heterogeneous results are retained in fixed local storage.
Hibana endpoint exchanges remain in their role locals. The core suite passed
594 tests and thumbv6m checking passed. The host suite passed 123 tests. The native combined-loss reproduction also
passed after this change (53.917 seconds, matching file). The independent reference suite passed 55 tests (one private-fixture case
ignored), and its all-targets strict Clippy check passed. Seventeen non-Hibana direct dependencies
remain; this is not zero-external-dependency completion.

## Remaining choreography audit

The legacy `BoundedTls` still stores `State` and key-created, key-discarded and
key-handoff flags. Their generation/retirement checks must be replaced by actual
owned material and projected local continuations before claiming that all
protocol progression state has been eliminated. Do not simply delete fail-closed
checks and thereby permit duplicate key generation or handoff.

The new runtime join helper collects future outputs only. It contains no
endpoint exchange or protocol-phase choice; communication remains visible in
the supplied role locals. This does not resolve the legacy TLS flags above.

### Completion-exchange design probe

A minimal four-role experiment rejects an early request for completion: at
queue capacity one, delaying the peer Finished by eight scheduler yields leaves
that request occupying capacity needed by Finished. The initial no-delay pass
was insufficient. This is a candidate-graph counterexample, not evidence of a
Hibana implementation defect.

The revised experiment writes Finished -> Verified -> Completion directly in
the global sequence and sends Completion from the verification local without
an early query. It passes all 24 task placements with peer delays of 0, 1 and 8
yields (72 cases) at the same queue capacity. The fixture is
`tests/transcript_completion.rs`. These finite schedules are not a liveness
proof. Integration into the real transcript, preserving live ACK/PTO work while
awaiting completion and testing lost Finished, remains unfinished. No production
State or key flag has been removed by this probe.

### Projected transcript completion integration

QUIC's transcript source no longer queries `BoundedTls::state() == Connected`.
The receive local sends `TranscriptComplete` only after the real TLS owner
continuation; a distinct projected completion endpoint is polled alongside
retained source exchanges. Arrival wakes a TX parked after Idle before waiting
for the outstanding Request/Taken cycle. That exact cycle is settled rather
than cancelled, then remaining generated output is drained. No stored completion
flag, synthetic acknowledgement or new protocol dispatch wrapper was added.
This removes one external progress predicate, not all legacy TLS flags.

Verification of this change: 469 library tests, 72 other integration tests,
28 connected-application tests and 26 documentation tests passed (595 total,
run in separate groups), plus thumbv6m checking and a native host build.
Native IPv4/IPv6 authenticated prefixes and wrong-name/untrusted-CA rejection
passed; the Python fixture now checks the actual certificate failure reason
rather than a stale error wrapper spelling.

The first integration attempt parked after a received completion while waiting
for the next Request. Its regression was fixed by waking the existing scheduler
from the actual received event before settling the owned cycle. The unchanged
one-request loss sweep also exposed an absent 16th server datagram after the
wire schedule changed. Positive loss injection remains mandatory: the revised
sweep covers one request at ordinals 1..15 and three requests at 1..16, each with
burst lengths 1..3 (93 cases). Capacities and time budgets are unchanged. This
local coverage expansion does not modify or qualify the official interop runner.

The prior exact native quiche combined-loss result is historical, not rerun for
this new completion integration. No new remote publication or CI result is
claimed. Core all-targets strict Clippy and complete cryptographic security
qualification are not claimed by these checks.

### Authenticated handoff owns its evidence

The QUIC Finished handoff no longer adds a historical Connected-state test.
KeySource exposes authenticated transport parameters only while it owns the
actual verified Finished receipt. After transfer, its recipient owns the
receipt and copied parameters; the old source cannot re-authorize the handoff.
Fatal source checks use the retained Failure object rather than its duplicated
Failed-state label. No new phase flag or communication wrapper is introduced.
The no-allocation handoff test additionally checks that insufficient output
capacity preserves the exact receipt for a subsequent adequate buffer, and that
a second successful transfer is rejected. All 595 core/integration/doc tests
passed on this change. Legacy BoundedTls State/key flags and external crypto
dependencies still remain; this is not their complete elimination.

### Remove outward phase forwarding

The owned KeySource no longer exposes state()/is_handshaking(), and QUIC's
Transcript no longer forwards state(). Tests now inspect actual retained
Finished evidence, actual Failure objects and successfully returned connection
continuations. The legacy BoundedTls implementation still has its internal
State/key flags; removal of these three outward APIs is not their elimination.
595 core/integration/doc tests, Host 123, independent reference 55 (one existing
private-fixture case ignored) and thumbv6m checking passed for this change.
The QUIC-only shared-global/key/Finished integration requirements are now recorded
in TLS-INTEGRATION.md. Actual separate-crate integration is the next step.
