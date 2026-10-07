# Audited local dependency snapshots

`hibana/` is the complete tracked source at published commit
`8302a07b5f0f2d224229afdba4d0afef62d6aa2b` on
`development/rolled-route-ownership`. This descends from the previous
`c3d89f787aa1a8e066b310a5307fdf7cb076ee26` snapshot and retains the earlier
completed-descendant and containing-visit corrections. All 1,207 files and
executable modes match that Git tree, with no extras or local edits. Cargo
metadata, `ci/pins.env` and
`hibana-provenance.json` pin the exact source.

This update keeps independent active receive lanes armed during a parked
parallel offer, scans incomplete events from existing completion words, and
shares one checked immutable event row during each admission. Dependency,
conflict, reentry and lane-head checks still run on every operation; there is
no persistent eligibility cache. The final commit only corrects the optional
route-arm presence model; its Rust, Cargo and CI files match parent cf084d22.
Public API, wire format, capacity and dependencies are unchanged.

Fresh local Lean/Z3 checks pass: event admission 4 theorems / 6 UNSAT / 4 SAT,
parallel offer ingress 14 / 8 / 2, and pending-event scan 7 / 4 / 2. These
scoped models do not establish a whole-Rust refinement or QUIC interop proof.

QUIC retains the publication regression and four actual capacity-one
carrier tests: retained-sample failure ACK, premature switch rejection,
duplicate ACK rejection and right-par-lane-first reentry. The requested local
wire/full-connection/host suites run separately from those contract traces and
from native Neqo diagnosis. A new delayed-parallel-offer test uses the actual
capacity-one QUIC carrier, cancels each owned preview, then receives and ACKs
all six payloads without duplication. Upstream CI runs 37664144837 (parent)
and 37668496444 (selected SHA) were both confirmed successful. Fresh consumer
evidence and remaining limits are recorded in RECOVERY-STATUS.md.

The earlier three immutable metadata lookup optimizations have pre-implementation Lean
and Z3 evidence, differential tests, and passing upstream Kani/final-form CI:
https://github.com/hibanaworks/hibana/actions/runs/37052293598 . Their proof and
measurement artifacts are retained inside the upstream snapshot. This update
is historical evidence for that earlier revision. Consumer runtime and
compile-capacity checks on the current revision are recorded separately.

The prior base-plus-local-patch snapshot and its provenance are retained under
`artifacts/upstream-history/`; original reproduction, pre-fix Lean+Z3 chronology,
patch, unmodified old-base archive and test evidence remain in
`artifacts/hibana-offer-repro/`. The correction was proved before implementation.
These scoped semantic/selector models are not a machine-checked Rust refinement
proof. Original MIT/Apache notices are unchanged. New consumer tests on the
selected upstream revision are recorded separately from historical results.

`rustls-webpki-0.103.15/` retains the pinned upstream ISC crate with one explicit
bounded depth change, six to eight intermediate certificates. See
`webpki-provenance.json`, its patch and `artifacts/webpki-depth8/` for provenance,
constraint tests, allocation measurements and stack-cost limitations. This is a
direct dependency of the bounded backend; the separate reference Rustls backend
continues to resolve its ordinary registry dependency.
