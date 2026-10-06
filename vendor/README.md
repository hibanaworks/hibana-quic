# Audited local dependency snapshots

`hibana/` is the complete tracked source at published commit
`c3d89f787aa1a8e066b310a5307fdf7cb076ee26` on
`development/rolled-route-ownership`. This descends from the previous
`adea68456116df8339c76a0d7407889755ae7b87` snapshot and retains its completed
descendant preview correction. All 1,193 files and executable modes match that
Git tree, with no extras or local edits. Cargo metadata, `ci/pins.env` and
`hibana-provenance.json` pin the exact source.

The new repair preserves an enclosing connection prefix when only its inner
rolled route enters a fresh visit. Prepared reset bounds use the real
descriptor/lane head; retained ancestors keep their arm. Public API, stored
state, wire format, capacity and dependencies are unchanged by this repair.
`hibana/proofs/rolled-route-ownership/NestedVisit.lean` has twelve scoped kernel
theorems; its Z3 companion has four UNSAT obligations and four SAT premises.
Fresh local replay of the whole supplemental runner passes nine Lean files and
18 UNSAT / 26 SAT results. These are scoped models and canonical histories.

QUIC retains the publication regression and adds four actual capacity-one
carrier tests: retained-sample failure ACK, premature switch rejection,
duplicate ACK rejection and right-par-lane-first reentry. The requested local
wire/full-connection/host suites run separately from those contract traces and
from native Neqo diagnosis. CI run 37396155673 was in progress on initial
inspection; a prior core test result or prior interop result is not a new result
for this snapshot. Fresh consumer evidence is recorded in RECOVERY-STATUS.md.

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
