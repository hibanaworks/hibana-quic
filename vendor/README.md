# Audited local dependency snapshots

`hibana/` is the complete tracked source at published commit
`adea68456116df8339c76a0d7407889755ae7b87` on
`fix/elastic-roll-wire-colors-20261002`, incorporating the rolled-route ownership
follow-up through `67cbf9f0a57fe89a8486766456a769b646f2a3e1` and the fresh completed
descendant preview correction. All 1,238 files and executable modes match that
Git tree, with no extras or local edits. Cargo metadata, `ci/pins.env` and
`hibana-provenance.json` pin the exact source.

The new repair has a QUIC-independent release reproduction, eight Lean theorems,
four Z3 UNSAT obligations and one historical SAT witness. The core workspace
passed 874 Rust tests with 11 ignored, and its release/LTO regression and Clippy
passed. QUIC has a separate test with the actual capacity-one carrier. These
checks are distinct from Neqo interop. The full resource gate still fails the
existing route-arm compiler RSS ceiling (135 MiB against 132 MiB); its isolated
run passed at 132 MiB. Stack/SRAM/flash remain within unchanged budgets. See
`hibana/proofs/live-descendant-preview/` and the fresh recovery evidence.

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
