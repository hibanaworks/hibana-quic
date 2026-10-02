# Audited local dependency snapshots

`hibana/` is the complete tracked source at published commit
`a9371bea437bbc1f4303ceeb3fc833f605efe730` on
`perf/certified-route-metadata-20261002`, based on the user-selected
`development/dots-causality` revision `3aef31ba015c75ea824b8b41f5603b03f5dd336b`.
All 833 files and executable modes match that Git tree, with no extras or local
edits. Cargo metadata and `hibana-provenance.json` pin the exact source.

The three immutable metadata lookup optimizations have pre-implementation Lean
and Z3 evidence, differential tests, and passing upstream Kani/final-form CI:
https://github.com/hibanaworks/hibana/actions/runs/37052293598 . Their proof and
measurement artifacts are retained inside the upstream snapshot. This update
contains no external rolled-route correctness repair and does not resolve the
known legal-trace offer failures. Consumer runtime and compile-capacity checks
on this revision must be recorded separately from the previous 3aef results.

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
