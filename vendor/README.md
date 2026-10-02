# Audited local dependency snapshots

`hibana/` is the complete tracked upstream source at commit
`3aef31ba015c75ea824b8b41f5603b03f5dd336b`, independently observed as the head of
`development/dots-causality` after the user requested the updated branch.
No local patch is applied. Cargo package metadata and `hibana-provenance.json`
pin that exact revision and every source file. Its runtime source matches the
previously verified selector correction, now incorporated upstream with proofs.

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
