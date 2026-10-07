# Qualification and limits

The unchanged selected interop matrix passed on
`b8c0d3059f616981bedf5f241ed8a70f707be2c4`:

- **44/44** candidate case/direction results, **0** unexecuted.
- **22/22** unchanged reference controls.
- All cells are from the same commit, run and attempt; no cumulative substitution.
- [Interop run 37639879838](https://github.com/hibanaworks/hibana-quic/actions/runs/37639879838), attempt 1.
- [Runtime run 37639879744](https://github.com/hibanaworks/hibana-quic/actions/runs/37639879744) passed.
- [Generated qualification report](../interop/qualification.json), retained from artifact 11492259003.

This is qualification of that selected matrix on that exact commit, not a
production-readiness, arbitrary-network, complete TLS/HTTP3, or repeatability proof.
The module/API cleanup after that commit requires its own regression checks and
same-commit matrix. A passing baseline does not automatically qualify later edits.

The qualified baseline used exact Hibana `b92a1fe4153e6b2404a183c9231245efd58e3237`,
with no local vendor patch. The current development snapshot now imports exact
Hibana `cf084d22a473b26c8cd0b8be80631eaf3e7184b4`, also without a vendor patch;
its consumer and remote qualification must be established separately. Runner and reference revisions are in `ci/pins.env`.
Original simulator rules, capacities and deadlines remain unchanged.

Locally, the baseline passed 586 Rust tests, the thumbv6m core check, 87 Python
tests, and native Neqo loss/migration in both directions. Native loopback is not
an official ns-3 result. Strict library Clippy still has 25 baseline diagnostics;
cleanup must address them rather than claim that ordinary CI implies lint-clean.
Full embedded connection RAM/task-size qualification remains unavailable.

Scoped Lean/Z3 models document their own assumptions; none proves all Rust code,
cryptographic security, or liveness under arbitrary loss. Private packet captures
and key logs are never part of the public qualification report.

## Post-baseline module organization and core refresh

The reorganized consumer, with exact core `cf084d22a473b26c8cd0b8be80631eaf3e7184b4`,
passed 586 core/consumer Rust tests across 18 suites, 123 host tests across nine
suites, and the `thumbv6m-none-eabi` no-default-features check locally. The exact
1207-file upstream snapshot audit and the source inventory audit also passed.
These checks do not replace the selected official interop matrix on a new commit.
Native Neqo loss, HTTP/3, and connection migration also passed in both directions
with this release binary, including byte comparison and verified retirement.
They remain local native checks, not official simulator verdicts.
