# Historical record — not current status

Preserved from the pre-organization snapshot. Dates, source paths, dependencies
and qualification claims below describe their original revisions only.
See [current status](../WORKING-STATUS.md).

# Qualification and limits

The unchanged selected interop matrix passed on
`b8c0d3059f616981bedf5f241ed8a70f707be2c4`:

- **44/44** candidate case/direction results, **0** unexecuted.
- **22/22** unchanged reference controls.
- All cells are from the same commit, run and attempt; no cumulative substitution.
- [Interop run 37639879838](https://github.com/hibanaworks/hibana-quic/actions/runs/37639879838), attempt 1.
- [Runtime run 37639879744](https://github.com/hibanaworks/hibana-quic/actions/runs/37639879744) passed.
- [Generated qualification report](../../tests/interop/qualification.json), retained from artifact 11492259003.

This is qualification of that selected matrix on that exact commit, not a
production-readiness, arbitrary-network, complete TLS/HTTP3, or repeatability proof.
The module/API cleanup after that commit requires its own regression checks and
same-commit matrix. A passing baseline does not automatically qualify later edits.

The qualified baseline used exact Hibana `b92a1fe4153e6b2404a183c9231245efd58e3237`.
The current local cleanup imports unpatched Hibana Git revision
`8302a07b5f0f2d224229afdba4d0afef62d6aa2b`; its own remote qualification
is still pending. Runner and reference revisions are in `tools/ci/pins.env`.
Original simulator rules, capacities and deadlines remain unchanged.

Locally, the baseline passed 586 Rust tests, the thumbv6m core check, 87 Python
tests, and native Neqo loss/migration in both directions. Native loopback is not
an official ns-3 result. Strict library Clippy still has 25 baseline diagnostics;
cleanup must address them rather than claim that ordinary CI implies lint-clean.
Full embedded connection RAM/task-size qualification remains unavailable.

Scoped Lean/Z3 models document their own assumptions; none proves all Rust code,
cryptographic security, or liveness under arbitrary loss. Private packet captures
and key logs are never part of the public qualification report.

## Latest published revision

`593e78d1202d821328702effd5f81e4d757f6a99` passed
[normal CI](https://github.com/hibanaworks/hibana-quic/actions/runs/37698852840).
Its [official interop run](https://github.com/hibanaworks/hibana-quic/actions/runs/37698852775)
executed all 44 candidate cells: 43 passed, client handshakeloss failed.
Server handshakeloss passed. This does not establish a root fix or qualify
subsequent module cleanup. See [working status](../WORKING-STATUS.md).

## Current CI scope

At the user's request, reference-versus-itself runs (quiche/quiche and neqo/neqo)
are omitted. Qualification still requires all 44 Hibana/reference candidate cells
on the same commit, run and attempt, both directions, unchanged pinned runner,
original deadlines and capacities, and successful execution/cleanup. Reports mark
reference self-tests as omitted with zero control results; this does not claim
that controls passed. Historical baseline reports above retain their original scope.
