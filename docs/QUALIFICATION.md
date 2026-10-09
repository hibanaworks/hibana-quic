# Verification and limits

## Latest verified baseline, 2026-10-09

- QUIC: `5c58cec60cf4ebf5231b844ffe6fcccfaadc103e`.
- TLS: `b5cd10fcabb26ed0b121ae9a192b4c254f000426`.
- Hibana: `6fccdbf81038b00d99ec1bb2b9c43a487521628e`.
- [Official interoperability run 37899220610](https://github.com/hibanaworks/hibana-quic/actions/runs/37899220610):
  attempts 1 and 2 each executed and passed all 44 candidate results, including
  all nine groups and qualification. No cross-attempt combination.
- [Runtime run 37899220604](https://github.com/hibanaworks/hibana-quic/actions/runs/37899220604):
  Rust/TLS/Host, compile-fail, embedded, strict Clippy, Miri, runner certificate
  chain, finite-loss and additional stress gates passed.

The pinned runner source and impairment scenarios are unchanged. Simulator
termination explicitly waits for signalled capture children; that entrypoint
adaptation and its hashes are reported by qualification. Do not describe the
simulator entrypoint as unchanged.

## Residual observations

Additional stress delivered all 500 matching files with successful endpoints and
retired owners. Strict normal close passed 8/10 conditions. Corruption seeds
20261009 and 20261011 each ended one server connection by idle expiry. Actual
idle is distinct from normal close; delivery qualification does not erase it.

The preceding f1c9779 Neqo rebinding runner stopped before producing result JSON.
Its oversized console prevented exception diagnosis. Added safe tail diagnostics
did not reproduce the stop in either succeeding full run; root cause is not
established. Earlier failures are retained in [the repair log](LOCAL-KEY-WAIT-20261009.md)
and [historical qualification](history/QUALIFICATION.md).

Finite passes do not guarantee delivery for arbitrary loss patterns or complete
cryptographic safety. Miri, selected formal models and algorithm vectors have
bounded scopes. New organization/API edits require fresh checks against their
own source identity; baseline results must not be attributed to them.
