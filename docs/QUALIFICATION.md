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

## Later source, not a replacement qualification

QUIC `1acbcadc78e15a263f8d4d284bd8064c54a987e2` passed all three
[runtime jobs](https://github.com/hibanaworks/hibana-quic/actions/runs/37911648433).
Its [official interop run](https://github.com/hibanaworks/hibana-quic/actions/runs/37911648501)
failed Neqo-client/Hibana-server `rebind-addr`; this is not a 44/44 pass.
Captured Initial retransmissions arrive from changed ports while server responses
retain the original port. Handshake-path filtering is deliberate; RFC 9000
section 21.12 permits rejecting a changed path during the handshake. A collision
with the runner's first-rebind=1s setting is under investigation, not a proven
cause. No path-security or amplification checks were removed to satisfy the test.

Earlier `9c9eabf` stress evidence also includes a 50-connection loss run with all
file hashes matching but a server deadline failure. A later frozen `1acbcad`
local replay of that seed passed; a passing replay does not resolve the intermittent
failure. Final source qualifications must retain these failures in the history.
