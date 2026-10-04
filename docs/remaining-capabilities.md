# Remaining capabilities and release gates

The executable is experimental. This document describes the current direct
implementation, not features once exercised by a removed driver.

## Verified scope

The pinned unchanged runner passed seven registered cases in both candidate
roles at `ff3c3d0f71e27d7db2b69e085b46cfada9adbbad`: handshake, transfer,
longrtt, transferloss, transfercorruption, IPv6 and ChaCha20. This is 14/44 candidate
cells. Separate unchanged-Neqo baseline results are not included. Later source
changes require a new runner result on their own commit.

See [the exact case inventory](../interop/qualification.json) and
[implementation/evidence](ACTIVE-IMPLEMENTATION.md). Missing, unsupported,
failed and skipped cells are never counted as passes. The full three-attempt
matrix has not run.

## Architecture work

- Finish the remaining control audit and projected CID/key-update integration;
  stream reclamation and lower key ownership now have explicit local checkpoints.
- Bind every transferred resource to the current affine scope. Correlation IDs
  and private side slots do not acquire Hibana guarantees merely by being
  mentioned in a choreography. Scoped Lean/Z3 models and actual negative tests
  document the existing boundaries.
- Keep numerical parsing, cryptography and bounded storage distinct from
  protocol-control permission. No legacy FSM compatibility path.

## Unqualified capabilities

- The other 30 runner cells, including multiplexing, Retry, resumption, 0-RTT,
  HTTP/3, QUIC v2, key update, ECN and path migration, lack current official
  qualification. TLS-only or numerical-kernel tests do not qualify the endpoint.
- Request production still has a fixed total request count; two-slot reuse for four requests is locally verified, but the runner's
  larger multiplexing workload and ongoing credit refill remain unqualified.
- Legacy standalone idle, close, migration, path validation, ECN marking, client
  Retry, version-negotiation and early-data
  controllers have been deleted. Their old component tests do not demonstrate
  current endpoint support. The live connection's projected close/drain flow
  remains and is tested independently.
- Private qlog/keylog capture needed by some runner verdicts is incomplete;
  fabricated log files must never replace actual evidence.
- Core no-allocation tests and thumbv6m compilation cover their stated scopes.
  Whole-stack allocation closure, board drivers/entropy, stack/RAM/flash fit,
  timing and real Pico hardware qualification remain open.

## Execution boundaries

The current cloud workspace cannot run the runner's Docker/ns-3 topology. Native
unchanged-Neqo diagnostics compare real bytes locally; the official runner runs
in the user-authorized disposable GitHub CI environment. Native results do not
stand in for topology/trace verdicts.

Path/ECN/Retry cleanup preserves address types, receive metadata, counter
validation, Retry packet integrity and token cryptography/replay bookkeeping.
Deleted standalone phase controllers are not an alternate implementation of
the pending features. Their replacement endpoint capabilities must be written
with Hibana when those interop cases are implemented.
