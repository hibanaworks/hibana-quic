# Remaining capabilities and release gates

The executable is experimental. This document describes the current direct
implementation, not features once exercised by a removed driver.

## Verified scope

The cumulative verified inventory is 30/44 unique case/direction cells across
recorded revisions: seven original cases both directions, resumption, blackhole,
0-RTT, key update and amplification limit both directions, handshake loss, handshake corruption and multiplexing both directions. Passing quiche controls are accepted where
Neqo self-controls failed; the failed controls remain recorded. This inventory
is not a complete rerun of all 44 cells on the latest commit.

See [the exact case inventory](../interop/qualification.json) and
[implementation/evidence](ACTIVE-IMPLEMENTATION.md). Missing, unsupported,
failed and skipped cells are never counted as passes. The full three-attempt
matrix has not run.

## Current priority

Complete the user-requested whole-codebase direct-local control audit and
replacement, while requalifying changed paths against existing interop cases.
Multiplexing has already passed both official directions. Then resume the
remaining interop capabilities. The
[15-second performance requirement and evidence](performance-follow-up.md)
remain open, with further optimization experiments deferred.

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

- The other 14 runner cells, including Retry, HTTP/3, QUIC v2,
  ECN and path migration, lack historical official
  qualification. TLS-only or numerical-kernel tests do not qualify the endpoint.
- [Multiplexing](multiplexing.md) now reuses at most 64 live slots for a finite
  4,096-request admission bound. Native 1,999-file transfer and credit refill
  are verified. Both official directions passed at 4fdc24a7 with a passing Neqo control.
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
