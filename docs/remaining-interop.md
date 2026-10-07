# Remaining interoperability work — 2026-10-07

The unchanged runner registers 22 cases, hence 44 candidate case/direction cells.
Historical official evidence is 34/44 cumulatively across different commits. The
latest same-commit 34-cell attempt (266e9d37, run 37549439439, attempt 2) passed
33/34, with client handshakecorruption failing; its 17 controls passed. That
failure is not erased by historical evidence or local tests.

## Current local evidence

The pinned, unmodified Neqo peer was rebuilt at
ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95 with NSS 3.126. Both candidate directions
and the peer self-control completed for:

- v2: actual v1 client Initial, v2 server Initial and both v2 Handshake directions;
  the 1 KiB file matched and candidate roles retired.
- rebind-port: 10 MiB file matched across two actual UDP port changes; matching
  challenge responses were observed and candidate roles retired.
- rebind-addr: the same checks with actual loopback IP and port changes.
- connectionmigration: 2 MiB file matched in both directions after use of the
  authenticated preferred address, peer path validation and candidate role retirement.
  The preceding three scenarios also passed again with this release executable.

Machine-readable local reports are under artifacts/remaining-interop/20261007-local.
These loopback tests are not the runner's ns-3 scenario or an official pass.

## Implementation

Version-specific keys/header encoding and authenticated compatible-version
selection retain packet-number and cryptographic usage accounting. Path
validation is a projected route/roll continuation, reusing role18 after its
Initial-retirement prefix. It has explicit request, physical settlement and
terminal/join edges. A 64-byte challenge can establish address reachability under
low amplification credit; a fresh nonce in a 1200-byte challenge then proves MTU.
An authenticated matching response can arrive on any path. New-IP adoption resets
RTT/congestion estimates and excludes earlier packets from their updates; port-only
rebinding retains those estimates. Existing ECN capability is not inherited by a
new path. Pending CID advertisements and response frames are consumed only by
actual physical acceptance or their authenticated acknowledgment/retirement.

The intermediate CI request has 42 candidate cells and 21 mandatory controls.
Every cell must come from the same source/run. Failed, unsupported, missing and
null observations remain failures. Original runner/deadline/capacity constraints
remain unchanged.

## Still open

HTTP/3 (two directions) is unfinished. The initial bounded static-QPACK/frame
codec has three passing unit tests, but no HTTP/3 native interchange has passed.
The other eight remaining case/direction cells have local evidence only.
The existing handshakecorruption failure still needs root-cause evidence.
Multi-connection routing of newly issued CIDs and non-current-path challenge
responses need further review before broad migration support is claimed.
Strict Clippy is not clean: the baseline independently reproduces 19 diagnostics;
the current candidate retains 18 shared baseline diagnostics.
No blanket lint waiver or protocol weakening was used to turn this into a pass.
