# Remaining interop handoff — 2026-10-07

## Read this first

The implementation and CI adapter now include HTTP/3. Five local native Neqo
scenarios have passed in both candidate roles, using one executable: v2,
rebind-port, rebind-addr, connectionmigration and http3. The peer's five unchanged
self-controls also passed. These ten native-loopback cells are NOT official
ns-3/interop-runner passes. Machine-readable evidence identifies each executable.

The passing candidate uses a separate Hibana parallel-offer repair on top of
1b28efff. The vendored source in this handoff deliberately remains exact,
unpatched 1b28efff until the core repair has a real commit identity. First apply
the core ZIP, then import that actual commit and rerun qualification. Do not push
this tree as a fully qualified exact-core snapshot before that dependency step.

## HTTP/3 fixes and boundaries

- Explicit authenticated ALPN selection, bounded static QPACK/Huffman parsing,
  three critical unidirectional streams, and projected control/SETTINGS ownership.
- SETTINGS startup settles the source before releasing the sink to send another
  coalesced control frame. A one-slot-carrier regression fails before and passes
  after this literal global/local order change; no capacity or timeout change.
- Streaming file decode has projected reader/write/receipt/FIN boundaries.
- RFC 9114 section 8 requires unknown peer application-close codes to be treated
  as H3_NO_ERROR. Actual codes stay preserved; known H3/QPACK failures stay errors,
  and missing file FINs/ACKs are never fabricated. This matters because the pinned
  Neqo test client closes its successful H3 connection with Application(0).
- Role futures are pinned at the existing executor join boundary before joining
  references. The connected suite passes on the default host test stack.

Normative close-code source: https://www.rfc-editor.org/rfc/rfc9114.html#section-8
Pinned reference: Neqo ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95.

## CI status and remaining limitations

The CI plan now requests all 44 candidate case/direction cells and 22 mandatory
controls on one source commit/run. HTTP/3 abbreviation `3` is read from unchanged
runner 740c05a10b61d65e8abd3ad38d60898004d335d9. Missing, failed, unsupported or null
cells cannot qualify. Adapter and matrix failure-path tests are included.

No new official CI run or remote push occurred in this handoff. Historical
same-commit run37549439439 attempt2 passed33/34, controls17/17; candidate-client
handshakecorruption failed. Historical cumulative34/44 is not a current pass.

Strict Clippy for the QUIC codebase is still not clean. Same-command all-target
checks reproduced75 baseline errors and57 before final cleanup of newly introduced
SETTINGS error signatures/range style. No blanket lint waiver was added. The
separate Hibana repair passes strict Clippy. General H3 production completeness,
full dynamic QPACK, broader GOAWAY admission, and official interop are not implied
by the finite native cases. Preserve existing resource and wire-check limits.

See the ZIP's README_FIRST.ja.md for exact import, test and push instructions.
