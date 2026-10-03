# Legacy control cleanup after executor reset

This recovery pass removes remaining consumers of the already-deleted central
Driver, HandshakeEndpoint, TransportEndpoint, top-level protocol and old HQ
implementation. No old production fallback or compatibility controller is added.
The working tree uses the recovered direct connection sources and host HQ.
Independent TLS, stream, path, recovery and early-data roles are retained.

`removed-files-and-tests.json` distinguishes files deleted in this pass from
those already removed when the recovered tree was assembled. It preserves old
check names and baseline content hashes, including old HQ/support checks.
Deleted tests are not treated as passed. The pre-existing endpoint `.orig`
backup moved byte-for-byte into `historical/`; its digest is recorded separately.

## Restored meaningful checks

- `src/test_evidence.rs`, under `cfg(test)`, performs an actual
  certificate-authenticated BoundedTls exchange through the independent TLS
  owner and takes its authentic Finished receipt. Six connection-authority and
  stream-owner fixture call sites no longer depend on Driver.
- `tests/ecn_history.rs` retains the two reclaimed/unknown-history ECN, sent
  ledger and congestion assertions from the old endpoint.
- `tests/path_cid_no_alloc.rs` retains Path/CID kernel allocation, challenge
  acceptance/MTU validation, reset-token rejection and retirement, advertisement
  and active-CID retirement checks. Removed Driver ticket assertions are not
  represented by this narrower kernel-only test.
- `tests/no_alloc.rs` remains, with certificate, AEAD/header protection/key
  update, Retry integrity, lease, flow, reassembly, PN and anti-amplification
  checks. Its shared helper no longer instantiates the deleted central graph.
- `src/early_control.rs` now owns its receive-context value type. Its kernel
  tests remain independent of an endpoint. The standalone early-data-check
  crate is absent from the recovered public baseline and was not invented.

## Remaining evidence gaps

All reconstructed Rust source and these restored Rust checks require fresh
compilation/execution. Earlier successful checks before storage loss do not
validate this tree. This pass ran no Rust compiler, cargo, rustup or formatter.
Only the nine historical-budget Python parser checks and static source/manifest
checks ran. `verification.json` records that distinction.

Full encrypted application transfer, large/repeated stream transfer, Retry/VN,
idle timeout, close/drain, resumption/0-RTT, migration/preferred-address, trace
integration and whole-connection allocation require fresh direct-role evidence.
Retained local role/kernel tests are not substitutes for those wire tests.
Historical budget readers now label the removed architecture and current budget
as `UNAVAILABLE_NOT_MEASURED`; old producers were deleted, and the old launcher
exits with an explicit unavailable diagnostic. No Pico/resource claim is made.
