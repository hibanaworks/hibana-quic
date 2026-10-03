# Recovery status

This is source preservation after execution storage was replaced around 2026-10-03 06:18 UTC. Reconstructed source is unverified and incomplete. No current successful build or interoperability claim is made.

Published unchanged baselines remain available:
- QUIC historical checkpoint: d086180079866d83c01ddaef254834ac2e738eb9
- Qualified integrated Hibana: e75d413bb3c3adc6e61ba92f267bd14795d8525e
- Core CI passed: https://github.com/hibanaworks/hibana/actions/runs/37099834655

Before storage loss, a direct-role handshake prefix completed IPv4/IPv6, wrong-hostname/CA rejection and client-to-Neqo authenticated TLS. Original binaries and local logs are unavailable. Those outcomes do not validate reconstructed files. Application transfer and formal runner qualification were not complete.

Restoration must retain the new choreography/local-role design. Legacy Driver, HandshakeEndpoint, TransportEndpoint and the old HQ central loop are not a runtime fallback. Unchanged packet, TLS, cryptographic and numerical kernels may be restored from public history without reintroducing old control.

Open correctness/integration work:
- actual affine prefix-to-application edges in one combined global
- file/stream transfer, ordinary-publication cancellation and close/drain retirement
- exact Initial retirement on client accepted Handshake send/server authenticated Handshake receive
- outstanding Handshake recovery carried into application so lost Finished ACK can be resolved by HANDSHAKE_DONE
- bounded RX work/yields and explicit profile capacity failure
- fresh build, allocation, authentication, cancellation, loss and actual Neqo/runner tests

Numerical/TLS adapter bodies and the connected runner have now been reconstructed. They have not been compiled. Initial retirement role wiring and API reconciliation remain incomplete. Legacy endpoint tests/targets and dead role bridges need final migration/removal before validation.

## Subsequent reconstruction, awaiting first fresh compilation

The current working source now contains the finite Initial-retirement roles, retained Handshake recovery, one affine connected startup, parallel application roles and post-retirement close/drain. The primary host file mode invokes that connected global. Five real-TLS connection tests cover single/multiple transfers and actual authenticated confirmation/ACK loss. These are source-only test bodies, not passing results. Adapter rejection currently terminates the prefix after cancelling its reservation; retry semantics remain unqualified.

The dedicated recovery compile diagnostic records interoperability as NOT_RUN. The standard runner path retains its existing checks and requires the diagnostic marker to be removed.
