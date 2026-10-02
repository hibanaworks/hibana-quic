# Fixed-path zero-length peer connection IDs

Historical document preserved from source `004a324`. It does not qualify the current full-owner tree; see the current README.

The managed network profile accepts a peer whose authenticated initial source connection ID is empty. Outgoing Initial, Handshake and 1-RTT packets preserve that actual zero-length destination. This does not insert an empty or synthetic value into the nonzero `Cid`/`PeerCidTable` kernel.

An explicit fixed-zero transmit target retains the real path reservation and adapter outcome. The path remains the original exact local/remote socket tuple, preserving anti-amplification, MTU, congestion/sent accounting, ECN and callback rollback. Authenticated transport parameters still have their actual values; the fixed-path policy is separate from `disable_active_migration`. A server-provided initial reset token is retained without a synthetic CID and can match only after an accepted send to the exact tuple.

Zero-peer mode is intentionally nonmigrating in this bounded profile. Changed tuples are discarded without creating a path or earning amplification credit. This is a profile limitation, not an assertion that RFC 9000 prohibits all NAT rebinding with zero-length CIDs. NAT/rebinding and migration interoperability cells remain unqualified.

RFC 9000 §5.1.1 and §19.15 prevent an issuer that selected an empty initial CID from later supplying NEW_CONNECTION_ID. The authenticated receive path enforces that rule. Local nonzero-CID retirement rules are unchanged, including rejection of retirement of the packet's actual destination. Local managed CID storage still requires a nonempty local CID; the legacy zero-local-CID receive path does not fabricate an unnecessary managed-network context.

`tests/managed_zero_peer_cid.rs` uses real certificate-authenticated BoundedTls peers, encrypted packets and scheduled Initial key roles. It covers empty long/short-header destinations, corrupted packets receiving no amplification credit, rejected-send reservation rollback, bidirectional application data, ECN feedback, changed-tuple confinement, authenticated forbidden NEW_CONNECTION_ID, and authenticated current-local-CID retirement. All three cases measure zero allocations during their complete transport scenario. Negative-control payloads are substituted before actual TLS sealing; no authentication or receive-policy bypass is used.

The same happy-path test fails against unmodified source `4a16640720403421b6649cbe56263fdc25e9c5da` on the server's first packet production with `Network(Cid(InvalidCidLength))`. This local regression is not an independent-peer interop pass or a completed runner matrix. Re-run those gates against the published exact source before making such a claim.
