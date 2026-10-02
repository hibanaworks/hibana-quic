# Async Initial / host reactor checkpoint

The Initial cryptographic keys are owned by real async Hibana roles. Their local sides perform direct send/recv/offer awaits; the two directional services share a global par with rolled typed requests. Host UDP, listener admission, resumption spacing and timer deadlines run through one epoll/eventfd reactor. Fixed mailboxes and core runtime do not allocate.

Remaining migration: Handshake/1RTT TLS ownership and receive/ACK/stream control still use the prior synchronous Driver in a separate session. This checkpoint is not maximal Hibana integration, full protocol conformance, a completed 40-cell matrix, or a Pico fit claim. Old synchronous integration fixtures remain in source and are pending migration.

Frozen-source local checks: root library 436 tests; Initial endpoint 3; runtime 9; mailbox 17; packet roles 7; paired bounded TLS/QUIC wire tests 3. Paired tests cover corruption/PTO recovery, shared integrity budget, key update/reordering/loss, protected close and trace overflow, with zero allocations in their scoped flow. Default-stack debug tests pass after removing nested owning task copies.

Host release builds from adapters/host/Cargo.toml. Host reactor setup/I/O allocation is outside the core no-allocation assertion. The earlier Waker clone/drop reentrancy bug has regression tests; callbacks execute outside the RefCell borrow. Public certificate/signature/algorithm fixtures are intentional; private ephemeral test keys, session tickets, raw packet captures and TLS secret logs are excluded.

Historical source 7a58d80 passed four distinct official handshake/transfer cells in three executions. Those results do not qualify this new checkpoint. The manual pilot reruns the unchanged baseline and same four cells with exact source_ref.

## Follow-up host correction

The initial async source79986a5 produced one success and three failures in run37003881341; the unchanged Neqo baseline passed both cells. Local independent reproduction found rejected mapped-IPv4 traffic on a dual-stack listener and a queued-UDP/expired-soft-timer fairness defect. Both now have failing-before/passing-after tests, while hard deadlines remain enforced. This rerun enables bounded counter-only telemetry on existing activity, adds no diagnostic timer wakes, and retains all original runner checks. It does not assert those two defects fully explain the prior run before new evidence.
