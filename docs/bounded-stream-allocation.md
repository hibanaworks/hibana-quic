# Whole bounded transport allocation measurement

Run:

```sh
cargo test --manifest-path adapters/host/Cargo.toml --test bounded_streams --release
```

The clean host package registers `reference-tls/tests/bounded_streams.rs` without
linking a reference TLS backend. Its two tests use the actual `BoundedTls`,
`HandshakeEndpoint`, `TransportEndpoint`, Hibana session runtime/Driver and fixed
stream/send/reference storage. A thread-local global allocator counter records
`alloc`, `alloc_zeroed`, and `realloc`. Each measured interval must report zero.
Deallocation is permitted and is not counted as an allocation.

Before measurement: rcgen/ring generate ephemeral test CA/leaf/private-key
fixtures, the CA anchor is imported, P-256 PKCS8 is decoded, transport parameters
are encoded, and all caller-owned arrays/storage are prepared. No private keys
or traffic secrets are written to public evidence files.

Inside measurement:

- Both bounded TLS constructors, including calls to injected OS entropy
- Actual Hibana runtime initialization/rendezvous/role attachment and both
  authenticated certificate/CV/Finished handshakes over encrypted QUIC packets
- An HTTP/0.9-shaped request and exactly 5 MiB of response data, checked byte for
  byte in 5,120 fixed 1,024-byte blocks, with bounded receive/send storage reuse
- Corrupt request discard, loss/PTO retransmission with a fresh PN, duplicate
  suppression, corrupt/lost response recovery, and rejected adapter output retry
- Flow-credit updates and current-phase sent-ledger ACK authorization
- Server-initiated then client-initiated QUIC key updates, both authenticated
  receive generations checked, with the phase bit wrapping to zero
- Stream-table retirement, local endpoint retirement, and endpoint/provider,
  runtime storage and carrier storage drops
- A separate genuine wrong-CA handshake failure, terminal connection state,
  denied subsequent stream opening, and disposal of both endpoints

The test's local `TransportEndpoint::close` operation retires local state. This
is **not** evidence for an on-wire CONNECTION_CLOSE exchange or RFC closing /
draining timers; that protocol lifecycle remains a separate implementation gate.

This is measured execution evidence for these paths, not a proof that every
adversarial path is allocation-free. It does not establish whole-device stack,
RAM or flash budgets, Pico hardware execution, TLS resumption or 0-RTT. The
existing `bounded_wire` test separately corrupts an Initial and verifies that
its failure count persists through application key updates in the shared
connection integrity budget. Target compilation and component allocator/link
smokes have their own evidence.
