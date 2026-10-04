# Owned response-reader transfer

The existing SourceData / admission reply / SourceTaken exchange now transfers
one actual response reader for a server stream. Ingress owns and reads that
reader into the same bounded packet-sized chunks. The reader is dropped before
replying. A client still transfers bounded request bytes through the same edge.
The global choreography and public application API are unchanged.

This removes a three-message source/ingress exchange for every response chunk.
It does not remove packet publication, key ownership, flow control, ACK recovery,
FIN/abandon, or the finite production-reclamation join. The existing
CHUNK + packet overhead <= datagram capacity check remains: increasing the chunk
past the packet capacity was rejected and is not used as an optimization.

Only a real zero-length BodyReader result selects normal server EOF. A read
failure, stream stop or connection stop selects rejection/abandon. Ingress
checks flow-control backpressure on every chunk and yields after sixteen reads
when work is continuously ready. No completion flag replaces an actual receive,
and no normal EOF is synthesized to finish a join.

## Verification boundary

- `Body.lean` checks EOF-only normal completion and single-owner transfer,
  receive and release arithmetic.
- `check_body.py` checks initial ownership and eight inductive transition
  obligations, with counterexamples for copying an owner or treating carrier
  acceptance as EOF.
- Actual Hibana endpoint tests exercise a stopped body followed by a fresh body,
  a pending read, a failing read, and exact drop/read counts with zero allocations.
- Connected TLS/QUIC tests check actual body bytes, empty responses, FIN, loss,
  confirmation, closing and slot reuse.

The model covers one input invocation. Rust moves and private inbox access are
its ownership implementation premise; a generic external BodyReader's native
side effects are not automatically verified. The existing stream-reclamation
proof still separately requires matching identities and no retained packets.

Reproduce the models with Lean 4.30.0 and Python with z3-solver:

    lean proofs/owned-body-input/Body.lean
    python3 proofs/owned-body-input/check_body.py

## Experimental measurements

With a 64 KiB backed host receive window, 64-datagram opportunistic receive
budget (time checked at datagram boundaries) and the certified-column lookup,
the local unchanged-Neqo-peer diagnostic sent the same 2/3/5 MiB files from
hibana-quic in 5.020 and 5.083 seconds, versus 7.119 seconds before moving the
reader. These are two diagnostic observations, not a repeated performance
qualification or a fair Neqo-server throughput comparison: the reference server
generates zeros while this server reads actual files.

The separate three-run release-client comparison measured 1 MiB in 0.036543 s
versus Neqo 0.011526 s, and 32 MiB in 0.692855 s versus 0.052621 s. Peak client
RSS was about 10.6 MiB. Native clean/loss/corruption/resumption checks passed in
both directions; server early receive also passed the local 40-file diagnostic.
These experiments add no official interop cells and do not establish near-Neqo
performance, especially on the sending path.
