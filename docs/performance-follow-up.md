# Deferred performance work

Priority decision: 2026-10-06 JST. Continue remaining interoperability work,
starting with multiplexing. Keep the performance requirement open; successful
interop or a relative improvement does not satisfy it. Correctness failures
found during interop remain immediate fixes.

## Required outcome

Client completion at or below 15 seconds for the same native 50-connection
burst-loss workload. Preserve all 50 content-hash checks, the loss pattern,
delay and timeouts. Report client completion, subsequent actual resource
retirement, and the TLS resumption/early-data mix separately. A single fast
sample is insufficient evidence of a repeatable result.

## Current evidence

- Published finite-capacity change: `714f9f6e9594338677cb7edfcfb41da2202c7eec`.
  Three client measurements: 18.666 / 18.384 / 22.303 seconds. All files and
  actual resource retirement verified. Peak server RSS: 26,496 / 29,908 /
  24,124 KiB. The 15-second requirement is not met.
- Before that capacity change, an interleaved three-pair comparison measured
  Neqo at 10.480 / 10.354 / 13.377 seconds (median 10.480) and Hibana at
  23.887 / 34.920 / 29.043 seconds (median 29.043). The gap is real.
- One actual wait4 observation measured Neqo server CPU at 0.364 seconds and
  Hibana server CPU at 1.579 seconds. Client times were 11.378 / 32.615 seconds.
  Computation alone cannot account for this wall-time difference.
- No matched quiche timing has been established. That part of the comparison
  remains unanswered; a passing quiche interop control is not a timing result.
- Real UDP observation found all 346 sampled client Initial datagrams at least
  1200 bytes. Do not blame the reference peer for undersized Initial packets
  based on individual packet-length logs inside coalesced datagrams.

## Keep these implemented fixes

- A matching short packet received during the finite handshake is held as
  owned ciphertext and authenticated only after the real join/key transfer.
- Parallel TLS ticket issuance shares one owned key. Real one-use NEW_TOKEN
  values are IP/expiry bound, retained with the authenticated control flight,
  and checked on future admission. Clean native runs verify 49 resumptions
  after the initial full handshake. No early data is enabled by this change.
- Finite server request limits determine both advertised credit and actual
  receive-slot storage. No unrelated phase controller or Hibana API was added.

## Experiments not retained

Fixed 100 ms initial RTT, measured-RTT reuse, larger chunks, DATA+FIN tail
holding, CRYPTO-first scheduling, and additional Handshake-ACK piggybacking did
not establish a stable enough benefit. Some produced a single sub-15-second
sample, followed by slower repeats. They are not part of the published code.
The normal initial RTT remains 333 ms and the send chunk is 1024 bytes.

## Investigation to resume

Prioritize packetization and retransmission waiting. A captured reference-peer
trace showed small Handshake ACK responses while missing Handshake CRYPTO
waited for PTO. Any first-flight coalescing design must retain separate packet
reservations and acknowledge only the real physical UDP acceptance. Source
ownership transfer is not physical-send completion; preserve explicit wire
completion and retirement joins. No coalesced production path has been
implemented or qualified. The existing source/wire projection was exercised
only in an isolated scheduling feasibility test.

Revisit after additional interop cases are working, or sooner if the same
recovery/packetization issue blocks a correctness test. Run matched repeated
controls before adopting another optimization. Keep the official historical
qualification count distinct from any latest-commit rerun.
