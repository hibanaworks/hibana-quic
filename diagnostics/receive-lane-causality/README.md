# Combined connection receive-lane diagnosis

The runtime-build attempt at source `74280de429eb37f86b9aa2e9f9573735eb65f53b`
failed during Hibana const projection with `ReceiveLaneCausality`; zero Rust
tests executed. The implementation was at fault. No core code, validation
condition, compiler limit, or carrier capacity was changed.

The original graph had 166 events on physical lane 0. Source-level expansion
found 27 failed obligations across these boundaries:

- TX2 receives from TLS_TX3, then ReadAdmission from RECEIVE10
- TX_KEYS13 receives WriteStart from TX2, then key commands from RX_KEYS12
- TRANSMIT16 receives admission from13 or publication results from17, then
  CloseAuthority from23
- PEER_CLOSE23 receives a peer outcome from22, then FilesOutcome from25
- PEER_CLOSE23 receives a peer outcome from22, then KeyRetirement from12
- PEER_CLOSE23 receives FilesOutcome from25, then KeyRetirement from12

The first failing pair is source event23, TLS_TX3→TX2 InitialTransmit.Flight,
and event109, RECEIVE10→TX2 ReadAdmission. The same later receive also fails
for the other relevant TX2 receives, including final TransmitContinuation.

## Ownership correction

Startup now passes the actual settled write continuation2→13→0. Prefix RX0
validates Finished/parameters/scope against that write material before the
bundle travels0→1→10→13. The actual RxControl then crosses13→12. Separate
parallel ownership paths use distinct physical lanes; local sends require the
received owned bundle, so an unsolicited later arrival cannot fill Q=1 first.

Peer and file terminal facets retain their separate actual permissions. After
all ordinary roles finish, TRANSMIT16 sends OrdinaryRetired to fresh close
owner26. That finite owner passes the accumulated grant through explicit
request/reply exchanges with12 (adds KeysQuiesced),23 (adds peer outcome), and25
(adds file outcome). Each response requires its actual received grant. Only
after those branches finish does26 send the complete Closing capability to16.
The ordinary RX/TX/key/clock concurrency and rolled wire work remain intact.

## Executed local source models

Run from any directory:

```
python3 diagnostics/receive-lane-causality/verify_final.py
python3 diagnostics/receive-lane-causality/finite_q1_model.py
```

`model.py` expands the actual Rust aliases and reproduces Seq/Route/Par/Roll,
endpoint-set lane coloring, route intersection, parallel union, and roll
reentry. `marker_port.py` independently traverses literal scope markers/ranges.
On the implemented aliases both report173 events,306 markers,4 lanes, and zero
modeled structured or roll-reentry failures. Source hashes and event rows are
in `implemented_source_result.json`.

`finite_q1_model.py` enumerates all interleavings of the direct finite local
send/recv sequences on one global capacity-one queue. The implemented startup,
admission and retirement sequences have no modeled deadlock. Its negative
control detects the blocked unordered-parallel-arrival design. Results are in
`finite_q1_result.json`.

These are Python source/queue models. They do not execute Rust, Hibana's full
global validator, its real carrier/futures, owned Rust capabilities, QUIC, or
interop. Fresh Rust compilation and real capacity-one connection tests remain
required. Earlier exploratory snapshots are retained locally and are not
required by the portable final scripts above.
