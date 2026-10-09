# ECN components and Linux metadata adapter

The components are connected to the endpoint's authenticated ACK generation,
sent ledger and NewReno path. Actual kernel/UDP feedback, controlled CE,
bleaching, replay and corruption tests pass. These direct tests do not qualify
the full runner `ecn` testcase.

## Actual UDP metadata

`src/udp.rs` retains the endpoint-family, source-policy, truncation and conflict
checks. `src/os/udp.rs` owns the small native recvmsg/sendmsg ABI boundary.
The host crate denies unsafe code except this explicitly isolated OS module.
No external nix/libc Cargo dependency remains in normal/build dependencies.

- Source address, destination packet information and ECN come from the kernel.
- Missing ECN stays None; truncated or contradictory metadata fails closed.
- Source selection and ECN are per datagram, with no socket-global send marking.
- Both send and receive ancillary storage are bounded stack arrays.
- Socket setup still allocates. The host is not the no_std/no_alloc core.

The reconstructed Linux host suite passes 130 tests, including all 22 UDP tests,
five native ABI/parser/live-loopback tests and zero-allocation send scheduling.
Darwin ABI definitions follow XNU headers, but Mac execution is unverified and
was deferred by the user. No full interop-runner ECN claim is made.

## Bounded protocol component

`src/quic/ecn.rs` in the core provides `Codepoint`, `RxCounts`, `PathIdentity` and
`PathEcn`. It has no allocation or standard-library dependency. `RxCounts`
requires the caller to count only authenticated, nonduplicate processed QUIC
packets. Coalesced packets each inherit their datagram's codepoint. Counts are
separate for the three packet-number spaces. One unavailable observation makes
that space's cumulative feedback unavailable rather than inventing a count.

`PathEcn` has one immutable connection/path-generation identity. It starts with
zero counters for a new connection's initial path; there is no reset or migration
API. Accepted send events must preserve increasing packet numbers per space.
ACK inputs require already-validated ranges and exact first-ACK classifications
from the sent ledger, including late ACKs of lost packets. Adapter rejection
does not count as transmission.

Validation follows [RFC 9000 §13.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.4)
and its Appendix A.4: a ten-packet/three-PTO probe budget, no capability claim
without marked-packet feedback, safe handling of reordered ACKs, and fallback
for missing, bleached, remarked or impossible counts. ACK loss may produce a
counter delta larger than the newly acknowledged set. Validated CE deltas are
returned once for the caller's [RFC 9002 congestion response](https://www.rfc-editor.org/rfc/rfc9002.html#section-b.7).
The endpoint must preserve the ACK-largest sent timestamp before reclaiming
history and apply congestion recovery before normal ACK growth.

Sixteen component tests cover these rules plus stale identities, overflow,
mixed codepoints, per-space separation and late ACKs after probe loss.
`artifacts/ecn/core-tests.log` and `thumbv6m-check.log` record the tests and
embedded-target compilation. Engine wiring preserves original marking in accepted sent history through
loss/late ACKs. It validates ACK ranges and obtains typed ACK authority before
processing ECN feedback, then applies validated congestion events before normal
ACK growth. The two ledger tests prove rejection/cancellation cannot create ECN
send credit and counter overflow is preflighted.

```sh
cargo test --manifest-path host/Cargo.toml --locked --lib
cargo test --locked --lib ecn::tests
cargo check --locked --target thumbv6m-none-eabi --lib
```

## Host use and measured direct evidence

HQ accepts `--ecn on` or `--ecn off` (default off) on either role. The option
controls local ECT probing; kernel-observed receive markings are reported even
when local marking is off. Existing receive APIs without metadata retain their
unavailable-observation semantics. `receive_with_metadata` additionally checks
the immutable path identity before granting ingress credit or parsing packets.

The JSON `ecn` object reports per-space actual accepted ECT sends, authenticated
receive counts, validation state/failure and validated CE/congestion-event
counts. Transfer success by itself is not an ECN validation claim: bleaching
correctly falls back to Not-ECT and can still complete the file transfer.

`artifacts/ecn/real-udp-loopback.json` records three exact-hash 5 MiB transfers.
A local UDP relay forwards encrypted bytes without decrypting or constructing
ACKs. It tests untouched markings, a genuine ancillary CE mark alongside replay
and corruption, and bleaching to Not-ECT. The CE case produces one validated CE
and one NewReno congestion event; invalid/replayed packets do not add counters.
Both endpoints disable marking on bleaching while finishing the transfer.

`artifacts/ecn/direct-neqo.json` records both verified direct directions with
actual X25519 group 29. The Neqo library client and bounded server both report
ECN capability. The bounded-client run combines official Neqo `--retry`, ECN
and a mid-transfer key update, with an exact 5 MiB hash and authenticated new key
generation. Retry's discarded sent attempt is not called an ACK/loss: ECN keeps
only cumulative accepted bounds and no dangling per-PN owner/reference.

```sh
python3 tests/tls-reference/tests/test_hq_ecn.py \
  --binary host/target/release/hq --output artifacts/ecn/real-udp.json
```

The verified peer's `test_hq_ecn_neqo.py` accepts explicit host/peer/official-server
binaries, NSS database and CA paths. Socket metadata from the shared host helper
is the only shared adapter code; all oracle QUIC/ACK/ECN decisions remain in the
unchanged Neqo library, and the forward direction uses its official server.

## Reclaimed send history

ECN congestion response does not disappear when the sent ledger reclaims the
ACK-largest record. A per-space monotone upper bound preserves accepted send
chronology across reclaim, explicit forgetting and key-space discard; cancelled
or reserved records contribute nothing. Exact retained timestamps remain the
only RTT sample source. Congestion recovery may conservatively use the bound
for retired history, and uses current time only as an explicit final upper bound
if no history is available. This can cause an extra conservative reduction for
an older retired packet; it does not claim an invented precise send timestamp.
Duplicate feedback contributes no new CE delta, and an unchanged prefix bound
within the existing recovery epoch does not reduce again. Dedicated regression
tests cover retired ACK-only/lost records, later prefix advancement, cross-space
isolation and unavailable history. Whole-crate revalidation after PSK integration passes all280 root tests, strict
Clippy and thumbv6m compilation; see `artifacts/resumption/root-tests.log`,
`root-clippy.log` and `thumb.log`.

Frozen-binary reruns are retained in `artifacts/ecn/direct-neqo-frozen.json` and
`real-udp-frozen.json`. The latter also reorders a client packet and marks a
replayed server packet CE; the replay does not add a second CE count or reaction.
