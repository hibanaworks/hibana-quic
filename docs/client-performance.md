# Measured client performance checkpoint

This is an optimization checkpoint, not Neqo performance parity or an increase
in official interoperability qualification (still 14 of 44 cells).

## Bulk receive spans, 2026-10-04

With the original 64 KiB backed window and 64-datagram budget, splitting
circular receive operations into at most two contiguous slices gave a five-run
32 MiB median of 0.531682573 s, versus Neqo 0.045999752 s (11.56x).
Client RSS stayed about 10.6 MiB. The earlier same-host checkpoint was
0.721776265 s; host timing variation remains visible across runs.

The 256 KiB window / 256-datagram experiment reached 0.375339414 s with the
same span implementation, but used about 22.9 MiB RSS. It is not the adopted
default. The chosen change removes repeated per-byte circular indexing, uses
bulk copying/clearing, and preserves complete overlap validation before mutation.
Lean/Z3 models and differential/transactional tests are in `proofs/ring-spans/`.
It adds no receive storage, allocation, protocol flags or public API.

A separate exact-match search hint was rejected: seven-run comparisons gave
0.517780069 s with it and 0.520965310 s without it, not a demonstrated benefit.
The gap to Neqo and the sub-0.1 s target remains substantial.

## Latest candidate, adopted 2026-10-04

The selected Hibana revision is `56d405671931eaac615edeb59b6562337f9edbb4`.
With its certified raw-column lookup, a 64 KiB backed host receive window and
owned response-reader handoff, three-run local release measurements gave:

| File | hibana-quic median | Neqo median | Latency ratio |
| --- | ---: | ---: | ---: |
| 1 MiB | 0.036542986 s | 0.011526408 s | 3.17x |
| 32 MiB | 0.692855196 s | 0.052620986 s | 13.17x |

Peak client RSS was about 10.6 MiB, compared with about 7.5 MiB before
the host receive-window increase. These remain local measurements; the gap
is too large to meet the near-Neqo target. See `proofs/owned-body-input/` for
ownership checks and separately scoped sending-path diagnostics.
The earlier checkpoint below is retained as measurement history.

## Reproducible workload

`adapters/host/tests/compare_release_clients.py` compares release clients against
one unchanged Neqo release server. Both clients download the same generated
zero file, write it to disk and pass its SHA-256 check. Settings are loopback,
one stream, QUIC v1, AES128, PMTUD disabled. Three measured runs follow warmup;
client order alternates. Download latency includes process startup and handshake,
but excludes final connection draining. CPU and RSS come from the child process.
Profiling samples are kept separate from benchmark results.

The 2026-10-04 measurements used Hibana `be02c869b75d62b6e99b19f1bc9d34c16a9c345e`
and Neqo `ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95`.
The subsequently pinned Hibana correction changes proof fixtures and test style,
not the measured production runtime.

| File | hibana-quic median | Neqo median | Latency ratio |
| --- | ---: | ---: | ---: |
| 1 MiB | 0.072511137 s | 0.008658295 s | 8.37x |
| 32 MiB | 2.190586735 s | 0.048221345 s | 45.43x |

The original 1 MiB candidate took 3.323310267 s in a single baseline run.
Its 32 MiB download did not complete within 60 seconds. This historical single
baseline is not a repeated-sample estimate. Current 32 MiB throughput is only
14.61 MiB/s versus Neqo's 663.61 MiB/s. The bulk-transfer gap is still large;
the small-file ratio must not be presented as general performance parity.

## Retained changes

- Hibana validates immutable resolver metadata once and uses certified lookup.
  Certified passive-child traversal visits the relevant subtree. The upstream
  proofs and tests retain malformed-descriptor rejection and ambiguity checks.
- Application delivery drains the backed receive window, rather than splitting
  it into send-chunk-sized local messages.
- Flow-control updates batch at half of the actual backed window, with explicit
  handling for tiny windows and the maximum offset. Credit is still backed by
  real released receive capacity and recovery owns retransmission evidence.
- The receiver processes only already-ready datagrams opportunistically. It
  flushes ready streams before waiting for input, after 64 datagrams or a 1 ms budget of
  work, before peer close, and when an ACK receipt requires consumption. A
  pending receive remains pinned and owned during delivery; it is not cancelled
  and reissued to obtain batching. The loop yields at bounded batch boundaries.

No extra timer is used to wait for a full batch, and the peer's ACK-delay contract
is not widened. Normal packet authentication, key ownership, finite retirement
joins and failure paths remain in use.

## Rejected experiments and remaining work

Event-wake coalescing had no reproducible speedup and was reverted. A key-ACK
message batch also failed to justify its additional retained storage and was
reverted. Neither experiment is part of this implementation.

Sampling of the current workload still finds substantial time in Hibana's role
scope lookup and local-event decoding. Optimize these only with unchanged
contracts, a measured benefit, and checks of code size and memory as well as CPU.
WAN behavior, loss/reordering performance, multiple streams, the server path,
client 0-RTT and the remaining official interoperability cells need separate
qualification. This benchmark does not qualify them.
