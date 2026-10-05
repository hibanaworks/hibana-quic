# Request-backed host receive windows

The host knows the client's request count before constructing its transport
parameters. It allocates that many receive slots, rather than sixty-four slots
for every single request. One through four requests use a 1 MiB window per
stream; five through sixty-four use the existing 64 KiB window. The server
retains sixty-four 64 KiB slots. Thus receive payload storage never exceeds the
previous 4 MiB pool; the unchanged presence arrays are additional storage.

The exact same selection supplies the advertised TLS transport parameters and
the actual stream-table allocation. Existing core validation rejects credits
beyond supplied storage. The native file count and all payload hashes remain
checked. No endpoint operation, authentication, ACK evidence or retirement join
is bypassed, and there is no new public core API or protocol control flag.

Opportunistic receive work retains the 1 ms work-budget check and the existing
flush-before-wait, peer-close and pending-ACK boundaries. Its count bound scales
with the backed receive window, with the existing minimum of 64 datagrams. This
is cooperative batching, not a hard real-time latency guarantee.

Lean and Z3 prove the bounded arithmetic budget for validated request counts.
They do not prove OS allocation behavior or complete QUIC correctness. Rust
tests cover invalid capacities and both selection branches; native diagnostics
cover 3, 5, 40 and 64 ordinary files in both directions, including files larger
than the small receive window. Official runner qualification is separate.

    lean Bounds.lean
    python3 check_bounds.py
