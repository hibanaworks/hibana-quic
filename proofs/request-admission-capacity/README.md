# Request admission must not block transport acknowledgments

The source may be producing a response larger than the bounded send queue and
therefore waiting for network ACKs. If the server request mailbox fills first,
the sink waits to enqueue another completed GET while RX waits for that sink.
RX then cannot receive the ACKs needed by the source. A forty-file native-peer
case with 128 KiB responses reproduced this stall on the preceding published
binary, while three and five ordinary files completed.

Each queued or produced request owns one distinct admitted stream slot through
its affine `Production` value. A mailbox sized to `MAX_LIVE_STREAMS` can therefore
accept every admitted request without waiting for a response body to complete.
The bound is explicit caller-owned storage (64 request values), not an unbounded
queue, a replacement protocol controller or a fabricated completion flag.

Lean and Z3 prove the capacity implication under the disjoint-owner premise and
show the old eight-entry counterexample. Rust ownership and stream admission
establish that premise in the integration; the models do not automatically prove
all Rust code. The unit regression enqueues all admitted slots while the consumer
is paused, then checks exact FIFO receipt. Real peer transfer tests cover larger
response bodies and all file hashes; official interoperability remains separate.

    lean Capacity.lean
    python3 check_capacity.py
