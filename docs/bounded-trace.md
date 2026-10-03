# Opt-in bounded qlog writer

`src/trace.rs` is the caller-buffer writer. `HandshakeEndpoint::enable_trace`
now explicitly opts into a metadata-only endpoint event subset; the HQ executable
still does not write qlog files. Standalone serializer tests use invented fixtures,
while `bounded_wire` separately exercises real encrypted endpoint observations.
Neither kind of test is a runner verdict. No TLS key exposure was added.

## Format and references

The format is pinned to these primary, work-in-progress specifications, checked
on 2026-10-02:

- [qlog main-schema-14](https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-14.html):
  sections 5/5.1 (sequential file), 6 (vantage point), 7.1 (time), 11.2/11.3
  (JSON-SEQ and integer interoperability), 12.1 (output paths), 14 (privacy)
- [QUIC qlog events-13](https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-13.html):
  sections 2.1 (draft identification), 5.5–5.7 (packet observations),
  5.10/5.11 (UDP), 6.1 (key generation), 7.4 (loss), 8.8 (packet headers)
- [RFC 7464 section 2.2](https://www.rfc-editor.org/rfc/rfc7464#section-2.2):
  JSON text sequence framing

The header identifies `urn:ietf:params:qlog:file:sequential` and
`application/qlog+json-seq`; the QUIC event schema is explicitly draft-qualified
as `urn:ietf:params:qlog:events:quic-13`. Records start with byte `0x1e` and end
with LF. Use `.sqlog` for future output files. These are current draft schemas,
not the older `qlog_version: "0.3"` layout. Older qlog tools may need conversion;
compatibility with qvis or a full external CDDL validator has not been tested.

The caller supplies microseconds from a fixed monotonic origin. Output is
decimal milliseconds with three fractional digits; no floating-point operations
are used by the writer. The header declares an unknown monotonic epoch and
`relative_to_epoch`. Uint64 metadata uses decimal JSON strings, preserving
large packet numbers/generations. A consumer using binary floating point for
time may round extreme durations; exact microsecond precision at `u64::MAX`
is not promised by that consumer. Same-tick events are allowed; decreasing
timestamps are rejected.

## API and ownership

`QlogWriter::new(&mut caller_buffer, vantage)` opts into serialization for one
connection, one vantage point, and one output sink. There is no global logger,
feature-triggered side effect, environment lookup, clock read, file creation,
I/O callback, or unbounded queue. The writer borrows the buffer and stores only
offsets and the last accepted timestamp. Each typed event contains fixed-size
values; no strings, byte arrays, lists, raw frame/payload data, network addresses,
connection IDs, tokens, certificates, or key values can be supplied.

`push(at_micros, event)` validates the supported metadata and measures the full
record before writing. On any error, pending bytes, backing-buffer contents,
and the last accepted timestamp remain unchanged. `Capacity { required,
available }` reports the whole record size and available space, including
reclaimable consumed bytes. There is no eviction, truncation, implicit drop,
or invented loss event. A 512-byte caller buffer is sufficient for the current
header and any single supported event after draining, but not an arbitrary
number of queued events.

Use `pending()` as ordered output. After the sink accepts `n` bytes, call
`consume(n)`. Partial writes are supported and later appends compact only the
unconsumed suffix if needed. An I/O error must leave unaccepted bytes pending.
An over-consume is rejected. Preserve the same sink and write ordering; moving
only the suffix to another file does not produce a complete trace.

A capacity error does not retain the event. The adapter must keep that event
and its original timestamp, drain output, and retry before logging subsequent
events, or explicitly declare the trace incomplete. If lossless capture is
required, integration must reserve/flush enough logging capacity at its actual
event boundary. Logging failure must never roll back an already accepted
network send, acknowledge bytes not owned by the transport, or fabricate a
protocol action. There is deliberately no user callback inside the writer.

JSON-SEQ needs no trailer. Drain all pending bytes and check sink errors before
claiming a complete file. Dropping a writer with pending output loses that
output; memory-level transactional writes do not make filesystem writes atomic.

## Event semantics and future integration

The current subset covers packet send/receive, individual UDP send/receive,
packet drop, threshold-based loss declaration, and installed application-key
generation metadata. Missing optional packet number/key phase fields stay
missing. Retry, Version Negotiation, stateless reset and unknown packets cannot
be assigned packet numbers by this API. A loss event requires a numbered
packet. Key-phase generations are full counters, not a phase-bit guess:

- [Events-13 section 6.1](https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-13.html#section-6.1)
  defines `key_updated.key_phase` as `uint64` and explicitly identifies it as
  the full generation (@M/@N in RFC 9001 Figure 9); the wire bit is its LSB
- [Events-13 section 8.8](https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-13.html#section-8.8)
  distinguishes `PacketHeader.key_phase: uint64` from `key_phase_bit: bool`.
  Both are restricted to 1RTT; the bit is an alternative when the full phase
  is unavailable. This writer exposes only the full-phase field, and callers
  must leave it `None` if they know only the protected/header phase bit
- Main-schema-14 section 11.3 permits these `uint64` values to be represented
  by decimal JSON strings. Generations above one remain intact, not reduced
  to parity, in both supported event shapes

Future endpoint instrumentation still needs to establish and test:

1. A send is observed only at the documented successful acceptance boundary;
   a rejected send is never counted as sent
2. Each packet in a coalesced datagram has a separate packet observation and
   can reference the same per-direction datagram ID
3. Protected header fields come from authenticated processing, not raw bytes
4. Drop reasons reflect actual processing results; unknown fields stay unknown
5. Loss events originate from real loss detection, not merely a PTO expiration
6. UDP ECN values come from actual socket metadata; this API requires a known
   codepoint and must not substitute Not-ECT for unavailable observations
7. Key-generation events occur after installation and contain no key values
8. Stream/ACK/frame/recovery/path/lifecycle instrumentation, bounded observer
   ownership, allocation counters, and malformed/interrupted output paths

No existing endpoint behavior or acceptance result changes from this writer.

## Pinned runner contract and private evidence

The locally inspected runner is
[`740c05a10b61d65e8abd3ad38d60898004d335d9`](https://github.com/quic-interop/quic-interop-runner/tree/740c05a10b61d65e8abd3ad38d60898004d335d9).

- Its [README logs contract](https://github.com/quic-interop/quic-interop-runner/blob/740c05a10b61d65e8abd3ad38d60898004d335d9/README.md#logs)
  directs qlog files to `QLOGDIR` and NSS-format TLS logs to `SSLKEYLOGFILE`
- Its [compose file](https://github.com/quic-interop/quic-interop-runner/blob/740c05a10b61d65e8abd3ad38d60898004d335d9/docker-compose.yml#L38-L43)
  sets `QLOGDIR=/logs/qlog/` and `SSLKEYLOGFILE=/logs/keys.log` for both roles
- [TestCase lines 169–220](https://github.com/quic-interop/quic-interop-runner/blob/740c05a10b61d65e8abd3ad38d60898004d335d9/testcase.py#L169-L220)
  choose a nonempty keylog containing a server-handshake-secret label, prefer
  the client log, and may inject the secrets into the simulator capture with
  `editcap`. This presence check is not cryptographic validation of a log
- [TraceAnalyzer](https://github.com/quic-interop/quic-interop-runner/blob/740c05a10b61d65e8abd3ad38d60898004d335d9/trace.py#L99-L109)
  analyzes pcaps with PyShark/Wireshark and the TLS keylog preference. Qlog is
  auxiliary diagnostic output, not a replacement for pcap/file assertions
- [Interop log copying](https://github.com/quic-interop/quic-interop-runner/blob/740c05a10b61d65e8abd3ad38d60898004d335d9/interop.py#L500-L510)
  preserves client, server, and simulator logs for successful and failed cases

Therefore raw runner log directories and secret-injected pcaps must be treated
as secret-bearing. Excluding only `keys.log` from an upload is insufficient.
Future keylogging must require explicit test-only opt-in and use private,
ephemeral, access-restricted local files; never console or public artifacts.
Do not inherit `SSLKEYLOGFILE` as silent authorization to expose TLS secrets.
This implementation neither reads that variable nor emits keylog records.
Even metadata-only qlog can reveal timing/traffic patterns and merits careful
retention/access control. No real secret was generated or exported for these
writer tests.

## Reproducible verification

With Rust 1.95 and `thumbv6m-none-eabi` installed:

```sh
cargo test --locked --test bounded_trace
python3 -m unittest discover -s tests -p test_bounded_trace.py -v
cargo clippy --locked --lib --test bounded_trace -- -D warnings
cargo check --locked --lib --target thumbv6m-none-eabi
rustc --edition=2024 --target thumbv6m-none-eabi -C opt-level=s \
  -C panic=abort -C link-arg=-e_start tests/support/trace_target.rs \
  -o /tmp/hibana-trace-thumb.elf
```

The Rust tests cover every short header capacity, every insufficient event
capacity for the sample shapes, exact-fit records, rejection atomicity,
compaction through small partial writes, invalid metadata, clock regression,
integer boundaries, and allocation-counted writer paths. Python independently
parses real serializer output and validates 36 fixture events covering all enum
spellings and selected schema shapes. The same exercised bounded paths link in
an allocator-free target image. These are component checks, not complete TLS/
QUIC no-allocation closure, an external schema certification, a full runner
matrix, or bootable/measured Pico firmware.

## Current endpoint observation subset

Opt in before I/O with caller-owned output storage. The wrapper forwards
`enable_trace`, `trace_status`, `trace_pending`, `consume_trace` and
`mark_trace_sink_failed`. No callbacks, files or environment variables are used.
Trace data remains drainable after protocol retirement.

- A packet send is recorded only after an exact pending adapter authority matches
  an accepted submission. Rejected and stale callbacks never invent a send
- Packet receive metadata is emitted after successful packet authentication,
  including actual 0-RTT protection. It does not claim frame admission or
  application delivery; no unauthenticated packet number is guessed
- Initial application-key installation and actual local/remote generation
  changes emit metadata only. Pending sends retain the generation used to seal
- A newly declared loss records the retained original protection type, including
  the shared 0/1-RTT PN distinction. Its optional cause is omitted because the
  current detector does not expose the winning threshold; PTO alone is not loss

This is not complete qlog coverage: socket UDP observations, raw frame contents,
CID/path events, all discard causes and host sink integration remain absent.
Datagram linkage is omitted, rather than inventing IDs or unknown ECN values.

Trace overflow never rolls back transport actions or changes a transport result.
It increments a sticky lost-event count; the first writer error, diagnostic-counter
exhaustion and explicit sink failure also remain visible after draining. A caller
must reject any complete-capture claim if status is incomplete, bytes remain pending,
or a sink write/flush failed. Completeness applies only to this stated event subset.

Actual bounded-wire tests run the same handshake, corruption/PTO, reordered old
keys, key updates and close/retirement with tracing disabled, a large trace buffer,
and forced overflow. All three paths measure zero allocations. Separate assertions
cover stale/rejected adapter callbacks, Busy retries, bad authentication, short sink
consumption after retirement and sticky errors. No qlog file or traffic secret is
published by these tests.
