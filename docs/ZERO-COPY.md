# Buffer ownership and copies

This implementation is not end-to-end zero-copy. An owned Rust array moving
between futures is not evidence that its machine-code memory copy disappeared.
These boundaries must be measured separately from allocation counts.

## Receive delivery

`quic::application_stream::App::consume` presents two borrowed slices of the
actual receive ring to a synchronous consumer. It performs no payload copy.
The consumer returns the prefix length it consumed; only then does the numeric
kernel consume bytes and replenish flow credit. Rejection or an excessive count
keeps receive bytes and credit intact. FIN is reported only when the full final
prefix has been consumed. This is a scoped numerical operation, not another
protocol-progress owner.

A consumer cannot keep these slices across an await. Doing so would keep the
receive ring borrowed while independent receive work needs to progress. The
existing asynchronous file/request profile therefore retains owned bytes. Its
request path now copies directly from the ring into the bounded retained
request, removing the intermediate RX-sized array and second payload copy.
This reduces two explicit copies to one; it does not make the complete request
path zero-copy or establish that moving its owned array has zero memory cost.

`App::read` remains the explicit copying interface for consumers needing owned
bytes. Both interfaces use the same consume/credit accounting.

## Boundaries still to improve

- Packet receive/reassembly: authenticated STREAM fragments are copied into the
  bounded receive ring. Reordering, overlap validation and independent packet
  buffer reuse currently rely on this storage. A leased packet pool would need
  bounded retention and equivalent handling of fragmentation/overlap first.
- Async response delivery: the present `StreamSink` borrows a staged chunk across
  its own future. The ring-to-staging copy remains. A future leased-buffer API
  must permit independent RX and make cancellation release the actual lease.
- Send admission: `BodyReader` fills a temporary chunk, then `SendQueue::enqueue`
  copies into retransmission storage. Direct filling requires ownership of a
  reserved queue slot through the read, with commit/cancel and peer flow-credit
  accounting. Removing the copy without that ownership is unsafe.
- Packet construction/encryption: retained plaintext cannot be encrypted in
  place and reused as the same plaintext for later packet numbers. Packet
  assembly copies must be distinguished from repeated unnecessary staging.
- Host UDP: no kernel-to-userspace or NIC zero-copy claim is made.

Any further change must preserve retransmission until real ACK, partial
acceptance, cancellation, loss/reordering and bounded memory. No new flag or
external state machine may replace the existing Hibana ordering.

## Current verification

The borrowed-ring regression checks pointer identity, ring wrap, partial FIN,
consumer rejection and excessive consumption. Full connected/Host regression
and interop qualification must be rerun for each published source revision;
prior revision CI results do not qualify an edited buffer implementation.
