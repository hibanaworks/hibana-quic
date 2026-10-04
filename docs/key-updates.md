# Scoped key ownership

The combined `ApplicationKeys` controller and the provider's legacy branch are
deleted. The TLS provider retains raw generation-zero directional material only
until KeySource transfers it. It does not implement a second key-update machine;
its old confirmation/update/ACK entry points reject Unsupported. Live connections
use independently owned ApplicationReadKeys and ApplicationWriteKeys.

Peer updates cross the actual projected RX_KEYS/TX_KEYS choreography. An
AEAD-authenticated peer-update receipt moves to the write owner, and the installed
write-epoch receipt returns to RX before new-generation ACK eligibility exists.
A copied wire label cannot substitute for either resource. No key borrow survives
an endpoint or UDP await.

Write-side confirmation retains the actual scoped confirmation receipt. Update
readiness retains the actual Recovery-issued ACK receipt and a numeric deadline;
the redundant handshake_confirmed/current_acked flags and epoch-less ACK fallback
are removed. Local updates still enforce actual sent-packet bounds, equal RX/TX
generations, monotonic time, positive PTO, prepared keys and the three-PTO policy.
Wire phase bits and generation/packet-number arithmetic remain data.

On projected key-role retirement, the actual application write key moves out of
the ordinary owner and into the finite closing receipt. The owner and RX control
retirement flags are removed. RX retirement consumes its control object. Dropping
a closing receipt drops its key; ordinary sending cannot recover it.

Directional tests cover both cipher suites, independent raw-key ciphertext
comparison, phase wrapping, unchanged header protection, nonce monotonicity,
foreign-scope rejection, missing/dropped receipts, old-key expiry, invalid ACKs,
integrity exhaustion and deadline checks. These are component tests, not official
keyupdate interop qualification. The local-update transport path and residual
receive-side transition representation remain part of the ongoing migration audit.

The receive-side Pending enum is also deleted. During write-epoch coupling the
actual receive PacketKey moves inside the authenticated/readiness receipt and
returns only with the matching installed/cancelled outcome. Missing or dropped
receipts leave no key with which RX can authenticate another packet. This is
resource transfer, not a copied pending-state marker.

Local initiation now crosses the existing RX_KEYS/TX_KEYS global with explicit
LocalUpdate, Installed/Rejected and Settled edges. Its cryptographic prepare,
initiate and completion methods are crate-private. Isolated role tests use real
keys/endpoints and zero allocation; the positive test supplies synthetic ACK and
confirmation evidence explicitly, not a real peer exchange. Live trigger policy
and official keyupdate interoperability are not qualified by these tests.
