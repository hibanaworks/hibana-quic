# Bounded QUIC v1 key updates

`crypto::ApplicationKeys`, used by `BoundedTls`, implements the packet-level
update mechanism in [RFC 9001 §6](https://www.rfc-editor.org/rfc/rfc9001.html#section-6).
TLS KeyUpdate messages remain forbidden. This is not resumption or 0-RTT support.

## Stored keys and ownership

One non-cloneable owner holds current and precomputed next write keys, plus
current, next, and temporarily previous read keys. Every `PacketKey` owns private
fixed-size secret/key/IV/HP arrays and zeroizes them on discard/drop. A write
promotion destroys its predecessor immediately and preserves the last consumed
application packet number. The write phase toggles; packet numbers never reset.
The HP key stays unchanged. The now-unused TLS handshake schedule is destroyed
at completion, including duplicate generation-zero application secrets.

The next read and write keys are derived before they are needed, using RustCrypto
HKDF with the RFC `quic ku` label. Packet opening performs no HKDF and tries one
key selected using the phase and recovered packet number. It never retries
current/previous keys after a failed attempt. Where a candidate is unavailable,
a surrogate current-key AEAD attempt cannot yield accepted plaintext. Failed
AEAD checks share the provider's existing connection-wide integrity budget. The
bounded provider exposes that same non-resettable budget to the packet engine
for Initial protection, so Initial, Handshake and all application generations
contribute to one count. A wire regression preserves a corrupt Initial's count
through both application updates.

`maintain_keys(now, pto)` runs outside packet opening, before each datagram and
on timers. It replenishes precomputed keys after successful promotion and
expires previous keys. This avoids attacker-triggered derivation on invalid
phase guesses. It does not constitute a formal constant-time proof of the
whole header parsing, PN recovery, provider dispatch, or transport pipeline.

## Transport evidence and timing

The transport alone establishes QUIC handshake confirmation. TLS completion is
insufficient. `confirm_handshake()` records that evidence. Local initiation
requires it and a current-generation ACK; requiring an ACK even for the first
update is a conservative restriction. Later updates additionally wait three
PTOs after the first current-generation acknowledgment. PTO must be positive,
time must be monotonic, and both use identical caller-selected units. Overflow
or backward time fails explicitly.

`open_one_rtt` returns authenticated plaintext length and monotonic generation,
not just the wrapping phase bit. A peer-triggered update promotes write keys
before returning, so an acknowledgment cannot be encrypted with stale keys.
Previous read keys expire three PTOs after the first authenticated new-generation
packet. A locally initiated update never expires original read keys merely
because time passed while waiting for the peer's first updated response.
Authenticated contradictory key-generation/PN ordering is a terminal
KEY_UPDATE_ERROR. ACKs of newer sent packets carried under older read keys also
produce this error.

Before `acknowledge_one_rtt(sent_pn, received_generation, now, pto)`, the engine
must prove the PN was actually sent and covered by a valid authenticated ACK.
It validates ACK ranges against the sent ledger, including unsent holes. The
provider checks the high-water mark and classifies PNs against the first PN
sealed in the current generation; those checks alone cannot prove holes were
sent. `received_generation` must come from opening the exact ACK carrier.

A prepared application datagram holds the transport's write generation until
its adapter accepts or rejects it. While such output is pending, the engine
returns nonfatal Busy before processing input; the caller retains and retries
the datagram. Rejected output has already consumed its PN. Repackaging uses a
new PN. This prevents transmission of previously prepared old-key bytes after
an authenticated peer update.

## Evidence

- Seven crypto lifecycle test groups cover AES-128-GCM and ChaCha20-Poly1305,
  four generations including phase wrap, stable HP, monotonic send PNs, ACK and
  clock checks, malformed authentication, old-key expiry, missing candidate
  handling, and authenticated illegal generation ordering
- `reference-tls/tests/bounded_tls.rs` completes a certificate-authenticated
  handshake against raw pinned rustls 0.23.45 QUIC TLS and uses its public
  `Secrets::next_packet_keys()` to independently verify generations 0–4 in both
  suites, alternating local and peer initiation. Every bounded operation in
  that case is measured at zero allocations; rustls/PKI fixture work is excluded
- `reference-tls/tests/bounded_wire.rs` sends actual encrypted packets through
  Hibana and the sent ledger, initiates from both roles, verifies phase wrap,
  delayed old-packet acceptance, expired-key rejection, and pending-output Busy.
  The existing whole-flow allocation measurement includes these operations
- The allocating `RustlsProvider` wrapper does not expose key-update support;
  its independent raw rustls test is intentionally separate

These tests do not establish the Neqo runner keyupdate/40-case gate, a formal
side-channel proof, all-path memory guarantees, or a complete mandatory TLS
algorithm profile. Native `thumbv6m-none-eabi` compilation is checked separately;
Pico hardware and final stack/flash budgets remain distinct release gates.
