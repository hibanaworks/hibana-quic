# Current implementation

Start with [architecture](ARCHITECTURE.md), [guarantee boundaries](GUARANTEES.md),
[qualification](QUALIFICATION.md), and [running HTTP/3](GETTING-STARTED.md).

The current cleanup changes module placement and exposes host IO/buffer
construction. It does not yet provide the planned complete, easy-to-embed
Hibana application transport over network QUIC streams. That is an explicit
remaining deliverable, not something supplied by the internal descriptor carrier.

## Bounded KeyUsage extraction

Production certificate KeyUsage traversal now uses the borrowed, bounded reader
in the paired hibana-tls crate. It does not implement a general X.509 verifier;
webpki still owns chain, name, signature, validity and critical-extension checks.
The normal/build QUIC graph no longer includes the external `der` package.
Independent DER remains in isolated test graphs for comparison, not production.
The candidate passed 599 core/integration/doc tests, 124 Host tests, 58 reference
tests (one existing private-fixture case ignored), and thumbv6m compilation.
The TLS crate passed its full tests, strict Clippy and thumbv6m compilation.
These results do not complete TLS local ownership migration, cryptographic
security qualification or fresh official interoperability qualification.

## Entropy boundary candidate

The paired TLS crate now defines one direct fallible entropy input contract.
QUIC key generation, Retry/NEW_TOKEN issuance and ticket keys consume it directly;
there is no rand_core adapter or replacement application RNG state machine.
The Linux Host uses safe standard-library reads from the opened /dev/random
character device, verifies Linux device 1:8 from that descriptor and reads the
whole requested buffer. It fails if the device is absent or substituted and
never falls back to counters, timestamps or uninitialized urandom. This changes
the Host's environment contract: /dev/random must be available. Linux >=5.6
blocks only until initialization; older kernels may block on later entropy
pressure. See https://man7.org/linux/man-pages/man4/random.4.html.
This is an OS entropy boundary, not a claim of implementing or proving the
kernel RNG. The final candidate passed 600 core/integration/doc tests, 125 Host tests,
58 independent reference tests (one existing ignored fixture), and thumbv6m
checking. The paired TLS crate passed 43 tests, strict Clippy and thumbv6m.
These are regression checks, not a proof of kernel RNG quality.

## Direct ownership candidate

The old stored TLS State enum and the four handshake/application key-created
and key-discarded flags have been removed in this candidate. Handshake and
application traffic secrets transfer exactly once; Finished MAC keys are actual
separately derived secrets, so packet-key handoff cannot recreate the source
material or prevent the later Finished verification. Early retirement destroys
the actual ECDHE/derivation material. No tombstone IntegrityBudget is created.

The real Finished receipt now survives early-data processing and stays with the
application RX continuation. Post-handshake CRYPTO input borrows that exact
scope-bound receipt instead of consulting a historical Connected flag. The
source cannot synthesize or receive-decode that authority. Resumption reporting
also reads the authenticated receipt. One-call failures preserve unconsumed
ownership where specified; incorrect scope, duplicate transfer and retirement
are covered by explicit regression cases. The source guard rejects a return of
the removed fields; it is not a behavioral proof.

Full candidate regressions and subsequent paired-checkout integration remain
pending. The numeric TLS owner and its direct local implementation still reside
in this repository while sharing the hibana-tls global. This change must not be
reported as completion of the entire separate-crate TLS-local extraction.


## Canonical TLS material extraction

The key schedule, TLS handshake syntax, shared immutable ALPN profile and bounded
RSA verifier have moved into hibana-tls. The QUIC modules reexport their actual
types instead of keeping copies or adding runtime forwarding. Existing subtle
and zeroize packages are shared by the extracted material; this is not an
external-dependency reduction. The external closure is unchanged.
The TLS extraction candidate passed 105 tests, strict Clippy and thumbv6m checks.
Fresh full paired QUIC/Host/reference qualification remains pending.
