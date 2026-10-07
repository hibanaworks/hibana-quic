# Mandatory RSA verification: feasibility and dependency gate

Assessment history: 2026-10-02. The first assessment below found no acceptable
public no-alloc RSA verifier API. The subsequently approved mechanical-extraction
adapter now exists in `src/tls/rsa.rs`, with six upstream function bodies
preserved and 1,224 complete signature cases passing at zero measured allocations.
Independent review found no blocking primitive defect; see
`artifacts/rsa-independent-review/REVIEW.md`. The certificate component now
verifies real RSA/mixed chains and exact algorithm parameters. A bounded client
authenticates independent rustls RSA servers at all three supported widths, with
zero measured allocations in its constructor/handshake/packet calls. RSA server
signing, mandatory-algorithm completion and final embedded stack qualification
remain open. The sections below retain the earlier investigation history.

## Protocol scope

[RFC 9846 §9.1](https://www.rfc-editor.org/rfc/rfc9846.html#section-9.1) retains
mandatory RSA PKCS#1 v1.5/SHA-256 for certificate signatures and RSA-PSS/SHA-256
with rsaEncryption public keys for certificates and CertificateVerify, alongside
ECDSA P-256/SHA-256. PSS uses MGF1 with the same hash and exactly a digest-sized
salt, hence 32 bytes here. PKCS#1 v1.5 is not a TLS 1.3 CertificateVerify scheme.
These requirements are distinct from QUIC's AES-128-GCM packet suite and
[RFC 9001's TLS integration](https://www.rfc-editor.org/rfc/rfc9001.html).

An implementation of verification alone would let a bounded client validate RSA
server identities and RSA-signed CA chains. It would not add an RSA signing
credential to the bounded server. RSA-PSS-restricted SPKI keys (scheme 0x0809),
SHA-384/SHA-512 and other optional profiles need separate decisions; they must
not be advertised by accident.

## Actual inspected packages

Package archives were fetched using the official crates.io registry; hashes and
embedded VCS revisions are pinned in
`artifacts/rsa-feasibility/20261002-042700/packages.json`. This avoids confusing
stale search-index `latest` pages with the registry versions actually inspected.

### Standard RustCrypto RSA

- `rsa = 0.9.10`: `src/key.rs` stores public modulus/exponent as `BigUint`;
  `src/lib.rs` imports alloc. Disabling std does not remove the heap
- `rsa = 0.10.0-rc.18`: the current registry prerelease uses `BoxedUint` in
  `RsaPublicKey`; PSS and PKCS#1 verification convert the signature to that boxed
  type and allocate result storage. `extern crate alloc` is unconditional
- Existing project `crypto-bigint = 0.5.5` does offer fixed-size integers, but
  these RSA public APIs are not generic over that type. Replacing the exponentiation
  and padding verification locally would create the bespoke crypto prohibited
  by this task

Upstream [heapless issue 51](https://github.com/RustCrypto/RSA/issues/51) remains
open. [Fixed-size key PR 636](https://github.com/RustCrypto/RSA/pull/636) was closed
without merging, while [alloc-gating PR 631](https://github.com/RustCrypto/RSA/pull/631)
is still WIP. Neither is a released fixed-storage verifier to depend on.

### rsa_heapless fork: technically relevant, not accepted as vetted

The official registry currently serves `rsa_heapless = 0.5.0`, source commit
`a598be1f5f7d6a6e8ec87a0fdb54e1a72a1a8c76`. Its
[documented API](https://docs.rs/rsa_heapless/latest/rsa/) and actual source
include `pss::verify_digest_into` with caller-provided scratch, generic public
keys, and a no-alloc path. The errors on that path are enums with static messages.

However:

- Its manifest unconditionally enables `fixed-bigint`'s `use-unsafe` feature;
  the bigint/modular backend is `fixed-bigint`/`modmath`, not the already-used
  RustCrypto `Uint` implementation
- `GenericRsaPublicKey::from_components` explicitly expects validated inputs;
  its implementation checks nonzero modulus but delegates other validation
- The retained upstream audit reference does not establish review coverage for
  this replacement arithmetic/backend and new generic paths. No independent
  audit of those changes was established in this investigation
- Existing Wycheproof integration is gated on its allocating `encoding` feature
  and uses the allocating public-key types. It does not itself qualify the
  fixed-storage path; that path needs its own vector runner and failure tests
- Its encoding feature enables alloc, so borrowed DER import would still need
  to use the already-vetted project DER parser plus a reviewed adapter

The fork is an isolated-prototype candidate only after dependency/security review.
No fork code was executed or introduced into the release dependency graph here.
Its name and no-std build claim are insufficient approval evidence.

### Other checked routes

Existing `ring = 0.17.14` source labels RSA verification alloc-only and allocates
bigint limbs during public operations; it cannot fill this no-alloc target gap.
[Graviola](https://docs.rs/graviola/latest/graviola/) limits its supported CPU
architectures to aarch64/x86_64, excluding thumbv6m.
The inspected [BearSSL Rust bindings](https://docs.rs/bearssl/latest/bearssl/type.br_rsa_pkcs1_vrfy.html)
expose unsafe C function pointers rather than a vetted safe Rust integration for
this profile. Introducing a new FFI safety layer is outside this assignment.

## Proposed bounded profile, once a backend passes the gate

This is a proposal, not negotiated capability:

1. Support RSA modulus sizes 2048, 3072 and 4096 bits initially; reject smaller,
   larger or unsupported widths before modular arithmetic. Document exact-size
   restrictions as a bounded profile, not universal RSA compatibility
2. Review a bounded public-exponent policy, such as odd 3..2^32-1, with explicit
   rejection rather than silently assuming 65537. Validate modulus oddness,
   positive canonical DER INTEGERs, exponent constraints, signature length and
   representative range using vetted parsing/arithmetic APIs
3. Expose borrowed verification through existing pki-types
   `SignatureVerificationAlgorithm` hooks. Use its `RSA_ENCRYPTION`,
   `RSA_PKCS1_SHA256` and `RSA_PSS_SHA256` identifiers so webpki checks key and
   signature AlgorithmIdentifiers. Preserve chain, name, validity, constraints,
   EKU and digitalSignature/keyCertSign checks
4. Set PSS salt length explicitly to Some(32); never enable permissive automatic
   salt-length discovery for the TLS scheme. Hash CertificateVerify's existing
   context-prefixed signed content exactly as the protocol requires
5. Advertise 0x0804 and certificate-only 0x0401 only after the corresponding
   verifier and end-to-end tests exist. Keep server credential selection honest
6. Use caller scratch sized for the selected maximum key profile, checked
   lengths, and non-allocating error mapping. No formatting into owned strings
   on attacker-controlled rejection paths

## Target cost: established bounds versus unmeasured work

A 2048/3072/4096-bit integer alone occupies 256/384/512 data bytes, equivalent to
64/96/128 32-bit limbs. This is only representation size, not a verification
stack bound. Modulus contexts, intermediate integers, padded messages and hashes
add working storage; generic size dispatch can also multiply code size.

The fork author's published Cortex-M0 RSA-2048 PSS/SHA-256 example reports about
7 KiB text and 13,984 bytes stack. Those are **author-reported** example results,
not this project's measurements or an RSA-4096 bound. The project must measure
2048, 3072 and 4096 separately, then the worst nested webpki chain plus RSA call
path. Current long-chain validation already has a substantial stack footprint.
No credible final Pico RAM/stack/flash total can be quoted before this is built
and measured with pinned flags and the full linked endpoint.

## Required evidence before integration

- Pin reviewed backend/source/dependency hashes and verify the no-std/no-alloc
  feature closure and thumbv6m compilation/linkage without allocator symbols
- Run the fixed-storage path against pinned C2SP Wycheproof
  [RSA-PSS/SHA-256](https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pss_2048_sha256_mgf1_32_test.json)
  and [PKCS#1/SHA-256](https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_signature_2048_sha256_test.json)
  corpora, including corresponding 3072/4096-bit files
- Test malformed padding/DigestInfo, wrong hash/MGF/salt/trailer, leading bits,
  short/overlong signatures, signature >= modulus, invalid exponent/modulus,
  truncated/noncanonical DER and oversized inputs. Compare with OpenSSL and
  pinned rustls/ring independently, never only self-generated/self-verified data
- Generate real RSA and mixed RSA/ECDSA CA/intermediate/leaf chains; verify
  hostname, validity, key usage, path length, name constraints, wrong CA and
  modified certificate/CertificateVerify negatives without bypasses
- Measure zero allocations during key import, valid/invalid verification,
  webpki integration and full RSA-authenticated TLS; fixture generation and
  independent peer may allocate outside clearly marked counters
- Measure maximum stack/code/latency for all allowed widths on thumbv6m and the
  complete longest-chain endpoint. Re-run after dependency or compiler changes

Until an acceptable backend/review path is chosen, the existing P-256 profile
must continue reporting the mandatory RSA gap. Passing P-256 runner fixtures or
PSK resumption cannot waive this independent algorithm requirement.

## Narrower official-component assessment (04:44 UTC)

A second pass establishes a technically narrower path; the remaining blocker is
now specific. **Official fixed-storage arithmetic and borrowed parsing work.
A supported public no-alloc PSS verifier API is still absent.**

The isolated `artifacts/rsa-feasibility/20261002-044400/foundations` crate uses
only `crypto-bigint = 0.5.5`, `pkcs1 = 0.7.5`, and `der = 0.7.10`, with default
features disabled. It contains no unsafe or allocation. The actual feature tree
has no alloc/std feature. Its three host tests and thumbv6m compilation pass.
For 2048, 3072 and 4096-bit published Wycheproof signatures it parses borrowed
PKCS#1 DER and invokes the official `DynResidue::pow_bounded_exp` API. Recovered
encoded messages match independent Python modular exponent results. Truncated
DER, incorrect signature length and signature >= modulus reject. These tests
**do not verify PSS padding or authenticate a message**; the recovered block is
never presented as successful signature verification.

The exact standard helper route to investigate next is a mechanical,
provenance-preserving extraction of the following private RustCrypto RSA0.9.10
functions, or upstream exposure of equivalent supported APIs:

- `algorithms/pss.rs`: `emsa_pss_verify_pre`, `emsa_pss_verify_salt`, and generic
  `emsa_pss_verify_digest`; these operate on caller-provided encoded-message
  storage and fixed-output digest values
- `algorithms/mgf.rs`: generic `mgf1_xor_digest` and its counter helper. The
  similarly named dynamic-digest `mgf1_xor` in this version **does allocate** and
  must not be substituted
- For the required certificate PKCS#1 v1.5 path,
  `algorithms/pkcs1v15.rs::pkcs1v15_sign_unpad` is also slice-based. Its separate
  digest-prefix generator allocates, so an approved adapter would use vetted
  DER encoding or the standard SHA-256 DigestInfo constant, checked against
  independent fixtures

All of those verification helpers are currently private; the public RSA hazmat
module only reexports core RSA operations and does not expose PSS verification.
An extraction therefore creates a small vendored security-maintenance surface,
not a simple use of an already-supported public API. It must preserve licenses,
source hashes and a mechanically reviewable diff, exclude signing/encryption and
all allocating variants, validate buffer/key-bit preconditions before calling
the helpers, and receive independent security review. Upstream provenance is
not proof that the exact extracted composition was covered by an audit.

This route avoids writing bigint arithmetic, inventing a padding algorithm or
adopting the unrelated heapless fork. It remains conditional on that review and
the full vector/integration/negative-allocation gates above. No such helper
extraction or production verifier was implemented in this assessment.

The probe's actual thumbv6m release assembly also makes the storage tradeoff
concrete. With rustc1.95.0, release optimization and `-C lto=no`, visible static
call-path subtotals are 21,296 bytes (2048), 31,792 bytes (3072), and 42,288 bytes
(4096). The corresponding wrapper's own frames are 5,448 / 8,128 / 10,816 bytes.
The subtotal includes visible modular-exponent/square frames, but excludes
outside callees and TLS/X509 callers. It is not a whole-program bound and can
change with full-link optimization. Assembly and path breakdowns are preserved
beside the probe. A no-alloc API does not imply a small stack.

## Standalone adapter status (04:56 UTC)

After approval of the provenance-pinned mechanical extraction, `src/tls/rsa.rs`
now exposes `verify_pss_sha256` and `verify_pkcs1_sha256`, taking borrowed PKCS#1
public DER, message and modulus-width signature. Six unmodified upstream
verification functions are retained under
`vendor/rustcrypto-rsa-verification-0.9.10`, with both licenses and per-function
hashes. `tools/check-rsa-upstream.py` passes for the actual source and rejects a
changed temporary copy. The PSS path fixes the salt at32 bytes; generic dynamic
allocating helpers are absent.

`cargo test --manifest-path adapters/host/Cargo.toml --test rsa_vectors --release`
passes nine groups in0.48s. These cover1100 cases from six complete TLS-profile
Wycheproof corpora,124 upstream-valid signatures under unsupported salt/MGF
parameters that must reject, and DER/exponent/modulus/width/range/truncation
negatives. Every verification call is measured at zero allocations. Three
Wycheproof acceptable/noncanonical cases are deliberately rejected. The public
fixtures, licenses, pinned upstream revision and hashes are under
tests/vectors/rsa. The test oracle's salt-policy correction is retained in the
artifacts; no verifier logic changed to make that case pass.

OpenSSL3.5.7 independently validates one positive and changed-message rejection
for each of the six key-size/scheme combinations. The adapter compiles for
thumbv6m and passes strict Clippy. Logs are in
`artifacts/rsa-verification/20261002-045200`. Independent review is still required
before pki-types wrappers and certificate/wire integration. This result does not
remove the mandatory TLS algorithm release gap on its own.
