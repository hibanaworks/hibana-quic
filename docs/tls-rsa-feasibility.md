# Bounded RSA signature verification

The production adapter supports exact 2048/3072/4096-bit public moduli and odd
32-bit exponents. It performs verification only: no signing, encryption, private
key operation or key generation is implemented here.

`src/tls/rsa/public_key.rs` validates the exact borrowed DER SEQUENCE of two
nonnegative, minimally encoded INTEGERs. It rejects indefinite/nonminimal lengths,
truncation, negative integers and trailing fields/bytes before arithmetic.
`src/tls/rsa.rs` invokes fixed-width modular arithmetic.
`src/tls/rsa/encoding.rs` owns the SHA-256 PKCS#1 v1.5 and PSS encoding checks.
PSS requires MGF1-SHA256 and exactly 32 salt bytes. PKCS#1 v1.5 requires the exact
SHA-256 DigestInfo encoding. Unsupported widths reject before indexing.

The extracted RustCrypto helper copy has been removed. Public-key arithmetic,
SHA-256 and byte-comparison dependencies still remain; the external `pkcs1`
package is removed from production, host and reference manifests/locks. The `der`
package still serves certificate parsing and independent test encoding, so
external-dependency
elimination is unfinished. Reference corpora and independent negative tests are
under tests/vectors/rsa and tests/tls-reference/tests/rsa_vectors.rs. Each
verification invocation is allocation-counted in the host test harness.

Six Lean lemmas in proofs/rsa-encoding/Layout.lean establish layout arithmetic
and exact-byte equality properties. They do not prove Rust refinement, RSA
security, the hash assumptions, constant-time machine code or the whole TLS stack.
