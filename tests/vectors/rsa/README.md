# RSA verification corpora

Public-only fixtures from C2SP/Wycheproof, pinned to the revision and source
SHA256 values in provenance.json. The upstream Apache2.0 license is retained.
No private key appears here. The binary representation only removes JSON/hex
fixture-decoding dependencies from the test executable.

Format: ASCII `RSAKAT01`, big-endian u32 record count, then records containing
u32 tcId, u8 expected_success, u16 key_len, u32 message_len, u32 signature_len,
followed by PKCS#1 public DER, message, and signature bytes.

The six SHA256 TLS-profile corpora are complete (1100 cases): PSS salt32 with
MGF1-SHA256 and PKCS1v1.5 at2048/3072/4096 bits. Valid cases must accept; invalid
and acceptable-noncanonical cases must reject under this strict profile.

The two additional out-of-profile corpora retain only their upstream VALID
signatures (124 cases), all of which must reject because their salt/MGF differs
from the TLS scheme. An INVALID verdict under a different salt/MGF policy is
not an expected rejection under the TLS policy: the original zero-salt corpus's
tcId69 is deliberately a valid salt32 signature. OpenSSL independently confirms
that distinction; the initial test-oracle correction is recorded in
artifacts/rsa-verification/20261002-045200/supplemental-oracle-correction.json.

Total:1224 complete signature checks plus separate DER/key/range negative tests.
Use tools/check-rsa-vectors.py to check packed lengths and hashes locally, and
its --upstream-dir option to reproduce packing against downloaded pinned JSON.
