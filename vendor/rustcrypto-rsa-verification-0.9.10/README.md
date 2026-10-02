# Private RustCrypto RSA verification helper extraction

Origin: https://github.com/RustCrypto/RSA at
`da2af9a0ff814762957c428460e4098720f394a6` (registry rsa0.9.10).
Both upstream licenses are retained. This is a new project-maintained adapter,
not an upstream public RSA API and not an assertion of audit coverage.

Only the six functions listed in provenance.json were extracted. Their complete
function text is unchanged. Changes outside the functions are module imports,
using sha2's reexport of the same digest API, a verification-only local error
enum, rustfmt-skip attributes, and narrow Clippy allowances for original style.
There is no allocating dynamic-digest MGF, signing, encryption or key generation.

The owner is responsible for exact key-bit / buffer-length / hash / salt bounds
before calling the private helpers. Public modular exponentiation uses the
separate official crypto-bigint fixed-size API. No bigint implementation is
copied here. TLS/X509 parsing remains with the official borrowed DER/PKCS1
parsers. Independent review and complete positive/negative vectors are required
before an integration claim.
