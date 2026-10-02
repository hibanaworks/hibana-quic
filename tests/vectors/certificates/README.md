# Public certificate fixtures

Generated with rcgen 0.13.2 / ring 0.17.14 using ephemeral P-256 keys. Only public
DER certificates and a signature are stored here; no private keys are included.
These bytes match the certificate-module unit-test fixtures.

- root.der: trusted test root CA
- intermediate.der: root-signed CA
- leaf.der: intermediate-signed localhost server certificate
- wrong_root.der: unrelated root
- bad_ca_usage.der: same intermediate public key/subject, missing keyCertSign
- bad_key_usage.der: same leaf key, keyEncipherment without digitalSignature
- bad_eku.der: same leaf key, clientAuth instead of serverAuth
- no_key_usage.der: leaf without optional KeyUsage extension
- certificate_verify.sig: ring ECDSA P-256/SHA-256 signature over TLS 1.3 server
  CertificateVerify input with transcript hash [0x42; 32]

Validity range: 2025-01-01 through 2035-01-01. Tests inject Unix time 1,800,000,000
for positive checks and dates outside that interval for rejection checks.
Fixtures are test inputs, not runtime roots, credentials, or authentication bypasses.
