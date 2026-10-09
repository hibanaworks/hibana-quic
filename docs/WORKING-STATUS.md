# Current work

Verified baseline: QUIC `5c58cec60cf4ebf5231b844ffe6fcccfaadc103e`, TLS
`b5cd10fcabb26ed0b121ae9a192b4c254f000426`, Hibana
`6fccdbf81038b00d99ec1bb2b9c43a487521628e`.
See [exact qualification](QUALIFICATION.md), including remaining failures.

## In progress: application API and organization

- Replace stale landing documentation with one current status and an explicit history.
- Remove file-only TLS forwarding facades; retain direct canonical module re-exports.
- Extract reusable HTTP/3 file framing from the CLI into Host, with separate global,
  direct local, and numerical file-decoding modules.
- Canonical role/resolver attachment now lives in the public role owner, shared
  by library users and CLI. Full connection construction is still coupled to CLI policy.
- Handshake exchange storage is exclusively borrowed by the operation; replace
  the claimed flag with Rust borrowing, returning retained ciphertext with continuations.
- Expose connection construction independently of CLI file handlers.
- Provide actual Hibana application transport, examples for request/reply,
  parallel requests, streaming and cancellation, and executable documentation.

The last two items are unfinished. Moving files or exposing the internal carrier
is not their implementation. [API acceptance criteria](APPLICATION-API.md).
Changes after the baseline are not qualified until their own regression and CI.

Historical development logs: [previous status](history/WORKING-STATUS.md),
[previous implementation log](history/ACTIVE-IMPLEMENTATION.md).
