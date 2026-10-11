# Public TLS syntax regression fixtures

`neqo-p256-grease-clienthello.bin` is a complete 512-byte ClientHello emitted by
unchanged Mozilla Neqo 0.32.0 at revision
`ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95`, using NSS 3.126 and the separately
verified test-peer wrapper revision 2 with its public `set_groups(P256)` API.

SHA-256: `851b91807ae3f82492c38ec3259e1e952980156a8ffe155a473f2cfe6ea8cca1`

The fixture was reconstructed by CRYPTO offset from an authenticated QUIC v1
Initial (public Initial derivation) captured on localhost on 2026-10-02. Its SNI
is localhost; its parameters contain an ephemeral test CID. It contains no
private key, PSK identity/binder, credentials, TLS traffic secret, or key log.

NSS offers psk_key_exchange_modes `[1, 0x2a]`; 0x2a is a GREASE mode. The
regression ensures unknown offered mode values are ignored according to RFC8701
§3.2, while exact nonempty vector framing and rejection of actual unsupported
PSK negotiation remain intact. Unknown values are treated uniformly, not
special-cased solely for known GREASE constants.
