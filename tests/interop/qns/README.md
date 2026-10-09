# Prepared QNS adapter, container gate not executed

This command adapter follows the exact environment/mount contract of
[runner740c05a](https://github.com/quic-interop/quic-interop-runner/tree/740c05a10b61d65e8abd3ad38d60898004d335d9)
and the [official endpoint setup](https://github.com/quic-interop/quic-network-simulator#building-your-own-quic-docker-image).
The prepared Dockerfile has not been built or run: NETLINK_ROUTE sockets are
blocked in this cloud, including fresh user/network namespaces. No host security
settings or networking bypass is attempted.

Only `handshake` and `transfer` endpoint behavior is currently admitted by this
wrapper. Other cases exit127 explicitly, as required by the runner; the project
release validator rejects unsupported cases, so this can never create a full
matrix pass. Adding a case requires its actual adapter behavior and protocol
trace evidence, not adding its name to this set. In particular, successful direct
key-update tests do not yet supply the runner's encrypted pcap/keylog assertions.

The client loads the runner-generated `/certs/ca.pem` and verifies each URL's
hostname. It downloads all same-origin requests on one connection into
`/downloads`; the HQ adapter bounds concurrent live streams and safely recycles
slots. The server uses `/certs/cert.pem`, `/certs/priv.key` and `/www`. Extra shell
parameter strings are rejected, never evaluated. Logs are written to `/logs`.
The current endpoint does not emit qlog or TLS keylog; no placeholder logs are
created to pretend otherwise.

For a future authorized environment, supply independently verified image digests
as RUST_IMAGE (official Rust1.95 image) and ENDPOINT_IMAGE (official QNS endpoint
image). The digest-qualified references, platform, source hash and build output
must be recorded before use. This recipe intentionally has no mutable `latest`
default. Building/running it remains an unexecuted gate and does not authorize
publication of any image.
