# Pico integration

This no_std/no_alloc library reuses the exact application global and localsides
from the native raw QUIC example. Select raw QUIC or HTTP/3 with `Protocol`.

Provide initialized TLS/QUIC resource owners, the matching `Setup`, physically
backed receive/send buffers, an actual UDP driver implementing `DatagramRx` and
`DatagramTx`, a monotonic `Clock`, and an executor. TLS setup must use secure
board entropy and the intended peer identity/trust configuration. The example
never substitutes synthetic entropy or disables certificate verification.

The board chooses all slab/buffer sizes and must qualify peak RAM and stack
usage. The example is not a boot image, network chip driver, or hardware test.

From the repository root:

```sh
cargo check --locked --manifest-path pal/examples/pico/Cargo.toml --target thumbv6m-none-eabi
```
