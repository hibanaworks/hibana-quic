# Local structure and receive-buffer regression — 2026-10-09

Implementation commit: `9c9eabfdf01cdc9c46ebaa2233fe71fed4fe02e4`.
TLS: `b5cd10fcabb26ed0b121ae9a192b4c254f000426`.
Hibana: `6fccdbf81038b00d99ec1bb2b9c43a487521628e`.

Local commands and observed results:

- `cargo test --locked`: 462 unit/integration tests plus 18 doctests passed.
- `cargo test --locked --manifest-path host/Cargo.toml`: 130 tests passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo clippy --locked --manifest-path host/Cargo.toml --all-targets -- -D warnings`: passed.
- `cargo check --locked --lib --target thumbv6m-none-eabi`: passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'`: 109 passed with
  the Rust toolchain on PATH. An initial invocation without `rustc` on PATH
  failed its compiler probe; it was rerun with the documented environment.
- Paired-source audit: passed, 447 QUIC and 152 TLS source files before this
  qualification-request documentation was added.
- Removed-controller audit: passed. This static guard is not behavioral proof.

The borrowed receive test checks actual ring pointer identity, wraparound,
partial FIN, rejected consumption and out-of-range consumption. The retained
request test covers an exactly full request followed by a separate FIN and a
one-byte overflow that leaves the receive byte unconsumed. The existing full
connected loss, reordering, cancellation and default-stack tests also passed.

An earlier by-value exchange-storage candidate overflowed the default test
stack and was rejected. The published implementation exclusively borrows that
storage; the no-claimed-flag change must not be described as a by-value zero-copy
optimization.

These local results are not 44-cell interop qualification. The request manifest
requires new evidence on one source/run/attempt, preserving all scenarios,
reference pins, deadlines, capacities and candidate directions. The old
5c58cec qualification does not qualify this revision.

Still unfinished: complete ergonomic application construction, generic Hibana
network application transport and live HTTP/3 streaming examples. Scoped
receive borrowing and removing one staging copy do not establish end-to-end
zero-copy. See [copy boundaries](ZERO-COPY.md) and [application criteria](APPLICATION-API.md).
