# Owned source export

This host tool exports QUIC and its exact sibling TLS checkout. Run it from
the `hibana-quic` directory, beside `hibana-tls`:

```sh
cargo +1.95.0 run --locked --manifest-path tools/ci/source-pair/Cargo.toml -- --output .ci-work/paired-source
```

It parses source pins, manifests and consumer locks, checks the actual TLS Git
commit and cleanliness, and rejects symlinks and paths outside the paired
repositories. Source validation finishes before exported files are written.
Core-free host tools remain separate from the QUIC dependency closure.

The export includes all source bytes, each file's SHA256, and the existing
sorted-JSON tree digests. Generated targets, Git metadata and private CI work
directories are excluded. The runtime and embedded crates do not depend on
this tool.

`--tls-revision` reads the immutable TLS dependency before its checkout.
`--audit-sources` rejects private material, generated inputs and symlinks in
both sources. `--audit` also checks all six consumer locks, normal/build Cargo
closures, removed cryptographic dependencies and the standalone TLS checksum.
Keep `CARGO_TARGET_DIR` outside the source or in `.ci-work` while auditing.

The former Python source checks and historical ELF readers have been removed.
Use `--legacy-target-budget FILE` or `--legacy-async-budget FILE` to read an old
ARM ELF table. The reports explicitly describe the removed controller and
cannot establish the current connection's firmware, stack or memory budget.
These host tools do not enter the runtime dependency closure.

The Rust tests create real Git repositories. They check committed bytes and
lockfiles in the export, reject mismatched dependencies and modified or missing
TLS without producing an export, and exercise source symlink and path rejection.
