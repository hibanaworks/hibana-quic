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

The Rust tests create real Git repositories. They check committed bytes and
lockfiles in the export, reject mismatched dependencies and modified or missing
TLS without producing an export, and exercise source symlink and path rejection.
