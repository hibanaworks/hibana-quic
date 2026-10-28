# Source checks

This host-only Rust tool checks the immutable Hibana/TLS dependencies, audits
source for private credentials and generated artifacts, and exports the paired
QUIC/TLS build context. Its dependencies are not linked into QUIC or TLS.

Run commands from the QUIC repository root:

```sh
cargo +stable test --locked --manifest-path tools/ci/source/Cargo.toml
cargo +stable run --locked --manifest-path tools/ci/source/Cargo.toml -- dependencies .
cargo +stable run --locked --manifest-path tools/ci/source/Cargo.toml -- stage . .ci-work/paired-source
cargo +stable run --locked --manifest-path tools/ci/source/Cargo.toml -- audit .ci-work/paired-source/hibana-quic
```

Stage requires a clean sibling `hibana-tls` checkout at the exact pinned commit.
Both exported directories retain their sibling layout. Cargo paths must be
relative and remain within that pair; manifest bytes are preserved. The output
directory must be new or empty. Source symlinks and private artifacts are rejected
before writing the export. Build and cache directories are excluded.

`source-files.json` records each exported file's SHA-256. In inventory format 1,
each tree digest hashes the UTF-8 compact JSON object of its path/hash pairs,
sorted by path. `source-pair.json` records these digests and the pinned identities.
This identifies the exported source; it does not certify a binary or an interop
result. The standalone `audit` command checks the entire source tree except Git
metadata and the declared cache/output directories. Keep build outputs outside
the source tree when auditing an unexported checkout.
