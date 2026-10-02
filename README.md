# hibana-quic: bounded experimental QUIC v1

An allocation-free, caller-storage TLS/QUIC core with a Linux HTTP/0.9 development
adapter. This test branch freezes a qualified local checkpoint; it is not a
production release or a full interoperability/Pico qualification.

The host filesystem, CLI and process runtime allocate. The bounded endpoint's
allocation measurements do not establish whole-process zero allocation. Current
runner admission is explicitly limited to `handshake` and `transfer`; other
endpoint test names return 127. No insecure certificate-verification mode exists
in the bounded client. It uses the runner's CA and each request's DNS hostname.

## Manual interoperability pilot

The `QUIC interoperability pilot` workflow is `workflow_dispatch` only. It runs
only for a public repository on a standard Ubuntu GitHub-hosted runner, with
read-only repository permission, a 60-minute job ceiling and one-day small-result
retention. Pushes and pull requests never start it. No workflow has passed merely
because its configuration is present.

One invocation first runs the unchanged pinned quic-interop-runner with an
unchanged pinned Neqo QNS endpoint against itself. Only if that baseline succeeds
does it run `handshake` and `transfer` with this endpoint in both directions.
The runner source/checks are untouched. A separate working-directory registration
file adds this endpoint; a Compose image-only override pins the simulator without
changing topology, delays, privileges, test semantics or assertions.

Source pins are in `ci/pins.env`; OCI digests and tool/package versions are recorded
before testing. The official simulator tag is resolved once per job and its
immutable digest is reused for every phase. Neqo's source, QNS entrypoint and
Dockerfile remain unchanged. The bounded endpoint is built from this branch's
manifest-checked source. The analysis container verifies tshark >=4.5, as required
by the pinned runner; a missing prerequisite is a failure, never a pass.

Artifacts contain only normalized original verdicts, exact source/image IDs,
version/count/hash evidence and bounded failure classifications. TLS key logs,
private fixture keys, session tickets, raw logs and raw captures are not uploaded.
Original packet captures are hashed before removal with the ephemeral VM; the
safe report does not pretend to contain raw forensic evidence.

This single small pilot does not satisfy the 40-cell, three-attempt release gate.
The remaining cases and physical Pico testing are separate work.

## Build

```sh
cargo build --locked --release --manifest-path adapters/host/Cargo.toml --bin hq
```

Use `hq --help` for the explicit host profile. Local development tests cover
certificate failures, exact file transfer, Retry, resumption, cipher selection,
ECN, key updates and connection lifecycle. Their existence is not evidence that
those runner test cases passed.

`docs/SOURCE_PROVENANCE.json` records the frozen implementation checkpoint.
`proofs/ACCOUNTING-MODEL.md` maps the Lean/Z3 kernel models and their assumptions;
these models are not a universal refinement proof of the Rust implementation.
Vendored Hibana includes its own scoped proof provenance for the previously
published completed-sibling route correction.

Licensed MIT OR Apache-2.0; retain `THIRD_PARTY_NOTICES.md` and bundled notices.
