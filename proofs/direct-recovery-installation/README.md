# Direct recovery installation

The old packet-arena facade was used by the active connection only to obtain a
one-shot recovery-construction claim. The active recovery owner already stores
and authenticates its own sent/received ledger. It now consumes an affine
`RecoveryInstallation` directly from the unique key-scope installation.

The token retains the same immutable scope identity; a shared scope reference or
copied numeric generation cannot construct it. Taking it spends the originating
claim before downstream construction. Drop, constructor failure and success
cannot reopen the claim. Rust compile-fail tests cover token reuse; actual
recovery tests cover failed construction, split/reuse, wrong plaintext and a
foreign scope with the same numeric generation.

Lean proves one-shot identity and no reissue in the small claim model. Z3 checks
nonvacuity and retains a reset-on-failure mutation witness. These are scoped
models, not a proof of the complete Rust runtime or QUIC protocol.
