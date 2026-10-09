# Verification boundary

This is experimental software, not a release candidate or a certified crypto
implementation. Read QUALIFICATION.md for exact source/run identities.

- Hibana's source is fixed by Git revision in Cargo.toml and Cargo.lock, checked
  against tools/ci/pins.env. Changes require fresh consumer verification.
- Global/local projection governs communication order and ownership joins. It
  does not prove the arithmetic, cryptography or arbitrary adapter side effects.
- Parsed network bytes do not confer authority. AEAD and TLS authentication must
  precede protected application effects.
- Caller-supplied time, entropy, trust anchors and physical IO are trust boundaries.
  Tests cannot replace their production configuration or hardware validation.
- Scoped Lean/Z3 models state their own assumptions. They are not full Rust
  refinement, arbitrary-loss liveness or target constant-time proofs.
- no_std compilation, allocation counting and final target resource/link tests
  are distinct checks. Whole-board SRAM, stack, flash and timing remain open.
- Local native peers do not replace the pinned official simulator verdicts.
  A dropped final required handshake message can prevent completion; success
  must never be inferred from send acceptance or from an unrelated ACK.
