# Verification boundary

This project is an incomplete implementation, not a release candidate.

- Hibana is the published performance-only revision
  `a9371bea437bbc1f4303ceeb3fc833f605efe730`, based on the user-requested
  `development/dots-causality` head `3aef31ba015c75ea824b8b41f5603b03f5dd336b`,
  version 0.9.6 and MSRV 1.95, vendored with no local edits. Known rolled-route
  offer failures remain unresolved. The initial branch head was `102fc47e807d00318c75d7ad344fc99c2d5d3724`.
  The input plan referenced `7f5537a80efdd9c3fad3fd77496a7671270c232e` instead.
- The minimal Hibana selector correction is now incorporated upstream, with pre-fix Lean and Z3
  evidence under artifacts/hibana-offer-repro. Any further suspected core bug must first have a
  reproducible counterexample and both Lean and Z3 evidence before implementing
  a core fix, per the user's additional requirement.
- Upstream CI for the selected head was reported failing in Kani inventory and
  Miri gate bookkeeping. The head is not represented as fully validated. Those
  failures alone do not establish a semantic core bug.
- Unit tests are not a source-level refinement proof. Lean, Z3, Kani and Miri
  verification of the new code are not yet complete.
- A parsed packet is not authenticated. Frame parsing and CRYPTO buffering must
  only reach application effects after real AEAD and TLS authentication.
- Private runtime queues are not a promise that UDP is reliable. Loss, reorder,
  duplication and corruption belong to the QUIC transport implementation.
- `no_std` and lack of `alloc` imports are not a complete no-allocation proof.
  Final target linking and host allocation counting must exercise the completed
  QUIC/TLS paths, including callbacks.
- Host interop (20 cases × 2 directions × 3 attempts), Pico HIL, and complete
  allocation-free TLS remain unexecuted. HTTP/3 and QUIC v2 are explicitly excluded.
- Latest user instruction supersedes existing-container discovery/reuse: this
  task builds from scratch in the assistant's cloud environment. The initial
  metadata-only Docker inventory is retained as historical evidence, not a gate
  requiring access to mini.local. Nothing on mini.local was touched.
