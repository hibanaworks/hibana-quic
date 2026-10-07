# Remaining interoperability work — recovery checkpoint

Base266e9d37f279f19d969feacaf5a1c16e729a01da includes the externally published ECN fix and the new34-cell CI matrix configuration. The matrix outcome is not asserted here. Cumulative official34/44 was verified from ECN artifact11450514076/run37546867484 before the environment reset.

At00:32 UTC on2026-10-07, the execution environment was replaced and the local source, evidence and toolchain disappeared. This checkpoint reconstructs the edits from the task's visible editing commands, not a surviving byte-identical old commit. Do not reuse pre-reset test results as qualification of these bytes.

Recovered source: QUIC v2 version/key/header domains, compatible v1→v2 profile, version-information validation, native invariant-header observer, authenticated PathResponse publication, caller-backed local CID issuance/advertisement/actual ACK/loss/retirement bookkeeping, and loopback port/address-rebinding fixture.

Fresh checks on reconstructed code: core442 unit tests and host cargo check passed; source/control/vendor audits passed. Full native revalidation and final regressions remain. Before the reset, v2 both native directions had passed; the initial rebind attempt failed because our client supplied no spare CID. CID integration has NOT passed a native test yet. Server rebinding/path validation, preferred-address migration and HTTP3 are incomplete. This is NOT the user's final ZIP or a claim of remaining10 success.

Rules: use literal Hibana local send/recv/offer and existing actual publication/retirement boundaries; no parallel progression FSM/flags/wrapper management. Numeric packet, CID, path and cryptographic facts remain data. Do not change peer/runner/deadlines to obtain passes. Each case must work with both client/server roles locally before final handoff. Preserve private diagnostics outside source; never publish private keys/keylogs/raw captures. The user requested an instructed ZIP after remaining10 completion, not an automatic push.

Reference: RFC9369 and RFC9368. V2 profile is compatible v1→v2; host v2 early/ticket/Retry combinations remain explicitly rejected pending complete validation. Other capabilities cannot be inferred from the existing v2 local result.
