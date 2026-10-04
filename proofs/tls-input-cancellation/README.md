# Pending TLS input cancellation

During integration of direct TLS transcript roles, the new complete-message
slot retained partially received bytes after cancellation. The message length
was committed only after the input future completed, so the old destructor
zeroized an empty prefix. The failing-before test is retained. This was a new
QUIC adapter defect, not an established Hibana core defect.

Lean and Z3 model the bounded buffer transfer, partial write, and cancellation
contract. Both ran before the fix. The old model has a concrete retained-byte
counterexample. Lease return establishes a clean unpublished buffer with sole
ownership restored to the slot. Preconditions are satisfiable and the Z3 query
checks each negated postcondition. These small models are not a verification of
Rust, TLS cryptography, or the entire scheduler.

The implementation transfers the actual mutable slice out of the slot into an
InputLease while I/O is pending. No RefCell guard crosses await. On error or
cancellation the lease zeroizes the complete slice, including bytes written
before length publication, then restores it. A successful read publishes the
same slice and its validated complete-message length. The transcript owner
clears the published message after applying its operation. The existing
no-allocation test exercises client and server full handshakes and cancellation
while partially filled input remains Pending, on a capacity-one carrier.

Commands (Lean 4.30.0, Z3 5.1.0.0):

    lean proofs/tls-input-cancellation/Cancellation.lean
    python proofs/tls-input-cancellation/cancellation.py
    cargo test --locked --manifest-path reference-tls/Cargo.toml --test bounded_tls direct_transcript_roles_validate_full_tls_without_allocating

The direct transcript roles are now wired into the live connection graph.
The old phase dispatcher and the temporary synchronous test-peer module/feature
have been deleted. The current regression drives BOTH peers through direct
async roles. Historical tests using synchronous handshake input still require
migration; none are silently counted as passing.
