# Verified CRYPTO consumption handoff

The async TLS migration originally left Transcript.received at zero, although the input role had authenticated, reassembled, and consumed handshake bytes. Old Handshake retransmissions could then be mistaken for new post-Finished data and cause a protocol close.

The private ReceiveContinuation now carries the actual consumed offsets. Only after all handshake roles complete does the coordinator record those monotonic bounded offsets in the transcript. Future Initial/Handshake bytes beyond that boundary remain forbidden; previously verified bytes are admitted as duplicates.

Lean and Z3 checked the boundary model before implementation. They retain a zero-watermark counterexample, prove admitting end <= verified_consumed and rejecting end > verified_consumed, and make no full-Rust or cryptographic proof claim. Connected-application regression now requires positive Initial and Handshake consumed offsets for both peers, alongside its existing loss/confirmation/byte/close assertions.
