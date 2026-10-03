# Direct-wire recovery checkpoint

UNVERIFIED, INCOMPLETE SOURCE PRESERVATION. The execution workspace disappeared on 2026-10-03 around 06:18 UTC. These files were reconstructed from retained source/edit context; byte identity is not claimed. Original successful test binaries and local logs are unavailable. No previous pass is asserted for these reconstructed files.

This branch intentionally has no legacy Driver/endpoint fallback and is not yet buildable. Complete restoration must use public baseline d086180079866d83c01ddaef254834ac2e738eb9 for unchanged kernels and exact qualified Hibana e75d413bb3c3adc6e61ba92f267bd14795d8525e, remove old production control, and integrate the recovered global/local path.

Required unfinished work includes explicit combined-global phase handoffs, application transfer/close, exact Initial retirement events, retained Handshake recovery for lost final ACK, bounded RX yields and fresh tests. No complete QUIC or interoperability success is claimed.
