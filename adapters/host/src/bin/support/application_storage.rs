//! Explicit host allocations for one bounded direct-role connection. No file
//! body is stored here: streams use rolling receive windows and send chunks.
use hibana_quic::{
    connection::{Config, Side, application},
    handshake::CryptoBuffer,
    streams::{Limits, PacketReference, SendChunk, StreamSlot},
};
pub const STREAMS: usize = hibana_quic::connection::application_stream::MAX_LIVE_STREAMS;
pub const RECEIVE_BYTES: usize = 64 * 1024;
pub const CLIENT_RECEIVE_BYTES: usize = 1024 * 1024;
// Keep the original total receive-storage budget. A small known request set
// gets a larger per-stream window without allocating sixty-four such windows.
pub fn client_uses_large_window(requests: usize) -> bool {
    requests != 0 && requests <= STREAMS * RECEIVE_BYTES / CLIENT_RECEIVE_BYTES
}
// A declared finite server request limit also bounds simultaneous streams.
// Use the same value for advertised credit and physically owned receive slots.
pub fn server_capacity(limit: Option<core::num::NonZeroUsize>) -> usize {
    limit.map_or(STREAMS, |count| count.get().min(STREAMS))
}
pub const CHUNK_BYTES: usize = 1024;
pub const SEND_CHUNKS: usize = 64;
pub const PACKET_REFERENCES: usize = 128;
pub fn local_limits<const RX: usize>(side: Side, stream_capacity: usize) -> Limits {
    Limits {
        max_data: (stream_capacity * RX) as u64,
        stream_data_bidi_local: RX as u64,
        stream_data_bidi_remote: RX as u64,
        stream_data_uni: 0,
        max_streams_bidi: if side == Side::Server {
            stream_capacity as u64
        } else {
            0
        },
        max_streams_uni: 0,
    }
}
pub struct Storage<const RX: usize> {
    initial: Vec<u8>,
    handshake: Vec<u8>,
    application: Vec<u8>,
    initial_bitmap: Vec<u8>,
    handshake_bitmap: Vec<u8>,
    application_bitmap: Vec<u8>,
    streams: Vec<StreamSlot<RX>>,
    chunks: Vec<SendChunk<CHUNK_BYTES>>,
    references: Vec<PacketReference>,
}
impl<const RX: usize> Storage<RX> {
    pub fn new(stream_capacity: usize) -> Result<Self, String> {
        if stream_capacity == 0 || stream_capacity > STREAMS {
            return Err("stream storage capacity must be 1..=64".into());
        }
        Ok(Self {
            initial: vec![0; 8192],
            handshake: vec![0; 16384],
            application: vec![0; 8192],
            initial_bitmap: vec![0; 1024],
            handshake_bitmap: vec![0; 2048],
            application_bitmap: vec![0; 1024],
            streams: (0..stream_capacity).map(|_| StreamSlot::EMPTY).collect(),
            chunks: (0..SEND_CHUNKS).map(|_| SendChunk::EMPTY).collect(),
            references: vec![PacketReference::EMPTY; PACKET_REFERENCES],
        })
    }
    pub fn setup<'a>(
        &'a mut self,
        config: Config<'a>,
    ) -> Result<application::Setup<'a, RX, CHUNK_BYTES>, String> {
        Ok(application::Setup {
            server_token: None,
            local_idle_timeout_ms: 30_000,
            key_update_target: 0,
            early: None,
            config,
            local_limits: local_limits::<RX>(config.side, self.streams.len()),
            handshake_crypto: [
                CryptoBuffer::new(&mut self.initial, &mut self.initial_bitmap)
                    .map_err(|e| format!("Initial CRYPTO storage: {e:?}"))?,
                CryptoBuffer::new(&mut self.handshake, &mut self.handshake_bitmap)
                    .map_err(|e| format!("Handshake CRYPTO storage: {e:?}"))?,
            ],
            application: application::Buffers {
                streams: &mut self.streams,
                chunks: &mut self.chunks,
                references: &mut self.references,
                crypto: CryptoBuffer::new(&mut self.application, &mut self.application_bitmap)
                    .map_err(|e| format!("application CRYPTO storage: {e:?}"))?,
            },
        })
    }
}

/// The same explicit allocation is checked by TLS opt-in and handed to the
/// connected quarantine owner; it is never substituted by an unbacked limit.
pub struct EarlyStorage {
    bytes: Vec<u8>,
    ends: Vec<hibana_quic::connection::early_wire::PacketEnd>,
    pub slots: Vec<hibana_quic::early_data::QuarantineSlot<RECEIVE_BYTES>>,
}
impl EarlyStorage {
    pub fn new() -> Self {
        Self {
            bytes: vec![0; STREAMS * super::direct_bootstrap::DATAGRAM],
            ends: vec![hibana_quic::connection::early_wire::PacketEnd::EMPTY; STREAMS],
            slots: (0..STREAMS)
                .map(|_| hibana_quic::early_data::QuarantineSlot::EMPTY)
                .collect(),
        }
    }
    pub fn policy() -> hibana_quic::early_data::ServerPolicy {
        hibana_quic::early_data::ServerPolicy::BufferedReplaySafeRequests {
            max_bytes: STREAMS * RECEIVE_BYTES,
            max_streams: STREAMS,
        }
    }
    pub fn borrow(&mut self) -> application::EarlyServer<'_, RECEIVE_BYTES> {
        application::EarlyServer {
            packets: hibana_quic::connection::early_wire::PendingPackets::new(
                &mut self.bytes,
                &mut self.ends,
            ),
            slots: &mut self.slots,
            policy: Self::policy(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_server_credit_matches_owned_slots() {
        for count in [1, 2, STREAMS] {
            let capacity = server_capacity(core::num::NonZeroUsize::new(count));
            let storage = Storage::<1024>::new(capacity).unwrap();
            let limits = local_limits::<1024>(Side::Server, capacity);
            assert_eq!(storage.streams.len(), count);
            assert_eq!(limits.max_streams_bidi, count as u64);
            assert_eq!(limits.max_data, (count * 1024) as u64);
        }
        assert_eq!(server_capacity(None), STREAMS);
        assert_eq!(
            server_capacity(core::num::NonZeroUsize::new(STREAMS + 1)),
            STREAMS
        );
    }
    #[test]
    fn client_limits_are_backed_by_exact_requested_slot_count() {
        for count in [1, 2, 40, STREAMS] {
            let storage = Storage::<1024>::new(count).unwrap();
            assert_eq!(storage.streams.len(), count);
            let limits = local_limits::<1024>(Side::Client, storage.streams.len());
            assert_eq!(limits.max_data, (count * 1024) as u64);
            assert_eq!(limits.stream_data_bidi_local, 1024);
            assert_eq!(limits.max_streams_bidi, 0);
            assert_eq!(limits.max_streams_uni, 0);
        }
    }

    #[test]
    fn server_keeps_its_actual_full_stream_capacity() {
        let storage = Storage::<1024>::new(STREAMS).unwrap();
        let limits = local_limits::<1024>(Side::Server, storage.streams.len());
        assert_eq!(limits.max_streams_bidi, STREAMS as u64);
        assert_eq!(limits.max_data, (STREAMS * 1024) as u64);
    }

    #[test]
    fn selected_client_windows_never_exceed_the_original_pool() {
        for count in 1..=STREAMS {
            let bytes = if client_uses_large_window(count) {
                CLIENT_RECEIVE_BYTES
            } else {
                RECEIVE_BYTES
            };
            assert!(count * bytes <= STREAMS * RECEIVE_BYTES);
        }
        assert!(client_uses_large_window(1));
        assert!(client_uses_large_window(4));
        assert!(!client_uses_large_window(5));
        assert!(!client_uses_large_window(0));
    }

    #[test]
    fn invalid_slot_counts_are_rejected_before_allocation() {
        assert!(Storage::<1024>::new(0).is_err());
        assert!(Storage::<1024>::new(STREAMS + 1).is_err());
    }
}
