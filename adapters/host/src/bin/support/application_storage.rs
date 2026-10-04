//! Explicit host allocations for one bounded direct-role connection. No file
//! body is stored here: streams use rolling receive windows and send chunks.
use hibana_quic::{
    connection::{Config, Side, application},
    handshake::CryptoBuffer,
    streams::{Limits, PacketReference, SendChunk, StreamSlot},
};
pub const STREAMS: usize = hibana_quic::connection::application_stream::MAX_LIVE_STREAMS;
pub const RECEIVE_BYTES: usize = 16 * 1024;
pub const CHUNK_BYTES: usize = 1024;
pub const SEND_CHUNKS: usize = 64;
pub const PACKET_REFERENCES: usize = 128;
pub fn local_limits(side: Side) -> Limits {
    Limits {
        max_data: (STREAMS * RECEIVE_BYTES) as u64,
        stream_data_bidi_local: RECEIVE_BYTES as u64,
        stream_data_bidi_remote: RECEIVE_BYTES as u64,
        stream_data_uni: 0,
        max_streams_bidi: if side == Side::Server {
            STREAMS as u64
        } else {
            0
        },
        max_streams_uni: 0,
    }
}
pub struct Storage {
    initial: Vec<u8>,
    handshake: Vec<u8>,
    application: Vec<u8>,
    initial_bitmap: Vec<u8>,
    handshake_bitmap: Vec<u8>,
    application_bitmap: Vec<u8>,
    streams: Vec<StreamSlot<RECEIVE_BYTES>>,
    chunks: Vec<SendChunk<CHUNK_BYTES>>,
    references: Vec<PacketReference>,
}
impl Storage {
    pub fn new() -> Self {
        Self {
            initial: vec![0; 8192],
            handshake: vec![0; 16384],
            application: vec![0; 8192],
            initial_bitmap: vec![0; 1024],
            handshake_bitmap: vec![0; 2048],
            application_bitmap: vec![0; 1024],
            streams: (0..STREAMS).map(|_| StreamSlot::EMPTY).collect(),
            chunks: (0..SEND_CHUNKS).map(|_| SendChunk::EMPTY).collect(),
            references: vec![PacketReference::EMPTY; PACKET_REFERENCES],
        }
    }
    pub fn setup<'a>(
        &'a mut self,
        config: Config<'a>,
    ) -> Result<application::Setup<'a, RECEIVE_BYTES, CHUNK_BYTES>, String> {
        Ok(application::Setup {
            early: None,
            config,
            local_limits: local_limits(config.side),
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
    ends: Vec<usize>,
    pub slots: Vec<hibana_quic::early_data::QuarantineSlot<RECEIVE_BYTES>>,
}
impl EarlyStorage {
    pub fn new() -> Self {
        Self {
            bytes: vec![0; STREAMS * super::direct_bootstrap::DATAGRAM],
            ends: vec![0; STREAMS],
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
