//! Caller-owned storage for one bounded direct-role connection. No file
//! body is stored here: streams use rolling receive windows and send chunks.
use crate::quic::Config;
use crate::quic::Side;
use crate::quic::application;
use crate::quic::application::Error;
use crate::quic::imp::crypto_buffer::CryptoBuffer;
use crate::quic::imp::kernel::streams::Limits;
use crate::quic::imp::kernel::streams::PacketReference;
use crate::quic::imp::kernel::streams::SendChunk;
use crate::quic::imp::kernel::streams::StreamSlot;
/// Datagram capacity shared by the host IO and buffer profile.
pub const DATAGRAM: usize = 1536;
pub const STREAMS: usize = crate::quic::application::imp::stream::MAX_LIVE_STREAMS;
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
pub fn capacity(protocol: crate::http3::Protocol, files: usize) -> usize {
    let reserved = if protocol == crate::http3::Protocol::Http3 {
        6
    } else {
        0
    };
    files.min(STREAMS - reserved) + reserved
}
pub fn local_limits<const RX: usize>(
    side: Side,
    stream_capacity: usize,
    protocol: crate::http3::Protocol,
) -> Limits {
    let reserved = if protocol == crate::http3::Protocol::Http3 {
        6
    } else {
        0
    };
    Limits {
        max_data: (stream_capacity * RX) as u64,
        stream_data_bidi_local: RX as u64,
        stream_data_bidi_remote: RX as u64,
        stream_data_uni: if reserved == 0 { 0 } else { RX as u64 },
        max_streams_bidi: if side == Side::Server {
            stream_capacity.saturating_sub(reserved) as u64
        } else {
            0
        },
        max_streams_uni: if reserved == 0 { 0 } else { 3 },
    }
}
pub struct Storage {
    cid_slots: [crate::quic::imp::kernel::connection_id::LocalCidSlot; 16],
    peer_cid_slots: [crate::quic::imp::kernel::connection_id::PeerCidSlot<4>; 16],
    cid_seed: hibana_tls::secret::Secret<[u8; 32]>,
    initial: [u8; 8192],
    handshake: [u8; 16384],
    application: [u8; 8192],
    initial_bitmap: [u8; 1024],
    handshake_bitmap: [u8; 2048],
    application_bitmap: [u8; 1024],
    chunks: [SendChunk<CHUNK_BYTES>; SEND_CHUNKS],
    references: [PacketReference; PACKET_REFERENCES],
}
impl Storage {
    pub const fn new() -> Self {
        Self {
            cid_slots: [crate::quic::imp::kernel::connection_id::LocalCidSlot::EMPTY; 16],
            peer_cid_slots: [const { crate::quic::imp::kernel::connection_id::PeerCidSlot::EMPTY };
                16],
            cid_seed: hibana_tls::secret::Secret::new([0; 32]),
            initial: [0; 8192],
            handshake: [0; 16384],
            application: [0; 8192],
            initial_bitmap: [0; 1024],
            handshake_bitmap: [0; 2048],
            application_bitmap: [0; 1024],
            chunks: [const { SendChunk::EMPTY }; SEND_CHUNKS],
            references: [PacketReference::EMPTY; PACKET_REFERENCES],
        }
    }
    pub fn setup<'s, const RX: usize>(
        &'s mut self,
        streams: &'s mut [StreamSlot<RX>],
        config: Config<'s>,
        protocol: crate::http3::Protocol,
        local_idle_timeout_ms: u64,
        entropy: &mut impl crate::entropy::Entropy,
    ) -> Result<application::Setup<'s, RX, CHUNK_BYTES>, Error> {
        if streams.is_empty()
            || streams.len() > STREAMS
            || (protocol == crate::http3::Protocol::Http3 && streams.len() <= 6)
        {
            return Err(Error::Capacity);
        }
        use hibana_tls::secret::Erase;
        self.cid_seed.erase();
        if entropy.try_fill_bytes(&mut *self.cid_seed).is_err() {
            self.cid_seed.erase();
            return Err(Error::Entropy);
        }
        let stream_capacity = streams.len();
        Ok(application::Setup {
            peer_ids: Some(crate::quic::path::imp::peer_ids::Storage {
                slots: &mut self.peer_cid_slots,
                active_limit: 2,
            }),
            local_ids: Some(crate::quic::path::imp::ids::Storage {
                slots: &mut self.cid_slots,
                seed: &self.cid_seed,
            }),
            server_token: None,
            local_idle_timeout_ms,
            key_update_target: 0,
            early: None,
            config,
            local_limits: local_limits::<RX>(config.side, stream_capacity, protocol),
            handshake_crypto: [
                CryptoBuffer::new(&mut self.initial, &mut self.initial_bitmap)
                    .map_err(|e| Error::Connection(crate::quic::Error::Reassembly(e)))?,
                CryptoBuffer::new(&mut self.handshake, &mut self.handshake_bitmap)
                    .map_err(|e| Error::Connection(crate::quic::Error::Reassembly(e)))?,
            ],
            application: application::Buffers {
                streams,
                chunks: &mut self.chunks,
                references: &mut self.references,
                crypto: CryptoBuffer::new(&mut self.application, &mut self.application_bitmap)
                    .map_err(|e| Error::Connection(crate::quic::Error::Reassembly(e)))?,
            },
        })
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-owned bounded storage is checked by TLS opt-in and handed to the
/// connected quarantine owner; it is never substituted by an unbacked limit.
pub struct EarlyStorage<'a> {
    bytes: [u8; STREAMS * DATAGRAM],
    ends: [crate::quic::imp::early_wire::PacketEnd; STREAMS],
    pub slots: &'a mut [crate::quic::early_data::imp::QuarantineSlot<RECEIVE_BYTES>],
}
impl<'a> EarlyStorage<'a> {
    pub fn new(
        slots: &'a mut [crate::quic::early_data::imp::QuarantineSlot<RECEIVE_BYTES>],
    ) -> Result<Self, Error> {
        if slots.len() != STREAMS {
            return Err(Error::Capacity);
        }
        Ok(Self {
            bytes: [0; STREAMS * DATAGRAM],
            ends: [crate::quic::imp::early_wire::PacketEnd::EMPTY; STREAMS],
            slots,
        })
    }
    pub fn policy() -> crate::quic::early_data::imp::ServerPolicy {
        crate::quic::early_data::imp::ServerPolicy::BufferedReplaySafeRequests {
            max_bytes: STREAMS * RECEIVE_BYTES,
            max_streams: STREAMS,
        }
    }
    pub fn borrow(&mut self) -> application::EarlyServer<'_, RECEIVE_BYTES> {
        application::EarlyServer {
            packets: crate::quic::imp::early_wire::PendingPackets::new(
                &mut self.bytes,
                &mut self.ends,
            ),
            slots: self.slots,
            policy: Self::policy(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestEntropy;
    impl crate::entropy::Entropy for TestEntropy {
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), crate::entropy::Unavailable> {
            bytes.fill(7);
            Ok(())
        }
    }
    fn config(side: Side) -> Config<'static> {
        Config {
            local_preferred: None,
            initial_path: None,
            version: crate::quic::version::Version::V1,
            side,
            local_connection_id: b"local001",
            original_destination_id: b"original",
            retry_source_id: None,
            initial_token: &[],
            peer_connection_id: b"peer0001",
        }
    }

    #[test]
    fn finite_server_credit_matches_owned_slots() {
        for count in [1, 2, STREAMS] {
            let capacity = server_capacity(core::num::NonZeroUsize::new(count));
            let mut slots = [const { StreamSlot::<1024>::EMPTY }; STREAMS];
            let mut storage = const { Storage::new() };
            let setup = storage
                .setup(
                    &mut slots[..capacity],
                    config(Side::Server),
                    Default::default(),
                    15_000,
                    &mut TestEntropy,
                )
                .unwrap();
            assert_eq!(setup.application.streams.len(), count);
            assert_eq!(setup.local_limits.max_streams_bidi, count as u64);
            assert_eq!(setup.local_limits.max_data, (count * 1024) as u64);
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
            let mut slots = [const { StreamSlot::<1024>::EMPTY }; STREAMS];
            let mut storage = const { Storage::new() };
            let setup = storage
                .setup(
                    &mut slots[..count],
                    config(Side::Client),
                    Default::default(),
                    15_000,
                    &mut TestEntropy,
                )
                .unwrap();
            assert_eq!(setup.application.streams.len(), count);
            assert_eq!(setup.local_limits.max_data, (count * 1024) as u64);
            assert_eq!(setup.local_limits.stream_data_bidi_local, 1024);
            assert_eq!(setup.local_limits.max_streams_bidi, 0);
            assert_eq!(setup.local_limits.max_streams_uni, 0);
        }
    }
    #[test]
    fn server_keeps_its_actual_full_stream_capacity() {
        let mut slots = [const { StreamSlot::<1024>::EMPTY }; STREAMS];
        let mut storage = const { Storage::new() };
        let setup = storage
            .setup(
                &mut slots,
                config(Side::Server),
                Default::default(),
                15_000,
                &mut TestEntropy,
            )
            .unwrap();
        assert_eq!(setup.local_limits.max_streams_bidi, STREAMS as u64);
        assert_eq!(setup.local_limits.max_data, (STREAMS * 1024) as u64);
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
    fn invalid_slot_counts_cannot_borrow_connection_storage() {
        let mut storage = const { Storage::new() };
        assert!(
            storage
                .setup::<1024>(
                    &mut [],
                    config(Side::Client),
                    Default::default(),
                    15_000,
                    &mut TestEntropy
                )
                .is_err()
        );
        let mut slots = [const { StreamSlot::<1024>::EMPTY }; STREAMS + 1];
        assert!(
            storage
                .setup(
                    &mut slots,
                    config(Side::Client),
                    Default::default(),
                    15_000,
                    &mut TestEntropy
                )
                .is_err()
        );
        assert!(
            storage
                .setup(
                    &mut slots[..6],
                    config(Side::Client),
                    crate::http3::Protocol::Http3,
                    15_000,
                    &mut TestEntropy
                )
                .is_err()
        );
    }
    #[test]
    fn failed_entropy_does_not_retain_a_previous_or_partial_seed() {
        struct FailedEntropy;
        impl crate::entropy::Entropy for FailedEntropy {
            fn try_fill_bytes(
                &mut self,
                bytes: &mut [u8],
            ) -> Result<(), crate::entropy::Unavailable> {
                bytes[..4].fill(9);
                Err(crate::entropy::Unavailable)
            }
        }
        let mut storage = const { Storage::new() };
        let mut slots = [const { StreamSlot::<1024>::EMPTY }; 1];
        {
            let _setup = storage
                .setup(
                    &mut slots,
                    config(Side::Client),
                    Default::default(),
                    15_000,
                    &mut TestEntropy,
                )
                .unwrap();
        }
        assert_eq!(*storage.cid_seed, [7; 32]);
        assert!(matches!(
            storage.setup(
                &mut slots,
                config(Side::Client),
                Default::default(),
                15_000,
                &mut FailedEntropy
            ),
            Err(Error::Entropy)
        ));
        assert_eq!(*storage.cid_seed, [0; 32]);
    }
}
