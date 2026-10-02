//! A genuine affine StreamCancellation backed by actual Path/Recovery kernels.
use super::*;
struct TestRandom(u64);
impl RngCore for TestRandom {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl CryptoRng for TestRandom {}
pub(crate) fn cancel_stream(
    transmission: super::super::stream_owner::TransmissionId,
) -> super::super::datagram::StreamCancellation {
    let generation = transmission.generation();
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer = [PeerCidSlot::EMPTY; PEER_CIDS];
    let mut state = State::new(
        Config {
            generation,
            role: Role::Client,
            initial: Address {
                local: "127.0.0.1:4433".parse().unwrap(),
                remote: "127.0.0.1:4434".parse().unwrap(),
            },
            local_cid: Destination::new(b"clientid").unwrap(),
            bootstrap_destination: Destination::new(b"serverid").unwrap(),
            local_active_limit: 2,
            local_reset_token: None,
            preferred_server: None,
            now: 0,
            pto: 100,
        },
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        TestRandom(19),
    )
    .unwrap();
    let path = state.initial_path();
    super::super::recovery_owner::cancellation_fixture::with_reserved_stream(
        generation,
        path,
        |ticket| {
            assert_eq!(ticket.packet().value, transmission.packet_number());
            let pending = state
                .reserve(
                    Descriptor {
                        generation,
                        sequence: 1,
                    },
                    path,
                    ticket.bytes(),
                    ticket.packet(),
                    false,
                    0,
                )
                .unwrap();
            let cancellations = super::super::datagram::cancel_before_publication(
                pending,
                ticket,
                Some(transmission),
            )
            .unwrap();
            state.complete(cancellations.path.into()).unwrap();
            assert!(state.pending.iter().all(Option::is_none));
            (
                cancellations.recovery,
                cancellations.stream.expect("bound stream cancellation"),
            )
        },
    )
}
