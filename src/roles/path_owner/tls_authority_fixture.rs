//! Test-only adapters over the real Path policy. No grant fields are writable.
use super::*;
use crate::roles::{connection_authority::PathReady, packet_authority::ReceiveEvidence};

pub(crate) fn confirmation(
    ready: PathReady,
    initial: (
        crate::roles::packet_protection::OpenReceipt,
        crate::roles::packet_protection::Packet<128>,
    ),
    handshake_done: Option<(
        crate::roles::tls_owner::OpenReceipt,
        crate::roles::packet_protection::Packet<1536>,
    )>,
) -> HandshakeConfirmation {
    let generation = ready.generation();
    let role = if ready.server_handshake_confirmed() {
        Role::Server
    } else {
        Role::Client
    };
    let local = if role == Role::Client {
        b"clientid"
    } else {
        b"serverid"
    };
    let peer = if role == Role::Client {
        b"serverid"
    } else {
        b"clientid"
    };
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local_cids = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer_cids = [PeerCidSlot::EMPTY; PEER_CIDS];
    let mut state = State::new(
        config(generation, role, local, peer),
        Resources {
            paths: &mut paths,
            local_cids: &mut local_cids,
            peer_cids: &mut peer_cids,
        },
        Random(97),
    )
    .unwrap();
    let arena = authority::Arena::<1, 2>::new(generation);
    let ticket = arena
        .admit(ReceiveEvidence::Initial(initial.0), initial.1.body())
        .unwrap();
    let learned = arena
        .grant_initial_peer_cid(ticket, initial.1.header())
        .unwrap();
    state.learn_peer_cid(&arena, learned).unwrap();
    arena.finish(ticket).unwrap();
    state.handshake(ready).unwrap();
    if role == Role::Client {
        assert!(
            !state.confirmed,
            "TLS completion alone cannot confirm a client"
        );
        assert!(state.tls_confirmation.is_none());
        let (receipt, packet) =
            handshake_done.expect("client requires authenticated HANDSHAKE_DONE");
        let ticket = arena
            .admit(ReceiveEvidence::Tls(receipt), packet.body())
            .unwrap();
        let context = PathContext {
            address: state.config.initial,
            destination: state.config.local_cid,
            datagram_id: 1,
            datagram_bytes: packet.bytes().len() as u64,
            now: 0,
        };
        arena.bind_path_context(ticket, context).unwrap();
        let grant = arena
            .grant_path(ticket, 0, PathFrame::HandshakeDone, context)
            .unwrap();
        let Outcome::Frame {
            tls_confirmation: Some(confirmation),
            ..
        } = state.frame(&arena, grant).unwrap()
        else {
            panic!("authenticated HANDSHAKE_DONE must mint exactly one confirmation")
        };
        arena.finish(ticket).unwrap();
        assert!(state.confirmed);
        assert!(state.tls_confirmation.is_none());
        confirmation
    } else {
        assert!(handshake_done.is_none());
        assert!(
            state.confirmed,
            "verified client Finished confirms the server"
        );
        state.tls_confirmation.take().unwrap()
    }
}

/// The returned completion is produced by immutable protected bytes and an
/// awaited adapter success, then applied to the actual Path reservation.
pub(crate) async fn submit<const N: usize>(
    ticket: crate::roles::recovery_owner::SendTicket,
    sealed: crate::roles::sealed_packet::SealedPacket<N>,
    plaintext: &[u8],
    mask: [u8; 5],
    now: u64,
) -> crate::roles::datagram::RecoveryCompletion {
    struct Adapter(u64);
    impl UdpAdapter for Adapter {
        async fn send(&mut self, datagram: Datagram<'_>) -> Result<u64, ()> {
            assert!(!datagram.bytes.is_empty());
            runtime::yield_now().await;
            Ok(self.0)
        }
    }
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local_cids = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer_cids = [PeerCidSlot::EMPTY; PEER_CIDS];
    let config = config(
        ticket.descriptor().generation,
        Role::Client,
        b"clientid",
        b"serverid",
    );
    let mut state = State::new(
        config,
        Resources {
            paths: &mut paths,
            local_cids: &mut local_cids,
            peer_cids: &mut peer_cids,
        },
        Random(97),
    )
    .unwrap();
    let pending = state
        .reserve(
            ticket.descriptor(),
            state.original,
            sealed.bytes().len() as u64,
            ticket.packet(),
            false,
            now,
        )
        .unwrap();
    let offset = sealed.header().len() - 1;
    let protected = crate::roles::datagram::ProtectedDatagram::from_sealed::<1>(
        &pending,
        ticket,
        None,
        crate::ecn::Codepoint::NotEct,
        sealed,
        plaintext,
        offset,
        mask,
    )
    .unwrap();
    let completions = pending.submit(&mut Adapter(now), protected).await.unwrap();
    assert_eq!(completions.recovery.accepted_at(), Some(now));
    state.complete(completions.path.into()).unwrap();
    completions.recovery
}

fn config(generation: u64, role: Role, local: &[u8], peer: &[u8]) -> Config {
    Config {
        generation,
        role,
        initial: Address {
            local: "127.0.0.1:4433".parse().unwrap(),
            remote: "127.0.0.1:5000".parse().unwrap(),
        },
        local_cid: Destination::new(local).unwrap(),
        bootstrap_destination: Destination::new(peer).unwrap(),
        local_active_limit: 2,
        local_reset_token: None,
        preferred_server: None,
        now: 0,
        pto: 10,
    }
}
struct Random(u64);
impl RngCore for Random {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl CryptoRng for Random {}

/// Setup evidence is prepared before allocation measurement; every receipt
/// still comes from a real Initial AEAD open in the owning key actor.
pub(crate) fn initial(
    generation: u64,
    client: bool,
) -> (
    crate::roles::packet_protection::OpenReceipt,
    crate::roles::packet_protection::Packet<128>,
) {
    if client {
        super::test_auth::initial(generation, b"serverid", b"clientid")
    } else {
        super::test_auth::initial(generation, b"clientid", b"serverid")
    }
}
