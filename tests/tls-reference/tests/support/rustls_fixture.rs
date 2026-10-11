//! Test-only transport to an independent rustls peer. Candidate order is the
//! production Hibana projection, never Provider::receive handshake replay.
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::runtime::TaskSet;
use hibana_quic::runtime::carrier::CarrierStorage;
use hibana_quic_reference_tls::rustls::quic::{Connection, KeyChange, Keys};
use hibana_tls::handshake::BoundedTls;
use hibana_tls::handshake::global;
use hibana_tls::handshake::localside;
use hibana_tls::quic::Level;
use hibana_tls::quic::Provider;
use std::collections::VecDeque;
pub struct Peer {
    pub connection: Connection,
    pub application: Option<Keys>,
    pub saw_hrr: bool,
    level: Level,
    input: VecDeque<(Level, u8)>,
}
impl Peer {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,
            application: None,
            saw_hrr: false,
            level: Level::Initial,
            input: VecDeque::new(),
        }
    }
    fn flush(&mut self) {
        loop {
            let mut bytes = Vec::new();
            let change = self.connection.write_hs(&mut bytes);
            let empty = bytes.is_empty();
            self.input
                .extend(bytes.into_iter().map(|b| (self.level, b)));
            match change {
                Some(KeyChange::Handshake { .. }) => self.level = Level::Handshake,
                Some(KeyChange::OneRtt { keys, .. }) => {
                    self.application = Some(keys);
                    self.level = Level::OneRtt
                }
                None if empty => break,
                None => {}
            }
        }
    }
}
struct Input<'a>(&'a RefCell<&'a mut Peer>);
impl hibana_tls::handshake::MessageInput for Input<'_> {
    async fn read_message(
        &mut self,
        level: Level,
        out: &mut [u8],
    ) -> Result<usize, hibana_tls::handshake::Error> {
        let mut n = 4;
        let mut copied = 0;
        while copied < n {
            let (actual, b) = poll_fn(|_| match self.0.borrow_mut().input.pop_front() {
                Some(b) => Poll::Ready(b),
                None => Poll::Pending,
            })
            .await;
            assert_eq!(actual, level);
            out[copied] = b;
            copied += 1;
            if copied == 4 {
                n = 4 + ((out[1] as usize) << 16) + ((out[2] as usize) << 8) + out[3] as usize;
                if n > out.len() {
                    return Err(hibana_tls::handshake::Error::Capacity);
                }
            }
        }
        Ok(n)
    }
}
pub fn handshake(bounded: &mut BoundedTls<'_, '_>, peer: &mut Peer) {
    handshake_observe(bounded, peer, |_, _| {})
}
pub fn handshake_observe(
    bounded: &mut BoundedTls<'_, '_>,
    peer: &mut Peer,
    mut observe: impl FnMut(&mut BoundedTls<'_, '_>, &mut Peer),
) {
    let client = matches!(peer.connection, Connection::Server(_));
    let candidate = RefCell::new(bounded);
    let peer = RefCell::new(peer);
    let mut input = Input(&peer);
    let mut bytes = [0; 8192];
    let slot = hibana_tls::handshake::MessageSlot::new(&mut bytes);
    let carrier = CarrierStorage::<1, 16, 4>::new();
    let mut slab = vec![0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let id = SessionId::new(4801);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(id).unwrap())
        .unwrap();
    let projection = if client {
        {
            let graph = global::client();
            (
                hibana::runtime::program::project::<{ global::INPUT }>(&graph),
                hibana::runtime::program::project::<{ global::VERIFY }>(&graph),
            )
        }
    } else {
        {
            let graph = global::server();
            (
                hibana::runtime::program::project::<{ global::INPUT }>(&graph),
                hibana::runtime::program::project::<{ global::VERIFY }>(&graph),
            )
        }
    };
    let mut verify = rv.enter(id, &projection.1).unwrap();
    let mut wire = rv.enter(id, &projection.0).unwrap();
    let owner = async {
        if client {
            localside::verify::client_owner(&mut verify, &candidate, &slot).await
        } else {
            localside::verify::server_owner(&mut verify, &candidate, &slot).await
        }
    };
    let receiver = async {
        if client {
            localside::input::client_input(&mut wire, &slot, &mut input).await
        } else {
            localside::input::server_input(&mut wire, &slot, &mut input).await
        }
    };
    let mut owner = pin!(owner);
    let mut receiver = pin!(receiver);
    let mut tasks = pin!(TaskSet::new([owner.as_mut(), receiver.as_mut()]));
    let mut cx = Context::from_waker(Waker::noop());
    let mut finished = false;
    for _ in 0..256 {
        let result = tasks.as_mut().poll(&mut cx);
        observe(&mut candidate.borrow_mut(), &mut peer.borrow_mut());
        let mut out = [0; 4096];
        while let Some(message) = candidate.borrow_mut().transmit(&mut out).unwrap() {
            let mut p = peer.borrow_mut();
            if hibana_tls::wire::is_hello_retry_request(&out[..message.len]) {
                p.saw_hrr = true;
            }
            for fragment in out[..message.len].chunks(37) {
                p.connection.read_hs(fragment).unwrap();
            }
            p.flush();
        }
        peer.borrow_mut().flush();
        if let Poll::Ready(r) = result {
            r.unwrap();
            finished = true;
            break;
        }
    }
    assert!(finished, "projected transcript did not complete");
    assert!(!candidate.borrow().is_handshaking());
    assert!(!peer.borrow().connection.is_handshaking());
    // Post-handshake tickets use the public authenticated post-handshake input.
    while let Some((level, b)) = peer.borrow_mut().input.pop_front() {
        assert_eq!(level, Level::OneRtt);
        candidate.borrow_mut().receive(level, &[b]).unwrap();
    }
}
