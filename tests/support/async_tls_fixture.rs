//! Test wiring only: actual four projected roles and the production task set.
//! No synchronous handshake replay or protocol-order dispatcher is used.
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    bounded_tls::{BoundedTls, locals, protocol},
    carrier::CarrierStorage,
    runtime::TaskSet,
    tls::{Level, Provider},
};
struct Access<'a, 'cfg, 'buf>(RefCell<&'a mut BoundedTls<'cfg, 'buf>>);
impl locals::CryptoAccess for Access<'_, '_, '_> {
    fn with_crypto<R>(&self, f: impl FnOnce(&mut BoundedTls<'_, '_>) -> R) -> R {
        f(&mut self.0.borrow_mut())
    }
}
struct Input<'a, 'b, 'cfg, 'buf, L> {
    local: &'a L,
    fragment: usize,
    protect: bool,
    pn: [u64; 3],
    certificates: usize,
    remote: &'a Access<'b, 'cfg, 'buf>,
    pending: [u8; 8208],
    used: usize,
    end: usize,
    level: Level,
}
impl<L: locals::CryptoAccess> locals::MessageInput for Input<'_, '_, '_, '_, L> {
    async fn read_message(&mut self, level: Level, out: &mut [u8]) -> Result<usize, locals::Error> {
        let mut copied = 0;
        let mut len = 4;
        while copied < len {
            if self.used == self.end {
                let output = poll_fn(|_| {
                    match self
                        .remote
                        .0
                        .borrow_mut()
                        .transmit(&mut self.pending[..self.fragment])
                    {
                        Ok(Some(p)) => Poll::Ready(Ok(p)),
                        Ok(None) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(locals::Error::Input(e))),
                    }
                })
                .await?;
                self.used = 0;
                self.end = output.len;
                self.level = output.level;
                if self.protect && output.level != Level::Initial {
                    let i = if output.level == Level::Handshake {
                        1
                    } else {
                        2
                    };
                    let pn = self.pn[i];
                    self.pn[i] += 1;
                    let n = self
                        .remote
                        .0
                        .borrow_mut()
                        .seal(
                            output.level,
                            pn,
                            b"fixture CRYPTO",
                            &mut self.pending,
                            output.len,
                        )
                        .map_err(locals::Error::Input)?;
                    assert_eq!(
                        self.local
                            .with_crypto(|p| p.open(
                                output.level,
                                pn,
                                b"fixture CRYPTO",
                                &mut self.pending[..n]
                            ))
                            .map_err(locals::Error::Input)?,
                        output.len
                    );
                }
            }
            assert_eq!(level, self.level);
            let n = (len - copied).min(self.end - self.used);
            out[copied..copied + n].copy_from_slice(&self.pending[self.used..self.used + n]);
            copied += n;
            self.used += n;
            if copied == 4 {
                len = 4 + ((out[1] as usize) << 16) + ((out[2] as usize) << 8) + out[3] as usize;
                if len > out.len() {
                    return Err(locals::Error::Capacity);
                }
            }
        }
        if out[0] == 11 {
            self.certificates += 1;
        }
        Ok(len)
    }
}
pub fn handshake(client: &mut BoundedTls<'_, '_>, server: &mut BoundedTls<'_, '_>) {
    handshake_with(client, server, 8192, false);
}
pub fn handshake_with(
    client: &mut BoundedTls<'_, '_>,
    server: &mut BoundedTls<'_, '_>,
    fragment: usize,
    protect: bool,
) -> usize {
    handshake_observe(client, server, fragment, protect, |_, _| {})
}
pub fn handshake_observe(
    client: &mut BoundedTls<'_, '_>,
    server: &mut BoundedTls<'_, '_>,
    fragment: usize,
    protect: bool,
    mut observe: impl FnMut(&mut BoundedTls<'_, '_>, &mut BoundedTls<'_, '_>),
) -> usize {
    let c = Access(RefCell::new(client));
    let s = Access(RefCell::new(server));
    let mut ci = Input {
        remote: &s,
        local: &c,
        fragment,
        protect,
        pn: [0; 3],
        certificates: 0,
        pending: [0; 8208],
        used: 0,
        end: 0,
        level: Level::Initial,
    };
    let mut si = Input {
        remote: &c,
        local: &s,
        fragment,
        protect,
        pn: [0; 3],
        certificates: 0,
        pending: [0; 8208],
        used: 0,
        end: 0,
        level: Level::Initial,
    };
    let mut cb = [0; 8192];
    let mut sb = [0; 8192];
    let cs = locals::MessageSlot::new(&mut cb);
    let ss = locals::MessageSlot::new(&mut sb);
    let cc = CarrierStorage::<1, 16, 4>::new();
    let sc = CarrierStorage::<1, 16, 4>::new();
    let mut cm = [0; 65536];
    let mut sm = [0; 65536];
    let mut ck = SessionKitStorage::uninit();
    let mut sk = SessionKitStorage::uninit();
    let ck = ck.init();
    let sk = sk.init();
    let cid = SessionId::new(5200);
    let sid = SessionId::new(5201);
    let cr = ck.rendezvous(&mut cm, cc.bind(cid).unwrap()).unwrap();
    let sr = sk.rendezvous(&mut sm, sc.bind(sid).unwrap()).unwrap();
    let cp = protocol::client_programs();
    let sp = protocol::server_programs();
    let mut cv = cr.enter(cid, &cp.verify).unwrap();
    let mut cw = cr.enter(cid, &cp.input).unwrap();
    let mut sv = sr.enter(sid, &sp.verify).unwrap();
    let mut sw = sr.enter(sid, &sp.input).unwrap();
    {
        let mut co = pin!(locals::client_owner(&mut cv, &c, &cs));
        let mut cin = pin!(locals::client_input(&mut cw, &cs, &mut ci));
        let mut so = pin!(locals::server_owner(&mut sv, &s, &ss));
        let mut sin = pin!(locals::server_input(&mut sw, &ss, &mut si));
        let mut tasks = pin!(TaskSet::new([
            co.as_mut(),
            cin.as_mut(),
            so.as_mut(),
            sin.as_mut()
        ]));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..128 {
            let result = tasks.as_mut().poll(&mut cx);
            observe(&mut c.0.borrow_mut(), &mut s.0.borrow_mut());
            if let Poll::Ready(result) = result {
                result.unwrap();
                break;
            }
        }
        assert!(
            c.0.borrow().state() == hibana_quic::bounded_tls::State::Connected
                && s.0.borrow().state() == hibana_quic::bounded_tls::State::Connected,
            "actual async transcript did not finish"
        );
    }
    ci.certificates + si.certificates
}

/// Deliver one adversarial ClientHello through the real server projection.
/// The test expects rejection before another input message is requested.
pub fn reject_server_message(server: &mut BoundedTls<'_, '_>, message: &[u8]) -> locals::Error {
    probe_server_message(server, message, |_| None::<()>).expect_err("invalid ClientHello accepted")
}
pub fn probe_server_message<R>(
    server: &mut BoundedTls<'_, '_>,
    message: &[u8],
    mut observe: impl FnMut(&mut BoundedTls<'_, '_>) -> Option<R>,
) -> Result<R, locals::Error> {
    struct One<'a>(&'a [u8], bool);
    impl locals::MessageInput for One<'_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, locals::Error> {
            if self.1 {
                return core::future::pending().await;
            }
            assert_eq!(level, Level::Initial);
            self.1 = true;
            out[..self.0.len()].copy_from_slice(self.0);
            Ok(self.0.len())
        }
    }
    let source = Access(RefCell::new(server));
    let mut input = One(message, false);
    let mut bytes = [0; 8192];
    let slot = locals::MessageSlot::new(&mut bytes);
    let carrier = CarrierStorage::<1, 16, 4>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(5202);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let programs = protocol::server_programs();
    let mut owner = rv.enter(sid, &programs.verify).unwrap();
    let mut receiver = rv.enter(sid, &programs.input).unwrap();
    let mut owner = pin!(locals::server_owner(&mut owner, &source, &slot));
    let mut receiver = pin!(locals::server_input(&mut receiver, &slot, &mut input));
    let mut tasks = pin!(TaskSet::new([owner.as_mut(), receiver.as_mut()]));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        let result = tasks.as_mut().poll(&mut cx);
        if let Some(value) = observe(&mut source.0.borrow_mut()) {
            return Ok(value);
        }
        if let Poll::Ready(result) = result {
            return Err(result.expect_err("incomplete peer unexpectedly finished"));
        }
    }
    panic!("invalid ClientHello was not rejected at the transcript boundary")
}

pub fn drain_authenticated_tickets(
    from: &mut BoundedTls<'_, '_>,
    to: &mut BoundedTls<'_, '_>,
    fragment: usize,
) -> usize {
    let mut buffer = [0; 4112];
    let mut pn = 0;
    let mut tickets = 0;
    while let Some(out) = from.transmit(&mut buffer[..fragment]).unwrap() {
        assert_eq!(
            out.level,
            Level::OneRtt,
            "handshake must have completed through async roles"
        );
        if fragment == 4096 {
            let mut pos = 0;
            while pos < out.len {
                assert_eq!(buffer[pos], 4);
                tickets += 1;
                pos += 4
                    + ((buffer[pos + 1] as usize) << 16)
                    + ((buffer[pos + 2] as usize) << 8)
                    + buffer[pos + 3] as usize;
            }
            assert_eq!(pos, out.len);
        }
        let n = from
            .seal(
                Level::OneRtt,
                pn,
                b"authenticated ticket",
                &mut buffer,
                out.len,
            )
            .unwrap();
        assert_eq!(
            to.open(Level::OneRtt, pn, b"authenticated ticket", &mut buffer[..n])
                .unwrap(),
            out.len
        );
        to.receive(Level::OneRtt, &buffer[..out.len]).unwrap();
        pn += 1;
    }
    tickets
}

/// Actual projected transcript processing through pristine KeySource ownership.
/// This component fixture transports CRYPTO plaintext, not QUIC packets.
pub fn handshake_key_sources_observe(
    client: &mut hibana_quic::bounded_tls::key_source::KeySource<'_, '_, '_>,
    server: &mut hibana_quic::bounded_tls::key_source::KeySource<'_, '_, '_>,
    mut observe: impl FnMut(
        &mut hibana_quic::bounded_tls::key_source::KeySource<'_, '_, '_>,
        &mut hibana_quic::bounded_tls::key_source::KeySource<'_, '_, '_>,
    ),
) {
    use hibana_quic::bounded_tls::key_source::KeySource;
    struct SourceInput<'a, 'scope, 'cfg, 'buf> {
        remote: &'a RefCell<&'a mut KeySource<'scope, 'cfg, 'buf>>,
        bytes: [u8; 8208],
        pos: usize,
        end: usize,
        level: Level,
    }
    impl locals::MessageInput for SourceInput<'_, '_, '_, '_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, locals::Error> {
            let mut copied = 0;
            let mut required = 4;
            while copied < required {
                if self.pos == self.end {
                    let output =
                        poll_fn(
                            |_| match self.remote.borrow_mut().transmit(&mut self.bytes) {
                                Ok(Some(p)) => Poll::Ready(Ok(p)),
                                Ok(None) => Poll::Pending,
                                Err(e) => Poll::Ready(Err(locals::Error::Input(e))),
                            },
                        )
                        .await?;
                    self.pos = 0;
                    self.end = output.len;
                    self.level = output.level;
                }
                if self.level != level {
                    return Err(locals::Error::Binding);
                }
                let n = (required - copied).min(self.end - self.pos);
                out[copied..copied + n].copy_from_slice(&self.bytes[self.pos..self.pos + n]);
                copied += n;
                self.pos += n;
                if copied == 4 {
                    required =
                        4 + ((out[1] as usize) << 16) + ((out[2] as usize) << 8) + out[3] as usize;
                    if required > out.len() {
                        return Err(locals::Error::Capacity);
                    }
                }
            }
            Ok(required)
        }
    }
    let c = RefCell::new(client);
    let s = RefCell::new(server);
    let mut ci = SourceInput {
        remote: &s,
        bytes: [0; 8208],
        pos: 0,
        end: 0,
        level: Level::Initial,
    };
    let mut si = SourceInput {
        remote: &c,
        bytes: [0; 8208],
        pos: 0,
        end: 0,
        level: Level::Initial,
    };
    let mut cb = [0; 8192];
    let mut sb = [0; 8192];
    let cs = locals::MessageSlot::new(&mut cb);
    let ss = locals::MessageSlot::new(&mut sb);
    let cc = CarrierStorage::<1, 16, 4>::new();
    let sc = CarrierStorage::<1, 16, 4>::new();
    let mut cm = [0; 65536];
    let mut sm = [0; 65536];
    let mut ck = SessionKitStorage::uninit();
    let mut sk = SessionKitStorage::uninit();
    let cid = SessionId::new(5300);
    let sid = SessionId::new(5301);
    let cr = ck
        .init()
        .rendezvous(&mut cm, cc.bind(cid).unwrap())
        .unwrap();
    let sr = sk
        .init()
        .rendezvous(&mut sm, sc.bind(sid).unwrap())
        .unwrap();
    let cp = protocol::client_programs();
    let sp = protocol::server_programs();
    let mut cv = cr.enter(cid, &cp.verify).unwrap();
    let mut cw = cr.enter(cid, &cp.input).unwrap();
    let mut sv = sr.enter(sid, &sp.verify).unwrap();
    let mut sw = sr.enter(sid, &sp.input).unwrap();
    {
        let mut co = pin!(locals::client_source_owner(&mut cv, &c, &cs));
        let mut so = pin!(locals::server_source_owner(&mut sv, &s, &ss));
        let mut cin = pin!(locals::client_input(&mut cw, &cs, &mut ci));
        let mut sin = pin!(locals::server_input(&mut sw, &ss, &mut si));
        let mut tasks = pin!(TaskSet::new([
            co.as_mut(),
            so.as_mut(),
            cin.as_mut(),
            sin.as_mut()
        ]));
        let mut complete = false;
        for _ in 0..128 {
            let result = tasks.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            observe(&mut c.borrow_mut(), &mut s.borrow_mut());
            if let Poll::Ready(value) = result {
                value.unwrap();
                complete = true;
                break;
            }
        }
        assert!(complete, "owned projected TLS must complete");
    }
    assert_eq!(
        c.borrow().state(),
        hibana_quic::bounded_tls::State::Connected
    );
    assert_eq!(
        s.borrow().state(),
        hibana_quic::bounded_tls::State::Connected
    );
}
