#![allow(dead_code)] // Shared fixture: each integration crate selects different scenarios.
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
    runtime::TaskSet,
    runtime::carrier::CarrierStorage,
    tls::handshake::{BoundedTls, global, local},
    tls::{Level, Provider},
};
struct Input<'a, 'b, 'cfg, 'buf, 'remote_cfg, 'remote_buf> {
    local: &'a RefCell<&'b mut BoundedTls<'cfg, 'buf>>,
    fragment: usize,
    protect: bool,
    pn: [u64; 3],
    certificates: usize,
    remote: &'a RefCell<&'b mut BoundedTls<'remote_cfg, 'remote_buf>>,
    pending: [u8; 8208],
    used: usize,
    end: usize,
    level: Level,
}
impl local::MessageInput for Input<'_, '_, '_, '_, '_, '_> {
    async fn read_message(&mut self, level: Level, out: &mut [u8]) -> Result<usize, local::Error> {
        let mut copied = 0;
        let mut len = 4;
        while copied < len {
            if self.used == self.end {
                let output = poll_fn(|_| {
                    match self
                        .remote
                        .borrow_mut()
                        .transmit(&mut self.pending[..self.fragment])
                    {
                        Ok(Some(p)) => Poll::Ready(Ok(p)),
                        Ok(None) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(local::Error::Input(e))),
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
                        .borrow_mut()
                        .seal(
                            output.level,
                            pn,
                            b"fixture CRYPTO",
                            &mut self.pending,
                            output.len,
                        )
                        .map_err(local::Error::Input)?;
                    assert_eq!(
                        self.local
                            .borrow_mut()
                            .open(output.level, pn, b"fixture CRYPTO", &mut self.pending[..n])
                            .map_err(local::Error::Input)?,
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
                    return Err(local::Error::Capacity);
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
    observe: impl FnMut(&mut BoundedTls<'_, '_>, &mut BoundedTls<'_, '_>),
) -> usize {
    try_handshake_observe::<8192>(client, server, fragment, protect, observe).unwrap()
}

pub fn try_handshake_with<const MESSAGE: usize>(
    client: &mut BoundedTls<'_, '_>,
    server: &mut BoundedTls<'_, '_>,
    fragment: usize,
    protect: bool,
) -> Result<usize, local::Error> {
    try_handshake_observe::<MESSAGE>(client, server, fragment, protect, |_, _| {})
}

fn try_handshake_observe<const MESSAGE: usize>(
    client: &mut BoundedTls<'_, '_>,
    server: &mut BoundedTls<'_, '_>,
    fragment: usize,
    protect: bool,
    mut observe: impl FnMut(&mut BoundedTls<'_, '_>, &mut BoundedTls<'_, '_>),
) -> Result<usize, local::Error> {
    let c = RefCell::new(client);
    let s = RefCell::new(server);
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
    let mut cb = [0; MESSAGE];
    let mut sb = [0; MESSAGE];
    let cs = local::MessageSlot::new(&mut cb);
    let ss = local::MessageSlot::new(&mut sb);
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
    let cp = global::client_programs();
    let sp = global::server_programs();
    let mut cv = cr.enter(cid, &cp.verify).unwrap();
    let mut cw = cr.enter(cid, &cp.input).unwrap();
    let mut sv = sr.enter(sid, &sp.verify).unwrap();
    let mut sw = sr.enter(sid, &sp.input).unwrap();
    {
        let mut co = pin!(local::client_owner(&mut cv, &c, &cs));
        let mut cin = pin!(local::client_input(&mut cw, &cs, &mut ci));
        let mut so = pin!(local::server_owner(&mut sv, &s, &ss));
        let mut sin = pin!(local::server_input(&mut sw, &ss, &mut si));
        let mut tasks = pin!(TaskSet::new([
            co.as_mut(),
            cin.as_mut(),
            so.as_mut(),
            sin.as_mut()
        ]));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..128 {
            let result = tasks.as_mut().poll(&mut cx);
            observe(&mut c.borrow_mut(), &mut s.borrow_mut());
            if let Poll::Ready(result) = result {
                result?;
                break;
            }
        }
        assert!(
            c.borrow().negotiated_alpn().is_some() && s.borrow().negotiated_alpn().is_some(),
            "actual async transcript did not finish"
        );
    }
    Ok(ci.certificates + si.certificates)
}

/// Deliver one adversarial ClientHello through the real server projection.
/// The test expects rejection before another input message is requested.
pub fn reject_server_message(server: &mut BoundedTls<'_, '_>, message: &[u8]) -> local::Error {
    probe_server_message(server, message, |_| None::<()>).expect_err("invalid ClientHello accepted")
}
pub fn probe_server_message<R>(
    server: &mut BoundedTls<'_, '_>,
    message: &[u8],
    mut observe: impl FnMut(&mut BoundedTls<'_, '_>) -> Option<R>,
) -> Result<R, local::Error> {
    struct One<'a>(&'a [u8], bool);
    impl local::MessageInput for One<'_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, local::Error> {
            if self.1 {
                return core::future::pending().await;
            }
            assert_eq!(level, Level::Initial);
            self.1 = true;
            out[..self.0.len()].copy_from_slice(self.0);
            Ok(self.0.len())
        }
    }
    let source = RefCell::new(server);
    let mut input = One(message, false);
    let mut bytes = [0; 8192];
    let slot = local::MessageSlot::new(&mut bytes);
    let carrier = CarrierStorage::<1, 16, 4>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(5202);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let programs = global::server_programs();
    let mut owner = rv.enter(sid, &programs.verify).unwrap();
    let mut receiver = rv.enter(sid, &programs.input).unwrap();
    let mut owner = pin!(local::server_owner(&mut owner, &source, &slot));
    let mut receiver = pin!(local::server_input(&mut receiver, &slot, &mut input));
    let mut tasks = pin!(TaskSet::new([owner.as_mut(), receiver.as_mut()]));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        let result = tasks.as_mut().poll(&mut cx);
        if let Some(value) = observe(&mut source.borrow_mut()) {
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
pub fn handshake_key_sources_observe<'client, 'server>(
    client: &mut hibana_quic::tls::handshake::key_source::KeySource<'client, '_, '_>,
    server: &mut hibana_quic::tls::handshake::key_source::KeySource<'server, '_, '_>,
    mut observe: impl FnMut(
        &mut hibana_quic::tls::handshake::key_source::KeySource<'_, '_, '_>,
        &mut hibana_quic::tls::handshake::key_source::KeySource<'_, '_, '_>,
    ),
) -> (Collected<'client>, Collected<'server>) {
    use hibana_quic::tls::handshake::key_source::KeySource;
    struct SourceInput<'a, 'scope, 'cfg, 'buf> {
        remote: &'a RefCell<&'a mut KeySource<'scope, 'cfg, 'buf>>,
        bytes: [u8; 8208],
        pos: usize,
        end: usize,
        level: Level,
    }
    impl local::MessageInput for SourceInput<'_, '_, '_, '_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, local::Error> {
            let mut copied = 0;
            let mut required = 4;
            while copied < required {
                if self.pos == self.end {
                    let output =
                        poll_fn(
                            |_| match self.remote.borrow_mut().transmit(&mut self.bytes) {
                                Ok(Some(p)) => Poll::Ready(Ok(p)),
                                Ok(None) => Poll::Pending,
                                Err(e) => Poll::Ready(Err(local::Error::Input(e))),
                            },
                        )
                        .await?;
                    self.pos = 0;
                    self.end = output.len;
                    self.level = output.level;
                }
                if self.level != level {
                    return Err(local::Error::Binding);
                }
                let n = (required - copied).min(self.end - self.pos);
                out[copied..copied + n].copy_from_slice(&self.bytes[self.pos..self.pos + n]);
                copied += n;
                self.pos += n;
                if copied == 4 {
                    required =
                        4 + ((out[1] as usize) << 16) + ((out[2] as usize) << 8) + out[3] as usize;
                    if required > out.len() {
                        return Err(local::Error::Capacity);
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
    let cs = local::MessageSlot::new(&mut cb);
    let ss = local::MessageSlot::new(&mut sb);
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
    let cp = hibana_tls::owned_global::programs();
    let sp = hibana_tls::owned_global::programs();
    let mut cv = cr.enter(cid, &cp.verify).unwrap();
    let mut cw = cr.enter(cid, &cp.input).unwrap();
    let mut sv = sr.enter(sid, &sp.verify).unwrap();
    let mut sw = sr.enter(sid, &sp.input).unwrap();
    let mut ch = cr.enter(cid, &cp.handoff).unwrap();
    let mut sh = sr.enter(sid, &sp.handoff).unwrap();
    let cmaterial = hibana_tls::handshake::key_source::Handoff::<1024>::new();
    let smaterial = hibana_tls::handshake::key_source::Handoff::<1024>::new();
    let mut cout = Collected::new();
    let mut sout = Collected::new();
    {
        let mut co = pin!(async {
            cv.send::<global::ClientStart>(&()).await?;
            local::client_owned(&mut cv, &c, &cs, &cmaterial).await
        });
        let mut so = pin!(async {
            sv.send::<global::ServerStart>(&()).await?;
            local::server_owned(&mut sv, &s, &ss, &smaterial).await
        });
        let mut cin = pin!(async {
            cw.offer().await?.recv::<global::ClientStart>().await?;
            local::client_input(&mut cw, &cs, &mut ci).await
        });
        let mut sin = pin!(async {
            sw.offer().await?.recv::<global::ServerStart>().await?;
            local::server_input(&mut sw, &ss, &mut si).await
        });
        let mut ct = pin!(collect(&mut ch, &cmaterial, &mut cout));
        let mut st = pin!(collect(&mut sh, &smaterial, &mut sout));
        let mut tasks = pin!(TaskSet::new([
            co.as_mut(),
            so.as_mut(),
            cin.as_mut(),
            sin.as_mut(),
            ct.as_mut(),
            st.as_mut()
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
    assert!(cout.finished.is_some());
    assert!(sout.finished.is_some());
    (cout, sout)
}

/// Actual affine material retained by the test's projected receiving local.
/// No keys or Finished receipt are reconstructed from the source after handoff.
pub struct Collected<'scope> {
    pub handshake: Option<hibana_tls::handshake::key_source::HandshakeKeyMaterial<'scope>>,
    pub application: Option<hibana_tls::handshake::key_source::ApplicationKeyMaterial<'scope>>,
    pub finished: Option<hibana_tls::handshake::key_source::Finished<'scope, 1024>>,
}
impl Collected<'_> {
    fn new() -> Self {
        Self {
            handshake: None,
            application: None,
            finished: None,
        }
    }
}
async fn collect<'scope>(
    endpoint: &mut hibana::Endpoint<'_, { hibana_tls::owned_global::HANDOFF }>,
    material: &hibana_tls::handshake::key_source::Handoff<'scope, 1024>,
    out: &mut Collected<'scope>,
) -> Result<(), local::Error> {
    use hibana_tls::owned_global as h;
    async fn take<'scope>(
        endpoint: &mut hibana::Endpoint<'_, { hibana_tls::owned_global::HANDOFF }>,
        material: &hibana_tls::handshake::key_source::Handoff<'scope, 1024>,
        out: &mut Collected<'scope>,
    ) -> Result<(), local::Error> {
        endpoint.recv::<h::KeysReady>().await?;
        if let Some(v) = material.take_handshake() {
            assert!(out.handshake.replace(v).is_none());
        }
        if let Some(v) = material.take_application() {
            assert!(out.application.replace(v).is_none());
        }
        if let Some(v) = material.take_finished() {
            assert!(out.finished.replace(v).is_none());
        }
        assert!(material.is_empty());
        endpoint.send::<h::KeysTaken>(&()).await?;
        Ok(())
    }
    let route = endpoint.offer().await?;
    let client = match route.label() {
        247 => {
            route.recv::<h::ClientKeys>().await?;
            true
        }
        248 => {
            route.recv::<h::ServerKeys>().await?;
            false
        }
        _ => return Err(local::Error::Binding),
    };
    take(endpoint, material, out).await?;
    let route = endpoint.offer().await?;
    match route.label() {
        242 => {
            route.recv::<h::RetryKeys>().await?;
            take(endpoint, material, out).await?;
        }
        243 => route.recv::<h::HelloKeys>().await?,
        _ => return Err(local::Error::Binding),
    }
    if client {
        take(endpoint, material, out).await?;
        let route = endpoint.offer().await?;
        match route.label() {
            244 => route.recv::<h::ResumedKeys>().await?,
            245 => {
                route.recv::<h::FullKeys>().await?;
                take(endpoint, material, out).await?;
                take(endpoint, material, out).await?;
            }
            _ => return Err(local::Error::Binding),
        }
    }
    take(endpoint, material, out).await?;
    endpoint.recv::<h::CompleteKeys>().await?;
    Ok(())
}
