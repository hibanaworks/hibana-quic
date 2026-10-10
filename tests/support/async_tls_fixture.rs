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
use hibana_quic::runtime::TaskSet;
use hibana_quic::runtime::carrier::CarrierStorage;
use hibana_tls::handshake::BoundedTls;
use hibana_tls::handshake::global;
use hibana_tls::handshake::localside;
use hibana_tls::quic::Level;
use hibana_tls::quic::Provider;
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
impl hibana_tls::handshake::MessageInput for Input<'_, '_, '_, '_, '_, '_> {
    async fn read_message(
        &mut self,
        level: Level,
        out: &mut [u8],
    ) -> Result<usize, hibana_tls::handshake::Error> {
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
                        Err(e) => Poll::Ready(Err(hibana_tls::handshake::Error::Input(e))),
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
                        .map_err(hibana_tls::handshake::Error::Input)?;
                    assert_eq!(
                        self.local
                            .borrow_mut()
                            .open(output.level, pn, b"fixture CRYPTO", &mut self.pending[..n])
                            .map_err(hibana_tls::handshake::Error::Input)?,
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
                    return Err(hibana_tls::handshake::Error::Capacity);
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
) -> Result<usize, hibana_tls::handshake::Error> {
    try_handshake_observe::<MESSAGE>(client, server, fragment, protect, |_, _| {})
}

fn try_handshake_observe<const MESSAGE: usize>(
    client: &mut BoundedTls<'_, '_>,
    server: &mut BoundedTls<'_, '_>,
    fragment: usize,
    protect: bool,
    mut observe: impl FnMut(&mut BoundedTls<'_, '_>, &mut BoundedTls<'_, '_>),
) -> Result<usize, hibana_tls::handshake::Error> {
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
    let cs = hibana_tls::handshake::MessageSlot::new(&mut cb);
    let ss = hibana_tls::handshake::MessageSlot::new(&mut sb);
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
    let cp = {
        let graph = global::client();
        (
            hibana::runtime::program::project::<{ global::INPUT }, _>(&graph),
            hibana::runtime::program::project::<{ global::VERIFY }, _>(&graph),
        )
    };
    let sp = {
        let graph = global::server();
        (
            hibana::runtime::program::project::<{ global::INPUT }, _>(&graph),
            hibana::runtime::program::project::<{ global::VERIFY }, _>(&graph),
        )
    };
    let mut cv = cr.enter(cid, &cp.1).unwrap();
    let mut cw = cr.enter(cid, &cp.0).unwrap();
    let mut sv = sr.enter(sid, &sp.1).unwrap();
    let mut sw = sr.enter(sid, &sp.0).unwrap();
    {
        let mut co = pin!(localside::verify::client_owner(&mut cv, &c, &cs));
        let mut cin = pin!(localside::input::client_input(&mut cw, &cs, &mut ci));
        let mut so = pin!(localside::verify::server_owner(&mut sv, &s, &ss));
        let mut sin = pin!(localside::input::server_input(&mut sw, &ss, &mut si));
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
pub fn reject_server_message(
    server: &mut BoundedTls<'_, '_>,
    message: &[u8],
) -> hibana_tls::handshake::Error {
    probe_server_message(server, message, |_| None::<()>).expect_err("invalid ClientHello accepted")
}
pub fn probe_server_message<R>(
    server: &mut BoundedTls<'_, '_>,
    message: &[u8],
    mut observe: impl FnMut(&mut BoundedTls<'_, '_>) -> Option<R>,
) -> Result<R, hibana_tls::handshake::Error> {
    struct One<'a>(&'a [u8], bool);
    impl hibana_tls::handshake::MessageInput for One<'_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, hibana_tls::handshake::Error> {
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
    let slot = hibana_tls::handshake::MessageSlot::new(&mut bytes);
    let carrier = CarrierStorage::<1, 16, 4>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(5202);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let projection = {
        let graph = global::server();
        (
            hibana::runtime::program::project::<{ global::INPUT }, _>(&graph),
            hibana::runtime::program::project::<{ global::VERIFY }, _>(&graph),
        )
    };
    let mut owner = rv.enter(sid, &projection.1).unwrap();
    let mut receiver = rv.enter(sid, &projection.0).unwrap();
    let mut owner = pin!(localside::verify::server_owner(&mut owner, &source, &slot));
    let mut receiver = pin!(localside::input::server_input(
        &mut receiver,
        &slot,
        &mut input
    ));
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
    client: &mut hibana_tls::handshake::keys::KeySource<'client, '_, '_>,
    server: &mut hibana_tls::handshake::keys::KeySource<'server, '_, '_>,
    mut observe: impl FnMut(
        &mut hibana_tls::handshake::keys::KeySource<'_, '_, '_>,
        &mut hibana_tls::handshake::keys::KeySource<'_, '_, '_>,
    ),
) -> (Collected<'client>, Collected<'server>) {
    use hibana_tls::handshake::keys::KeySource;
    struct SourceInput<'a, 'scope, 'cfg, 'buf> {
        remote: &'a RefCell<&'a mut KeySource<'scope, 'cfg, 'buf>>,
        bytes: [u8; 8208],
        pos: usize,
        end: usize,
        level: Level,
    }
    impl hibana_tls::handshake::MessageInput for SourceInput<'_, '_, '_, '_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, hibana_tls::handshake::Error> {
            let mut copied = 0;
            let mut required = 4;
            while copied < required {
                if self.pos == self.end {
                    let output =
                        poll_fn(
                            |_| match self.remote.borrow_mut().transmit(&mut self.bytes) {
                                Ok(Some(p)) => Poll::Ready(Ok(p)),
                                Ok(None) => Poll::Pending,
                                Err(e) => Poll::Ready(Err(hibana_tls::handshake::Error::Input(e))),
                            },
                        )
                        .await?;
                    self.pos = 0;
                    self.end = output.len;
                    self.level = output.level;
                }
                if self.level != level {
                    return Err(hibana_tls::handshake::Error::Binding);
                }
                let n = (required - copied).min(self.end - self.pos);
                out[copied..copied + n].copy_from_slice(&self.bytes[self.pos..self.pos + n]);
                copied += n;
                self.pos += n;
                if copied == 4 {
                    required =
                        4 + ((out[1] as usize) << 16) + ((out[2] as usize) << 8) + out[3] as usize;
                    if required > out.len() {
                        return Err(hibana_tls::handshake::Error::Capacity);
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
    let cs = hibana_tls::handshake::MessageSlot::new(&mut cb);
    let ss = hibana_tls::handshake::MessageSlot::new(&mut sb);
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
    let cp = {
        let graph = hibana_tls::handshake::global::owned::choreography();
        (
            hibana::runtime::program::project::<{ hibana_tls::handshake::global::owned::INPUT }, _>(
                &graph,
            ),
            hibana::runtime::program::project::<{ hibana_tls::handshake::global::owned::VERIFY }, _>(
                &graph,
            ),
            hibana::runtime::program::project::<{ hibana_tls::handshake::global::owned::HANDOFF }, _>(
                &graph,
            ),
        )
    };
    let sp = {
        let graph = hibana_tls::handshake::global::owned::choreography();
        (
            hibana::runtime::program::project::<{ hibana_tls::handshake::global::owned::INPUT }, _>(
                &graph,
            ),
            hibana::runtime::program::project::<{ hibana_tls::handshake::global::owned::VERIFY }, _>(
                &graph,
            ),
            hibana::runtime::program::project::<{ hibana_tls::handshake::global::owned::HANDOFF }, _>(
                &graph,
            ),
        )
    };
    let mut cv = cr.enter(cid, &cp.1).unwrap();
    let mut cw = cr.enter(cid, &cp.0).unwrap();
    let mut sv = sr.enter(sid, &sp.1).unwrap();
    let mut sw = sr.enter(sid, &sp.0).unwrap();
    let mut ch = cr.enter(cid, &cp.2).unwrap();
    let mut sh = sr.enter(sid, &sp.2).unwrap();
    let cmaterial = hibana_tls::handshake::keys::Handoff::<1024>::new();
    let smaterial = hibana_tls::handshake::keys::Handoff::<1024>::new();
    let mut cout = Collected::new();
    let mut sout = Collected::new();
    {
        let mut co = pin!(async {
            cv.send::<global::ClientStart>(&()).await?;
            localside::verify::client_owned(&mut cv, &c, &cs, &cmaterial).await
        });
        let mut so = pin!(async {
            sv.send::<global::ServerStart>(&()).await?;
            localside::verify::server_owned(&mut sv, &s, &ss, &smaterial).await
        });
        let mut cin = pin!(async {
            cw.offer().await?.recv::<global::ClientStart>().await?;
            localside::input::client_input(&mut cw, &cs, &mut ci).await
        });
        let mut sin = pin!(async {
            sw.offer().await?.recv::<global::ServerStart>().await?;
            localside::input::server_input(&mut sw, &ss, &mut si).await
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
    pub handshake: Option<hibana_tls::handshake::keys::HandshakeKeyMaterial<'scope>>,
    pub application: Option<hibana_tls::handshake::keys::ApplicationKeyMaterial<'scope>>,
    pub finished: Option<hibana_tls::handshake::keys::Finished<'scope, 1024>>,
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
    endpoint: &mut hibana::Endpoint<'_, { hibana_tls::handshake::global::owned::HANDOFF }>,
    material: &hibana_tls::handshake::keys::Handoff<'scope, 1024>,
    out: &mut Collected<'scope>,
) -> Result<(), hibana_tls::handshake::Error> {
    use hibana_tls::handshake::global::owned as h;
    async fn take<'scope>(
        endpoint: &mut hibana::Endpoint<'_, { hibana_tls::handshake::global::owned::HANDOFF }>,
        material: &hibana_tls::handshake::keys::Handoff<'scope, 1024>,
        out: &mut Collected<'scope>,
    ) -> Result<(), hibana_tls::handshake::Error> {
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
        _ => return Err(hibana_tls::handshake::Error::Binding),
    };
    take(endpoint, material, out).await?;
    let route = endpoint.offer().await?;
    match route.label() {
        242 => {
            route.recv::<h::RetryKeys>().await?;
            take(endpoint, material, out).await?;
        }
        243 => route.recv::<h::HelloKeys>().await?,
        _ => return Err(hibana_tls::handshake::Error::Binding),
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
            _ => return Err(hibana_tls::handshake::Error::Binding),
        }
    }
    take(endpoint, material, out).await?;
    endpoint.recv::<h::CompleteKeys>().await?;
    Ok(())
}
