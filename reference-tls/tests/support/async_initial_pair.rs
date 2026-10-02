//! Shared in-memory fixture bootstrap. Every test has one outer async drive;
//! real Initial/TLS owners and transport operations stay pending until their real peer
//! tasks run. No socket/network I/O or per-operation blocking bridge is used.
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    carrier::CarrierStorage,
    crypto,
    handshake_endpoint::{INITIAL_PACKET_BYTES, InitialKeyClient, InitialProtection, TlsClient},
    mailbox::Mailbox,
    roles::{
        packet_protection::{self, Command, Exchange, Reply},
        protocol::key_choreography,
        protocol_tls::tls_choreography,
        tls_owner,
    },
    runtime::{Task, TaskSet},
};
use std::{
    future::Future,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
/// Construct before enabling an allocation counter; polling itself allocates
/// nothing and fails if all work parks without a registered wake source.
pub struct Harness {
    count: Arc<Count>,
    waker: Waker,
}
impl Harness {
    pub fn new() -> Self {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        Self { count, waker }
    }
    pub fn drive<F: Future>(&self, mut future: Pin<&mut F>) -> F::Output {
        let mut context = Context::from_waker(&self.waker);
        for _ in 0..1_000_000 {
            let before = self.count.0.load(Ordering::SeqCst);
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result,
                Poll::Pending => assert!(
                    self.count.0.load(Ordering::SeqCst) > before,
                    "fixture parked without a registered wake"
                ),
            }
        }
        panic!("bounded async fixture did not finish");
    }
}
#[derive(Debug)]
enum Stop {
    AssertionsComplete,
    Actor(packet_protection::Error),
    Tls(tls_owner::Error),
}

/// Explicit fixture shutdown outcome. A positive fixture must await actual
/// retirement; only an assertion-checked terminal rejection cancels the peers.
#[allow(dead_code)] // The rustls-only suite has no certificate-rejection case.
pub enum Completion {
    Retired,
    Rejected,
}
/// Retain all six projected endpoint values per connection until their actual
/// Initial RX/TX/TLS owner tasks finish. No actor error is a successful outcome.
pub async fn with_pair<C: hibana_quic::tls::Provider, S: hibana_quic::tls::Provider>(
    client_provider: C,
    server_provider: S,
    application: impl for<'cc, 'cs, 'sc, 'ss, 'ctc, 'cts, 'stc, 'sts> AsyncFnOnce(
        InitialProtection<'cc, 'cs>,
        InitialProtection<'sc, 'ss>,
        TlsClient<'ctc, 'cts>,
        TlsClient<'stc, 'sts>,
    ) -> Completion,
) {
    let cq = CarrierStorage::<1, 16, 64>::new();
    let sq = CarrierStorage::<1, 16, 64>::new();
    let mut cslab = [0; 65536];
    let mut sslab = [0; 65536];
    let mut cstorage = SessionKitStorage::uninit();
    let mut sstorage = SessionKitStorage::uninit();
    let ckit = cstorage.init();
    let skit = sstorage.init();
    let csid = SessionId::new(81);
    let ssid = SessionId::new(82);
    let crv = ckit.rendezvous(&mut cslab, cq.bind(csid).unwrap()).unwrap();
    let srv = skit.rendezvous(&mut sslab, sq.bind(ssid).unwrap()).unwrap();
    let global = g::par(
        g::par(key_choreography::<16, 17>(), key_choreography::<18, 19>()),
        tls_choreography::<24, 25>(),
    );
    let p16 = project::<16, _>(&global);
    let p17 = project::<17, _>(&global);
    let p18 = project::<18, _>(&global);
    let p19 = project::<19, _>(&global);
    let p24 = project::<24, _>(&global);
    let p25 = project::<25, _>(&global);
    let mut c16 = crv.enter(csid, &p16).unwrap();
    let mut c17 = crv.enter(csid, &p17).unwrap();
    let mut c18 = crv.enter(csid, &p18).unwrap();
    let mut c19 = crv.enter(csid, &p19).unwrap();
    let mut s16 = srv.enter(ssid, &p16).unwrap();
    let mut s17 = srv.enter(ssid, &p17).unwrap();
    let mut s18 = srv.enter(ssid, &p18).unwrap();
    let mut s19 = srv.enter(ssid, &p19).unwrap();
    let mut c24 = crv.enter(csid, &p24).unwrap();
    let mut c25 = crv.enter(csid, &p25).unwrap();
    let mut s24 = srv.enter(ssid, &p24).unwrap();
    let mut s25 = srv.enter(ssid, &p25).unwrap();
    let mut crxc: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut crxr: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut ctxc: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut ctxr: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut srxc: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut srxr: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut stxc: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut stxr: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let crxc = Mailbox::new(&mut crxc).unwrap();
    let crxr = Mailbox::new(&mut crxr).unwrap();
    let ctxc = Mailbox::new(&mut ctxc).unwrap();
    let ctxr = Mailbox::new(&mut ctxr).unwrap();
    let srxc = Mailbox::new(&mut srxc).unwrap();
    let srxr = Mailbox::new(&mut srxr).unwrap();
    let stxc = Mailbox::new(&mut stxc).unwrap();
    let stxr = Mailbox::new(&mut stxr).unwrap();
    let (crxs, crx) = crxc.split().unwrap();
    let (crxrs, crxrr) = crxr.split().unwrap();
    let (ctxs, ctx) = ctxc.split().unwrap();
    let (ctxrs, ctxrr) = ctxr.split().unwrap();
    let (srxs, srx) = srxc.split().unwrap();
    let (srxrs, srxrr) = srxr.split().unwrap();
    let (stxs, stx) = stxc.split().unwrap();
    let (stxrs, stxrr) = stxr.split().unwrap();
    let mut crxe = Exchange::new();
    let mut ctxe = Exchange::new();
    let mut srxe = Exchange::new();
    let mut stxe = Exchange::new();
    let mut ctlsc: [Option<tls_owner::Command<1536>>; 1] = [None];
    let mut ctlsr: [Option<tls_owner::Reply<1536, 512>>; 1] = [None];
    let ctlsc = Mailbox::new(&mut ctlsc).unwrap();
    let ctlsr = Mailbox::new(&mut ctlsr).unwrap();
    let (ctlss, ctls) = ctlsc.split().unwrap();
    let (ctlsrs, ctlsrr) = ctlsr.split().unwrap();
    let mut ctlse = tls_owner::Exchange::new();
    let mut stlsc: [Option<tls_owner::Command<1536>>; 1] = [None];
    let mut stlsr: [Option<tls_owner::Reply<1536, 512>>; 1] = [None];
    let stlsc = Mailbox::new(&mut stlsc).unwrap();
    let stlsr = Mailbox::new(&mut stlsr).unwrap();
    let (stlss, stls) = stlsc.split().unwrap();
    let (stlsrs, stlsrr) = stlsr.split().unwrap();
    let mut stlse = tls_owner::Exchange::new();
    let ckeys = crypto::initial_keys(b"original").unwrap();
    let skeys = crypto::initial_keys(b"original").unwrap();
    {
        let mut client_rx = pin!(async {
            packet_protection::run_borrowed(
                &mut c16,
                &mut c17,
                1,
                ckeys.server,
                crx,
                crxrs,
                &mut crxe,
            )
            .await
            .map_err(Stop::Actor)
        });
        let mut client_tx = pin!(async {
            packet_protection::run_borrowed(
                &mut c18,
                &mut c19,
                1,
                ckeys.client,
                ctx,
                ctxrs,
                &mut ctxe,
            )
            .await
            .map_err(Stop::Actor)
        });
        let mut server_rx = pin!(async {
            packet_protection::run_borrowed(
                &mut s16,
                &mut s17,
                2,
                skeys.client,
                srx,
                srxrs,
                &mut srxe,
            )
            .await
            .map_err(Stop::Actor)
        });
        let mut server_tx = pin!(async {
            packet_protection::run_borrowed(
                &mut s18,
                &mut s19,
                2,
                skeys.server,
                stx,
                stxrs,
                &mut stxe,
            )
            .await
            .map_err(Stop::Actor)
        });
        let mut client_tls = pin!(async {
            tls_owner::run_borrowed(
                &mut c24,
                &mut c25,
                1,
                client_provider,
                ctls,
                ctlsrs,
                &mut ctlse,
            )
            .await
            .map_err(Stop::Tls)
        });
        let mut server_tls = pin!(async {
            tls_owner::run_borrowed(
                &mut s24,
                &mut s25,
                2,
                server_provider,
                stls,
                stlsrs,
                &mut stlse,
            )
            .await
            .map_err(Stop::Tls)
        });
        let mut work = pin!(async {
            let ctls = TlsClient::connect(ctlss, ctlsrr, 1).await.unwrap();
            let stls = TlsClient::connect(stlss, stlsrr, 2).await.unwrap();
            let client = InitialProtection::new(
                InitialKeyClient::connect(crxs, crxrr, 1).await.unwrap(),
                InitialKeyClient::connect(ctxs, ctxrr, 1).await.unwrap(),
            )
            .unwrap();
            let server = InitialProtection::new(
                InitialKeyClient::connect(srxs, srxrr, 2).await.unwrap(),
                InitialKeyClient::connect(stxs, stxrr, 2).await.unwrap(),
            )
            .unwrap();
            match application(client, server, ctls, stls).await {
                Completion::Retired => Ok(()),
                Completion::Rejected => Err(Stop::AssertionsComplete),
            }
        });
        let tasks: [Task<'_, Stop>; 7] = [
            client_rx.as_mut(),
            client_tx.as_mut(),
            server_rx.as_mut(),
            server_tx.as_mut(),
            client_tls.as_mut(),
            server_tls.as_mut(),
            work.as_mut(),
        ];
        match TaskSet::new(tasks).await {
            Err(Stop::AssertionsComplete) => {}
            Err(Stop::Actor(error)) => {
                panic!("Initial actor failed before endpoint assertions completed: {error:?}")
            }
            Err(Stop::Tls(error)) => {
                panic!("TLS owner failed before endpoint assertions completed: {error:?}")
            }
            Ok(()) => {}
        }
    }
    assert!(crxe.is_empty() && ctxe.is_empty() && srxe.is_empty() && stxe.is_empty());
    assert!(ctlse.is_empty() && stlse.is_empty());
}
