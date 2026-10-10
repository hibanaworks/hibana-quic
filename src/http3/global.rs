//! HTTP/3 control progression: the first actual SETTINGS receipt selects the
//! ready continuation. Subsequent frames cannot re-enter startup.
//!
//! The OWNER endpoint is executed by [`crate::http3::local`]. SOURCE and SINK
//! are the request/response locals in the QUIC application. The complete graph is
//! projected by [`crate::quic::application::global::programs`], attached by
//! [`crate::quic::application::local::Endpoints`], and polled in
//! [`crate::quic::application::local::run`]. Byte parsing lives in [`crate::http3::imp`].
use hibana::g;
use hibana::runtime::program::Projectable;
pub const OWNER: u8 = crate::quic::global::INITIAL_OWNER;
pub const SOURCE: u8 = crate::quic::application::global::SOURCE;
pub const SINK: u8 = crate::quic::application::global::SINK;
pub type Plain = g::Msg<238, ()>;
pub type Http3 = g::Msg<239, ()>;
pub type PlainSink = g::Msg<240, ()>;
pub type Http3Sink = g::Msg<241, ()>;
pub type StartupSettled = g::Msg<242, ()>;
pub type Input = g::Msg<244, ()>;
pub type SettingsStored = g::Msg<245, ()>;
pub type Stored = g::Msg<246, ()>;
pub type EarlyClosed = g::Msg<247, ()>;
pub type Closed = g::Msg<248, ()>;
pub fn choreography() -> impl Projectable {
    g::route(
        g::seq(
            g::send::<SOURCE, OWNER, Plain>(),
            g::seq(
                g::send::<OWNER, SINK, PlainSink>(),
                g::send::<OWNER, SOURCE, StartupSettled>(),
            ),
        ),
        g::seq(
            g::send::<SOURCE, OWNER, Http3>(),
            g::seq(
                g::send::<OWNER, SINK, Http3Sink>(),
                g::seq(
                    g::send::<SINK, OWNER, Input>(),
                    g::route(
                        g::seq(
                            g::send::<OWNER, SOURCE, StartupSettled>(),
                            g::seq(
                                g::send::<OWNER, SINK, SettingsStored>(),
                                g::seq(
                                    g::send::<SINK, OWNER, Input>(),
                                    g::route(
                                        g::send::<OWNER, SINK, Stored>(),
                                        g::send::<OWNER, SINK, Closed>(),
                                    ),
                                )
                                .roll(),
                            ),
                        ),
                        g::seq(
                            g::send::<OWNER, SINK, EarlyClosed>(),
                            g::send::<OWNER, SOURCE, StartupSettled>(),
                        ),
                    ),
                ),
            ),
        ),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn http3_global_projects_with_existing_connection_boundaries() {
        // Force the complete projection through code generation, not just
        // `cargo check`, which can defer validation of generic constants.
        let _programs = crate::quic::application::global::programs();
    }

    #[test]
    fn settings_settle_source_before_sink_can_offer_another_frame() {
        use super::*;
        use core::{
            future::Future,
            pin::pin,
            task::{Context, Poll, Waker},
        };
        use hibana::runtime::{
            SessionKitStorage,
            ids::SessionId,
            program::{RoleProgram, project},
        };
        let global = choreography();
        let source_program: RoleProgram<SOURCE> = project(&global);
        let sink_program: RoleProgram<SINK> = project(&global);
        let owner_program: RoleProgram<OWNER> = project(&global);
        let carrier = crate::runtime::carrier::CarrierStorage::<1, 16, 32>::new();
        let mut slab = std::vec![0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(511);
        let rv = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut source = rv.enter(sid, &source_program).unwrap();
        let mut sink = rv.enter(sid, &sink_program).unwrap();
        let mut owner = rv.enter(sid, &owner_program).unwrap();
        let source = async {
            source.send::<Http3>(&()).await.unwrap();
            source.recv::<StartupSettled>().await.unwrap();
        };
        let sink = async {
            sink.recv::<Http3Sink>().await.unwrap();
            sink.send::<Input>(&()).await.unwrap();
            sink.offer()
                .await
                .unwrap()
                .recv::<SettingsStored>()
                .await
                .unwrap();
            // A second frame was already coalesced with SETTINGS. There is no
            // timer, buffer enlargement or artificial yield between frames.
            sink.send::<Input>(&()).await.unwrap();
            sink.offer().await.unwrap().recv::<Stored>().await.unwrap();
            sink.send::<Input>(&()).await.unwrap();
            sink.offer().await.unwrap().recv::<Closed>().await.unwrap();
        };
        let owner = async {
            owner.offer().await.unwrap().recv::<Http3>().await.unwrap();
            owner.send::<Http3Sink>(&()).await.unwrap();
            owner.recv::<Input>().await.unwrap();
            owner.send::<StartupSettled>(&()).await.unwrap();
            owner.send::<SettingsStored>(&()).await.unwrap();
            owner.recv::<Input>().await.unwrap();
            owner.send::<Stored>(&()).await.unwrap();
            owner.recv::<Input>().await.unwrap();
            owner.send::<Closed>(&()).await.unwrap();
        };
        let mut tasks = pin!(async {
            crate::runtime::join::values3(
                async {
                    source.await;
                    Ok::<(), core::convert::Infallible>(())
                },
                async {
                    sink.await;
                    Ok::<(), core::convert::Infallible>(())
                },
                async {
                    owner.await;
                    Ok::<(), core::convert::Infallible>(())
                },
            )
            .await
            .unwrap();
        });
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..128 {
            if let Poll::Ready(()) = tasks.as_mut().poll(&mut cx) {
                assert_eq!(carrier.queued(), 0);
                return;
            }
        }
        panic!("HTTP/3 startup parked with a retained control descriptor");
    }
}
