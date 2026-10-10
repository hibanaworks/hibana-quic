//! Source, ingress and sink ownership integration tests.
use core::cell::{Cell, RefCell};

use super::{BodyReader, ClientRequests, Control, Error, MAX_REQUESTS, StreamSink, global as p};
use crate::quic::application::imp::stream::MAX_LIVE_STREAMS;

use super::{ingress::*, sink::*, source::*};
use crate::quic::application::imp::io::*;
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

#[cfg(test)]
struct EmptyBody;
#[cfg(test)]
impl BodyReader for EmptyBody {
    async fn read(&mut self, _: &mut [u8]) -> Result<usize, ()> {
        panic!("chunk-only fixture must not read a body")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn reusable_sink_storage_delivers_only_each_initialized_prefix() {
        use crate::crypto::directional::ApplicationKeyScope;
        use crate::quic::application::imp::stream::{Facets, StreamNumbers};
        use crate::quic::imp::kernel::packet::Frame;
        use crate::quic::imp::kernel::streams::{
            Limits, PacketReference, Role, SendChunk, StreamSlot,
        };
        use crate::quic::imp::publication_gate::PublicationGate;
        struct Sink {
            data: [u8; 10],
            len: usize,
            finished: usize,
        }
        impl StreamSink for Sink {
            async fn write(&mut self, id: u64, bytes: &[u8]) -> Result<(), ()> {
                assert_eq!(id, 0);
                self.data[self.len..self.len + bytes.len()].copy_from_slice(bytes);
                self.len += bytes.len();
                Ok(())
            }
            async fn finish(&mut self, id: u64) -> Result<(), ()> {
                assert_eq!(id, 0);
                self.finished += 1;
                Ok(())
            }
        }
        let mut scope = ApplicationKeyScope::new(918);
        let mut installation = scope.claim().unwrap();
        let mut gate = PublicationGate::new(installation.take_publication_gate().unwrap());
        let (_, stop) = gate.split().unwrap();
        let control = Control::new(stop);
        let limits = Limits {
            max_data: 16,
            max_streams_bidi: 1,
            max_streams_uni: 0,
            stream_data_bidi_local: 16,
            stream_data_bidi_remote: 16,
            stream_data_uni: 0,
        };
        let mut slots = [StreamSlot::<16>::EMPTY; 1];
        let mut chunks = [SendChunk::<8>::EMPTY; 1];
        let mut references = [PacketReference::EMPTY; 4];
        let mut numbers = StreamNumbers::new(
            installation.scope(),
            Role::Server,
            limits,
            limits,
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets { app, mut rx, .. } = numbers.split();
        let app = RefCell::new(app);
        let state = Exchange::<8, EmptyBody>::new();
        let mut sink = Sink {
            data: [0; 10],
            len: 0,
            finished: 0,
        };
        let mut storage = [0xa5; 16];
        rx.apply(&Frame::Stream {
            id: 0,
            offset: 0,
            fin: false,
            data: b"abcdefgh",
        })
        .unwrap();
        assert_eq!(
            ready(deliver(&control, &state, &app, &mut sink, 0, &mut storage)).unwrap(),
            Delivery::More
        );
        assert_eq!(&storage[8..], &[0xa5; 8]);
        rx.apply(&Frame::Stream {
            id: 0,
            offset: 8,
            fin: true,
            data: b"ij",
        })
        .unwrap();
        assert_eq!(
            ready(deliver(&control, &state, &app, &mut sink, 0, &mut storage)).unwrap(),
            Delivery::Fin
        );
        assert_eq!(sink.data, *b"abcdefghij");
        assert_eq!(sink.len, 10);
        assert_eq!(sink.finished, 1);
        assert_eq!(&storage[2..8], b"cdefgh");
    }

    #[test]
    fn retained_request_accepts_exact_capacity_and_rejects_overflow_without_consuming() {
        use crate::crypto::directional::ApplicationKeyScope;
        use crate::quic::application::imp::stream::Facets;
        use crate::quic::application::imp::stream::StreamNumbers;
        use crate::quic::imp::kernel::packet::Frame;
        use crate::quic::imp::kernel::streams::Limits;
        use crate::quic::imp::kernel::streams::PacketReference;
        use crate::quic::imp::kernel::streams::Role;
        use crate::quic::imp::kernel::streams::SendChunk;
        use crate::quic::imp::kernel::streams::StreamSlot;
        use crate::quic::imp::publication_gate::PublicationGate;
        let mut scope = ApplicationKeyScope::new(917);
        let mut installation = scope.claim().unwrap();
        let mut gate = PublicationGate::new(installation.take_publication_gate().unwrap());
        let (_, stop) = gate.split().unwrap();
        let control = Control::new(stop);
        let limits = Limits {
            max_data: 16,
            max_streams_bidi: 2,
            max_streams_uni: 0,
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            stream_data_uni: 0,
        };
        let mut slots = [StreamSlot::<8>::EMPTY; 2];
        let mut chunks = [SendChunk::<8>::EMPTY; 2];
        let mut references = [PacketReference::EMPTY; 4];
        let mut numbers = StreamNumbers::new(
            installation.scope(),
            Role::Server,
            limits,
            limits,
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets { app, mut rx, .. } = numbers.split();
        let app = RefCell::new(app);
        let state = Exchange::<8, EmptyBody>::new();
        let mut pending = [const { None }; MAX_LIVE_STREAMS];
        let mut queue = [const { None }; REQUEST_CAPACITY];
        let mailbox = crate::runtime::mailbox::Mailbox::new(&mut queue).unwrap();
        let (mut sender, mut receiver) = mailbox.split().unwrap();
        for id in [0, 4] {
            for offset in (0..REQUEST_BYTES).step_by(8) {
                rx.apply(&Frame::Stream {
                    id,
                    offset: offset as u64,
                    fin: false,
                    data: b"abcdefgh",
                })
                .unwrap();
                assert_eq!(
                    ready(receive_request(
                        &control,
                        &state,
                        &app,
                        &mut sender,
                        &mut pending,
                        id
                    ))
                    .unwrap(),
                    Delivery::More
                );
            }
            if id == 0 {
                rx.apply(&Frame::Stream {
                    id,
                    offset: REQUEST_BYTES as u64,
                    fin: true,
                    data: b"",
                })
                .unwrap();
                assert_eq!(
                    ready(receive_request(
                        &control,
                        &state,
                        &app,
                        &mut sender,
                        &mut pending,
                        id
                    ))
                    .unwrap(),
                    Delivery::Fin
                );
                let request = ready(receiver.recv()).unwrap();
                assert_eq!(request.len, REQUEST_BYTES);
                assert!(
                    request
                        .bytes
                        .chunks_exact(8)
                        .all(|bytes| bytes == b"abcdefgh")
                );
            } else {
                rx.apply(&Frame::Stream {
                    id,
                    offset: REQUEST_BYTES as u64,
                    fin: true,
                    data: b"x",
                })
                .unwrap();
                assert!(
                    ready(receive_request(
                        &control,
                        &state,
                        &app,
                        &mut sender,
                        &mut pending,
                        id
                    ))
                    .is_err()
                );
                let stream = ready_handle(&app, id).unwrap();
                app.borrow_mut()
                    .consume(stream, |view| {
                        assert_eq!(view.first, b"x");
                        assert!(view.fin);
                        Ok(0)
                    })
                    .unwrap();
                assert!(!state.is_complete(id));
            }
        }
    }

    #[test]
    fn all_admitted_requests_enqueue_while_response_source_is_paused() {
        let mut slots = [None; REQUEST_CAPACITY];
        let mailbox = crate::runtime::mailbox::Mailbox::new(&mut slots).unwrap();
        let (mut sender, mut receiver) = mailbox.split().unwrap();
        // No consumer poll occurs until all admitted stream requests arrive.
        // An eight-entry queue parks here before RX can receive transport ACKs.
        for stream in 0..MAX_LIVE_STREAMS {
            ready(sender.send(stream)).unwrap();
        }
        for stream in 0..MAX_LIVE_STREAMS {
            assert_eq!(ready(receiver.recv()).unwrap(), stream);
        }
    }

    struct Requests {
        remaining: usize,
        pending: bool,
        started: usize,
    }

    impl ClientRequests for Requests {
        async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
            assert!(
                !self.pending,
                "next must not overwrite an unstarted request"
            );
            if self.remaining == 0 {
                return Ok(None);
            }
            output[0] = b'/';
            self.pending = true;
            Ok(Some(1))
        }

        fn started(&mut self, _stream_id: u64) -> Result<(), ()> {
            assert!(self.pending, "started must correspond to exactly one next");
            self.pending = false;
            self.remaining -= 1;
            self.started += 1;
            Ok(())
        }
    }

    fn ready<T>(future: impl Future<Output = T>) -> T {
        match pin!(future)
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("bounded request admission unexpectedly parked"),
        }
    }

    #[test]
    fn exactly_sixteen_requests_reach_eof_without_capacity_failure() {
        let state = Exchange::<8, EmptyBody>::new();
        let mut requests = Requests {
            remaining: MAX_REQUESTS,
            pending: false,
            started: 0,
        };
        let mut bytes = [0; REQUEST_BYTES];
        for index in 0..MAX_REQUESTS {
            assert_eq!(
                ready(next_request(&state, &mut requests, &mut bytes)).unwrap(),
                Some(1)
            );
            assert!(requests.pending);
            requests.started(index as u64 * 4).unwrap();
            state.submitted().unwrap();
        }
        assert_eq!(
            ready(next_request(&state, &mut requests, &mut bytes)).unwrap(),
            None
        );
        assert_eq!(state.submitted_count(), MAX_REQUESTS);
        assert_eq!(requests.started, MAX_REQUESTS);
        assert!(!requests.pending);
    }

    #[test]
    fn seventeenth_request_is_rejected_while_still_pending() {
        let state = Exchange::<8, EmptyBody>::new();
        let mut requests = Requests {
            remaining: MAX_REQUESTS + 1,
            pending: false,
            started: 0,
        };
        let mut bytes = [0; REQUEST_BYTES];
        for index in 0..MAX_REQUESTS {
            ready(next_request(&state, &mut requests, &mut bytes)).unwrap();
            requests.started(index as u64 * 4).unwrap();
            state.submitted().unwrap();
        }
        assert!(matches!(
            ready(next_request(&state, &mut requests, &mut bytes)),
            Err(Error::Capacity)
        ));
        assert!(requests.pending);
        assert_eq!(requests.remaining, 1);
        assert_eq!(requests.started, MAX_REQUESTS);
        assert_eq!(state.submitted_count(), MAX_REQUESTS);
    }
}

#[cfg(test)]
mod stop_tests {
    use super::*;
    use crate::crypto::directional::ApplicationKeyScope;
    use crate::quic::application::imp::stream::Facets;
    use crate::quic::application::imp::stream::StreamNumbers;
    use crate::quic::imp::kernel::streams::Limits;
    use crate::quic::imp::kernel::streams::PacketReference;
    use crate::quic::imp::kernel::streams::Role;
    use crate::quic::imp::kernel::streams::SendChunk;
    use crate::quic::imp::kernel::streams::StreamSlot;
    use crate::quic::imp::publication_gate::PublicationGate;
    use crate::runtime::carrier::CarrierStorage;
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

    struct CountingBody<'a> {
        drops: &'a Cell<usize>,
        reads: &'a Cell<usize>,
        byte: Option<u8>,
        fail: bool,
    }
    impl BodyReader for CountingBody<'_> {
        async fn read(&mut self, output: &mut [u8]) -> Result<usize, ()> {
            let mut yielded = false;
            core::future::poll_fn(|cx| {
                if !yielded {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            self.reads.set(self.reads.get() + 1);
            if self.fail {
                return Err(());
            }
            match self.byte.take() {
                Some(byte) => {
                    output[0] = byte;
                    Ok(1)
                }
                None => Ok(0),
            }
        }
    }
    impl Drop for CountingBody<'_> {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    fn stopped_ingress(fin: bool, body: bool, fail_second: bool) {
        let mut scope = ApplicationKeyScope::new(912);
        let mut installation = scope.claim().unwrap();
        let mut gate = PublicationGate::new(installation.take_publication_gate().unwrap());
        let (_issuer, stop) = gate.split().unwrap();
        let control = Control::new(stop);
        let limits = Limits {
            max_data: 16,
            max_streams_bidi: 2,
            max_streams_uni: 0,
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            stream_data_uni: 0,
        };
        let mut slots = [StreamSlot::<8>::EMPTY; 2];
        let mut chunks = [SendChunk::<8>::EMPTY; 4];
        let mut refs = [PacketReference::EMPTY; 4];
        let mut numbers = StreamNumbers::new(
            installation.scope(),
            Role::Client,
            limits,
            Limits {
                max_streams_bidi: 0,
                ..limits
            },
            &mut slots,
            &mut chunks,
            &mut refs,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            reset: mut effects,
            ..
        } = numbers.split();
        let first = app.open_local().unwrap();
        let first_production = app.take_production(first).unwrap();
        effects
            .apply(rx.stop_intent(first.id(), 7).unwrap())
            .unwrap();
        let second = app.open_local().unwrap();
        let second_production = app.take_production(second).unwrap();
        let app = RefCell::new(app);
        let drops = Cell::new(0);
        let reads = Cell::new(0);
        let state = Exchange::<8, CountingBody<'_>>::new();
        let global = p::source_choreography();
        let source: RoleProgram<{ p::SOURCE }> = project(&global);
        let source_join_role: RoleProgram<{ p::SOURCE_JOIN }> = project(&global);
        let ingress_role: RoleProgram<{ p::INGRESS }> = project(&global);
        let collector_role: RoleProgram<{ p::SOURCE_COLLECTOR }> = project(&global);
        let reclaim = crate::quic::application::imp::reclaim::Exchange::new();
        let carrier = CarrierStorage::<1, 16, 8>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let id = SessionId::new(912);
        let rv = storage
            .init()
            .rendezvous(&mut slab, carrier.bind(id).unwrap())
            .unwrap();
        let mut source = rv.enter(id, &source).unwrap();
        let mut source_join = rv.enter(id, &source_join_role).unwrap();
        let mut input = rv.enter(id, &ingress_role).unwrap();
        let mut collector = rv.enter(id, &collector_role).unwrap();
        let allocations = actor_test_allocator::NoAlloc::start();
        let mut all = pin!(crate::runtime::join2(
            async {
                {
                    let endpoint = &mut source;
                    let state = &state;
                    let production = first_production;

                    let id = production.id();
                    state.opened.put(production).map_err(|_| Error::Binding)?;
                    endpoint.send::<p::SourceOpen>(&id).await?;
                }
                let outcome = if fin {
                    Admission::Accepted
                } else {
                    let result = async {
                        let endpoint = &mut source;
                        let state = &state;

                        let input = if body {
                            Input::Body(CountingBody {
                                drops: &drops,
                                reads: &reads,
                                byte: Some(1),
                                fail: false,
                            })
                        } else {
                            Input::Chunk(Chunk {
                                bytes: [1; 8],
                                len: 1,
                            })
                        };

                        state.data.put(input).map_err(|_| Error::Binding)?;
                        endpoint.send::<p::SourceData>(&()).await?;
                        let reply = endpoint.offer().await?;
                        let accepted = match reply.label() {
                            1 => {
                                reply.recv::<p::SourceAccepted>().await?;
                                Admission::Accepted
                            }
                            2 => {
                                reply.recv::<p::SourceRejected>().await?;
                                Admission::Interrupted
                            }
                            187 => {
                                reply.recv::<p::SourceStopped>().await?;
                                Admission::Stopped
                            }
                            215 => {
                                reply.recv::<p::SourceDataFailed>().await?;
                                Admission::Failed
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        endpoint.send::<p::SourceTaken>(&()).await?;

                        Ok(accepted)
                    }
                    .await?;
                    assert!(result == Admission::Stopped);
                    result
                };
                assert!(
                    async {
                        let endpoint = &mut source;
                        let stream_id = first.id();

                        endpoint.send::<p::SourceDataFinished>(&stream_id).await?;
                        if outcome == Admission::Accepted {
                            endpoint.send::<p::SourceFin>(&stream_id).await?;
                        } else {
                            // Connection shutdown abandons production; this is not a fabricated
                            // RESET_STREAM acknowledgment or a claim that FIN reached the peer.
                            endpoint.send::<p::SourceAbandon>(&stream_id).await?;
                        }
                        let reply = endpoint.offer().await?;
                        match reply.label() {
                            171 => {
                                check(reply.recv::<p::SourceEnded>().await?, stream_id)?;
                                Ok(outcome)
                            }
                            172 => {
                                check(reply.recv::<p::SourceEndRejected>().await?, stream_id)?;
                                Ok(Admission::Interrupted)
                            }
                            188 => {
                                check(reply.recv::<p::SourceEndStopped>().await?, stream_id)?;
                                Ok(Admission::Stopped)
                            }
                            216 => {
                                check(reply.recv::<p::SourceEndFailed>().await?, stream_id)?;
                                Ok(Admission::Failed)
                            }
                            label => Err(Error::UnexpectedLabel(label)),
                        }
                    }
                    .await?
                        == Admission::Stopped
                );
                assert!(!control.stopping());
                {
                    let endpoint = &mut source;
                    let state = &state;
                    let production = second_production;

                    let id = production.id();
                    state.opened.put(production).map_err(|_| Error::Binding)?;
                    endpoint.send::<p::SourceOpen>(&id).await?;
                }
                let second_outcome = async {
                    let endpoint = &mut source;
                    let state = &state;

                    let input = if body {
                        Input::Body(CountingBody {
                            drops: &drops,
                            reads: &reads,
                            byte: Some(2),
                            fail: fail_second,
                        })
                    } else {
                        Input::Chunk(Chunk {
                            bytes: [2; 8],
                            len: 1,
                        })
                    };

                    state.data.put(input).map_err(|_| Error::Binding)?;
                    endpoint.send::<p::SourceData>(&()).await?;
                    let reply = endpoint.offer().await?;
                    let accepted = match reply.label() {
                        1 => {
                            reply.recv::<p::SourceAccepted>().await?;
                            Admission::Accepted
                        }
                        2 => {
                            reply.recv::<p::SourceRejected>().await?;
                            Admission::Interrupted
                        }
                        187 => {
                            reply.recv::<p::SourceStopped>().await?;
                            Admission::Stopped
                        }
                        215 => {
                            reply.recv::<p::SourceDataFailed>().await?;
                            Admission::Failed
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    };
                    endpoint.send::<p::SourceTaken>(&()).await?;

                    Ok(accepted)
                }
                .await?;
                let expected = if fail_second {
                    Admission::Failed
                } else {
                    Admission::Accepted
                };
                assert!(second_outcome == expected);
                assert!(
                    async {
                        let endpoint = &mut source;
                        let stream_id = second.id();
                        let outcome = second_outcome;

                        endpoint.send::<p::SourceDataFinished>(&stream_id).await?;
                        if outcome == Admission::Accepted {
                            endpoint.send::<p::SourceFin>(&stream_id).await?;
                        } else {
                            // Connection shutdown abandons production; this is not a fabricated
                            // RESET_STREAM acknowledgment or a claim that FIN reached the peer.
                            endpoint.send::<p::SourceAbandon>(&stream_id).await?;
                        }
                        let reply = endpoint.offer().await?;
                        match reply.label() {
                            171 => {
                                check(reply.recv::<p::SourceEnded>().await?, stream_id)?;
                                Ok(outcome)
                            }
                            172 => {
                                check(reply.recv::<p::SourceEndRejected>().await?, stream_id)?;
                                Ok(Admission::Interrupted)
                            }
                            188 => {
                                check(reply.recv::<p::SourceEndStopped>().await?, stream_id)?;
                                Ok(Admission::Stopped)
                            }
                            216 => {
                                check(reply.recv::<p::SourceEndFailed>().await?, stream_id)?;
                                Ok(Admission::Failed)
                            }
                            label => Err(Error::UnexpectedLabel(label)),
                        }
                    }
                    .await?
                        == expected
                );
                {
                    let endpoint = &mut source;
                    let control = &control;
                    endpoint.send::<p::SourceDone>(&()).await?;
                    endpoint.recv::<p::SourceRetired>().await?;
                    if second_outcome == Admission::Failed {
                        endpoint.send::<p::SourceFailed>(&()).await?;
                    } else {
                        endpoint.send::<p::SourceJoined>(&()).await?;
                    }
                    control.changed()?;
                }
                Ok::<_, Error>(())
            },
            crate::runtime::join2(
                ingress(&mut input, &control, &state, &app, &reclaim),
                crate::runtime::join2(
                    super::super::reclaim::source(&mut collector, &reclaim, &control),
                    async {
                        let offered = source_join.offer().await?;
                        if fail_second {
                            offered.recv::<p::SourceFailed>().await?;
                        } else {
                            offered.recv::<p::SourceJoined>().await?;
                        }
                        Ok::<(), Error>(())
                    }
                )
            )
        ));
        for _ in 0..1000 {
            if let Poll::Ready(result) = all.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            {
                result.unwrap();
                allocations.finish();
                if body {
                    // The stopped body is read once, never reaches EOF, and
                    // is dropped once. The next body is read through real EOF.
                    assert_eq!(reads.get(), if fail_second { 2 } else { 3 });
                    assert_eq!(drops.get(), 2);
                }
                return;
            }
        }
        panic!("real ingress stalled after peer stop");
    }
    #[test]
    fn actual_ingress_preserves_connection_after_stopped_data_and_fin() {
        stopped_ingress(false, false, false);
        stopped_ingress(true, false, false);
    }
    #[test]
    fn actual_owned_body_moves_once_and_stop_does_not_fabricate_eof() {
        stopped_ingress(false, true, false);
    }
    #[test]
    fn actual_body_read_failure_is_rejected_without_a_successful_eof() {
        stopped_ingress(false, true, true);
    }
}

#[cfg(test)]
mod interrupted_delivery_tests {
    use super::*;
    use crate::crypto::directional::ApplicationKeyScope;
    use crate::quic::application::imp::stream::Facets;
    use crate::quic::application::imp::stream::StreamNumbers;
    use crate::quic::imp::kernel::streams::Limits;
    use crate::quic::imp::kernel::streams::PacketReference;
    use crate::quic::imp::kernel::streams::Role;
    use crate::quic::imp::kernel::streams::SendChunk;
    use crate::quic::imp::kernel::streams::StreamSlot;
    use crate::quic::imp::publication_gate::PublicationGate;
    use crate::runtime::carrier::CarrierStorage;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use hibana::g::Message;
    use hibana::runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    };
    struct NeverSink;
    impl StreamSink for NeverSink {
        async fn write(&mut self, _: u64, _: &[u8]) -> Result<(), ()> {
            panic!("cancelled sink must not write")
        }
        async fn finish(&mut self, _: u64) -> Result<(), ()> {
            panic!("cancelled sink must not finish")
        }
    }
    #[test]
    fn revoked_delivery_consumes_interrupted_branch_without_successful_fin() {
        let mut scope = ApplicationKeyScope::new(914);
        let mut installation = scope.claim().unwrap();
        let mut gate = PublicationGate::new(installation.take_publication_gate().unwrap());
        let (_issuer, stop) = gate.split().unwrap();
        let control = Control::new(stop);
        control.revoke().unwrap();
        let limits = Limits {
            max_data: 16,
            max_streams_bidi: 2,
            max_streams_uni: 0,
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            stream_data_uni: 0,
        };
        let mut slots = [StreamSlot::<8>::EMPTY; 2];
        let mut chunks = [SendChunk::<8>::EMPTY; 4];
        let mut refs = [PacketReference::EMPTY; 4];
        let mut numbers = StreamNumbers::new(
            installation.scope(),
            Role::Client,
            limits,
            limits,
            &mut slots,
            &mut chunks,
            &mut refs,
        )
        .unwrap();
        let Facets { app, .. } = numbers.split();
        let app = RefCell::new(app);
        let state = Exchange::<8, EmptyBody>::new();
        let reclaim = crate::quic::application::imp::reclaim::Exchange::new();
        let global = p::receive_choreography();
        let rx_role: RoleProgram<{ p::RECEIVE }> = project(&global);
        let sink_role: RoleProgram<{ p::SINK }> = project(&global);
        let collector_role: RoleProgram<{ p::INPUT_COLLECTOR }> = project(&global);
        let carrier = CarrierStorage::<1, 16, 8>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let id = SessionId::new(914);
        let rv = storage
            .init()
            .rendezvous(&mut slab, carrier.bind(id).unwrap())
            .unwrap();
        let mut rx = rv.enter(id, &rx_role).unwrap();
        let mut sink_endpoint = rv.enter(id, &sink_role).unwrap();
        let mut collector = rv.enter(id, &collector_role).unwrap();
        let mut sink = NeverSink;
        let mut all = pin!(crate::runtime::join2(
            async {
                rx.send::<p::ReceivedData>(&0).await?;
                let reply = rx.offer().await?;
                assert_eq!(reply.label(), p::ReceivedInterrupted::LOGICAL_LABEL);
                check(reply.recv::<p::ReceivedInterrupted>().await?, 0)?;
                rx.send::<p::ReceiveRetire>(&()).await?;
                rx.recv::<p::ReceiveRetired>().await?;
                Ok::<(), Error>(())
            },
            crate::runtime::join2(
                client_sink(
                    &mut sink_endpoint,
                    &control,
                    &state,
                    &app,
                    &mut sink,
                    &reclaim,
                    None
                ),
                super::super::reclaim::input(&mut collector, &reclaim, &control),
            ),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..128 {
            if let Poll::Ready(result) = all.as_mut().poll(&mut cx) {
                result.unwrap();
                assert!(!state.is_complete(0));
                return;
            }
        }
        panic!("interrupted delivery did not join");
    }
}
