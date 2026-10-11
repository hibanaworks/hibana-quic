use super::*;

fn local(role: Role) -> Limits {
    Limits {
        max_data: 8,
        max_streams_bidi: u64::from(role == Role::Server),
        stream_data_bidi_local: 8,
        stream_data_bidi_remote: 8,
        ..Limits::ZERO
    }
}
fn packet(pn: u64) -> Option<PacketNumber> {
    Some(PacketNumber {
        space: PacketNumberSpace::ApplicationData,
        value: pn,
    })
}

#[test]
fn production_is_one_shot_even_after_drop_and_same_stream_registration() {
    // These expressions become ambiguous if somebody adds Copy or Clone
    // to the lease. They check affinity at compile time, without a fixture
    // that could merely fail because the type is private.
    trait NotCopy<A> {
        fn witness() {}
    }
    impl<T: ?Sized> NotCopy<()> for T {}
    impl<T: Copy> NotCopy<u8> for T {}
    let _ = <Production<'static> as NotCopy<_>>::witness;
    let _ = <Delivered<'static> as NotCopy<_>>::witness;
    let _ = <ProductionReleased<'static> as NotCopy<_>>::witness;
    let _ = <InputReleased<'static> as NotCopy<_>>::witness;
    let _ = <DeliveryReleased<'static> as NotCopy<_>>::witness;
    let _ = <crate::quic::application::imp::reclaim::Joined<'static> as NotCopy<_>>::witness;
    let _ = <crate::quic::imp::recovery::ApplicationLoss<'static> as NotCopy<_>>::witness;
    trait NotClone<A> {
        fn witness() {}
    }
    impl<T: ?Sized> NotClone<()> for T {}
    impl<T: Clone> NotClone<u8> for T {}
    let _ = <Production<'static> as NotClone<_>>::witness;
    let _ = <Delivered<'static> as NotClone<_>>::witness;
    let _ = <ProductionReleased<'static> as NotClone<_>>::witness;
    let _ = <InputReleased<'static> as NotClone<_>>::witness;
    let _ = <DeliveryReleased<'static> as NotClone<_>>::witness;
    let _ = <crate::quic::application::imp::reclaim::Joined<'static> as NotClone<_>>::witness;
    let _ = <crate::quic::imp::recovery::ApplicationLoss<'static> as NotClone<_>>::witness;
    let scope = ApplicationKeyScope::new(707);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let mut app = core.split().app;
    let stream = app.open_local().unwrap();
    let allocation = actor_test_allocator::NoAlloc::start();
    let production = app.take_production(stream).unwrap();
    assert!(matches!(app.take_production(stream), Err(Error::Binding)));
    // Deliberately consume the affine token; it must not become reissuable.
    #[allow(clippy::drop_non_drop)]
    drop(production);
    app.core.numbers.borrow_mut().register(stream).unwrap();
    assert!(matches!(app.take_production(stream), Err(Error::Binding)));
    allocation.finish();
}

#[test]
fn production_cannot_cross_tables_with_identical_numeric_stream_ids() {
    let scope = ApplicationKeyScope::new(708);
    let mut slots_a = [StreamSlot::<8>::EMPTY];
    let mut chunks_a = [SendChunk::<8>::EMPTY];
    let mut refs_a = [PacketReference::EMPTY; 4];
    let mut slots_b = [StreamSlot::<8>::EMPTY];
    let mut chunks_b = [SendChunk::<8>::EMPTY];
    let mut refs_b = [PacketReference::EMPTY; 4];
    let mut a = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut slots_a,
        &mut chunks_a,
        &mut refs_a,
    )
    .unwrap();
    let mut b = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut slots_b,
        &mut chunks_b,
        &mut refs_b,
    )
    .unwrap();
    let mut a = a.split().app;
    let mut b = b.split().app;
    let sa = a.open_local().unwrap();
    let sb = b.open_local().unwrap();
    assert_eq!(
        sa, sb,
        "numeric identities alone must not authorize a different table"
    );
    let allocation = actor_test_allocator::NoAlloc::start();
    let mut production = a.take_production(sa).unwrap();
    assert!(matches!(
        b.enqueue_prefix(&mut production, b"data", false),
        Err(Error::Binding)
    ));
    assert_eq!(
        a.enqueue_prefix(&mut production, b"data", false).unwrap(),
        4
    );
    assert_eq!(a.queued_chunks().unwrap(), 1);
    assert_eq!(b.queued_chunks().unwrap(), 0);
    allocation.finish();
}

#[test]
fn three_streams_have_independent_windows_payloads_and_completion() {
    let scope = ApplicationKeyScope::new(13);
    let mut slots = [const { StreamSlot::<8>::EMPTY }; 3];
    let mut chunks = [const { SendChunk::<8>::EMPTY }; 3];
    let mut references = [PacketReference::EMPTY; 8];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Server,
        Limits {
            max_data: 24,
            ..local(Role::Client)
        },
        Limits {
            max_data: 24,
            max_streams_bidi: 3,
            ..local(Role::Server)
        },
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        mut rx,
        mut tx,
        mut publication,
        mut reset,
    } = core.split();
    // The highest incoming ID materializes the two implicit lower streams.
    for id in [8, 0, 4] {
        rx.apply(&Frame::Stream {
            id,
            offset: 0,
            fin: false,
            data: b"12345678",
        })
        .unwrap();
    }
    let handles = app.ready_streams().unwrap();
    let mut output = [0; 8];
    for stream in handles.into_iter().flatten() {
        assert_eq!(app.read(stream, &mut output).unwrap().len, 8);
        assert_eq!(&output, b"12345678");
    }
    let mut seen = [false; 3];
    for pn in 0..3 {
        let prepared = tx.prepare::<64>(false).unwrap().unwrap();
        let frames = packet::FrameIter::new(
            prepared.bytes(),
            packet::EncryptionLevel::OneRtt,
            packet::ParseLimits::default(),
        )
        .unwrap();
        for frame in frames {
            if let Frame::MaxStreamData { id, maximum } = frame.unwrap() {
                assert_eq!(maximum, 16);
                assert!(!seen[(id / 4) as usize]);
                seen[(id / 4) as usize] = true;
            }
        }
        let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
        publication.commit(reservation).unwrap();
    }
    assert_eq!(seen, [true; 3]);
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(0), packet(1), packet(2)])
        .unwrap();
    assert!(tx.prepare::<64>(true).unwrap().is_none());
    for stream in handles.into_iter().flatten() {
        let data = [stream.id() as u8; 8];
        rx.apply(&Frame::Stream {
            id: stream.id(),
            offset: 8,
            fin: true,
            data: &data,
        })
        .unwrap();
        assert!(app.read(stream, &mut output).unwrap().fin);
        assert_eq!(output, data);
        let mut production = app.take_production(stream).unwrap();
        assert_eq!(
            app.enqueue_prefix(&mut production, &data, true).unwrap(),
            data.len()
        );
    }
    for pn in 3..6 {
        let prepared = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
        publication.commit(reservation).unwrap();
    }
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(3), packet(4), packet(5)])
        .unwrap();
    for stream in handles.into_iter().flatten() {
        assert!(!app.send_complete(stream).unwrap());
    }
    while let Some(receipt) = reset.take_delivery().unwrap() {
        tx.record_delivery(receipt).unwrap();
    }
    for stream in handles.into_iter().flatten() {
        assert!(app.send_complete(stream).unwrap());
        assert!(app.receive_complete(stream).unwrap());
    }
}

#[test]
fn publication_cancel_loss_late_ack_and_send_completion() {
    let scope = ApplicationKeyScope::new(9);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        rx,
        mut tx,
        mut publication,
        mut reset,
    } = core.split();
    let stream = app.open_local().unwrap();
    let mut production = app.take_production(stream).unwrap();
    assert_eq!(
        app.enqueue_prefix(&mut production, b"GET /\r\n", true)
            .unwrap(),
        (b"GET /\r\n").len()
    );
    let bytes = tx.prepare::<64>(false).unwrap().unwrap();
    let reservation = tx.reserve_transmission(&bytes, 0).unwrap();
    publication.cancel(reservation).unwrap();
    assert!(!app.send_complete(stream).unwrap());
    let bytes = tx.prepare::<64>(false).unwrap().unwrap();
    let reservation = tx.reserve_transmission(&bytes, 1).unwrap();
    publication.commit(reservation).unwrap();
    assert!(tx.prepare::<64>(false).unwrap().is_none());
    tx.core.numbers.borrow_mut().lost(1).unwrap();
    let retransmission = tx.prepare::<64>(false).unwrap().unwrap();
    assert_eq!(bytes.bytes(), retransmission.bytes());
    let reservation = tx.reserve_transmission(&retransmission, 2).unwrap();
    publication.commit(reservation).unwrap();
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(1)])
        .unwrap();
    while let Some(receipt) = reset.take_delivery().unwrap() {
        tx.record_delivery(receipt).unwrap();
    }
    assert!(app.send_complete(stream).unwrap());
    assert_eq!(app.queued_chunks().unwrap(), 0);
    assert!(tx.prepare::<64>(true).unwrap().is_none());
}

#[test]
fn borrowed_receive_uses_ring_storage_and_rejects_invalid_consumption() {
    let scope = ApplicationKeyScope::new(10);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Server,
        local(Role::Client),
        local(Role::Server),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app, mut rx, ..
    } = core.split();
    rx.apply(&Frame::Stream {
        id: 0,
        offset: 0,
        fin: false,
        data: b"abcdefgh",
    })
    .unwrap();
    let stream = app.readable_stream().unwrap().unwrap();
    let pointer = app
        .core
        .numbers
        .borrow()
        .table
        .receive(stream)
        .unwrap()
        .first
        .as_ptr();
    assert_eq!(
        app.consume(stream, |view| {
            assert_eq!(view.first.as_ptr(), pointer);
            assert_eq!(view.first, b"abcdefgh");
            Err(Error::Capacity)
        }),
        Err(Error::Capacity)
    );
    assert_eq!(app.consume(stream, |_| Ok(9)), Err(Error::Capacity));
    assert_eq!(
        app.consume(stream, |view| {
            assert_eq!(view.first, b"abcdefgh");
            Ok(6)
        })
        .unwrap()
        .len,
        6
    );
    rx.apply(&Frame::Stream {
        id: 0,
        offset: 8,
        fin: true,
        data: b"ijklmn",
    })
    .unwrap();
    let read = app
        .consume(stream, |view| {
            assert_eq!(view.first, b"gh");
            assert_eq!(view.second, b"ijklmn");
            assert!(view.fin);
            Ok(2)
        })
        .unwrap();
    assert!(!read.fin);
    let read = app
        .consume(stream, |view| {
            assert_eq!(view.first, b"ijklmn");
            assert!(view.second.is_empty());
            Ok(6)
        })
        .unwrap();
    assert!(read.fin);
}

#[test]
fn consume_replenishes_credit_and_control_retransmits_until_ack() {
    let scope = ApplicationKeyScope::new(10);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Server,
        local(Role::Client),
        local(Role::Server),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        mut rx,
        mut tx,
        mut publication,
        reset: _,
    } = core.split();
    rx.apply(&Frame::Stream {
        id: 0,
        offset: 0,
        fin: false,
        data: b"abcdefgh",
    })
    .unwrap();
    let stream = app.readable_stream().unwrap().unwrap();
    let mut sink = [0; 8];
    assert_eq!(
        app.read(stream, &mut sink).unwrap(),
        Read {
            len: 8,
            fin: false,
            reset: None
        }
    );
    assert_eq!(&sink, b"abcdefgh");
    let update = tx.prepare::<64>(false).unwrap().unwrap();
    let expected = [
        Frame::MaxData { maximum: 16 },
        Frame::MaxStreamData { id: 0, maximum: 16 },
    ];
    let mut encoded = [0; 64];
    let mut len = 0;
    for frame in expected {
        len += packet::encode_frame(&frame, &mut encoded[len..]).unwrap();
    }
    assert_eq!(update.bytes(), &encoded[..len]);
    let reservation = tx.reserve_transmission(&update, 0).unwrap();
    publication.commit(reservation).unwrap();
    assert!(tx.prepare::<64>(false).unwrap().is_none());
    tx.core.numbers.borrow_mut().lost(0).unwrap();
    let resend = tx.prepare::<64>(false).unwrap().unwrap();
    assert_eq!(update.bytes(), resend.bytes());
    let reservation = tx.reserve_transmission(&resend, 1).unwrap();
    publication.commit(reservation).unwrap();
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(0)])
        .unwrap();
    assert!(tx.prepare::<64>(true).unwrap().is_none());
    rx.apply(&Frame::Stream {
        id: 0,
        offset: 8,
        fin: true,
        data: b"ijklmnop",
    })
    .unwrap();
    assert!(!app.receive_complete(stream).unwrap());
    assert!(app.read(stream, &mut sink).unwrap().fin);
    assert_eq!(&sink, b"ijklmnop");
    assert!(app.receive_complete(stream).unwrap());
}

#[test]
fn stop_while_adapter_pending_settles_then_reliably_resets() {
    let scope = ApplicationKeyScope::new(11);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        mut rx,
        mut tx,
        mut publication,
        mut reset,
    } = core.split();
    let stream = app.open_local().unwrap();
    let mut production = app.take_production(stream).unwrap();
    assert_eq!(
        app.enqueue_prefix(&mut production, b"hello", false)
            .unwrap(),
        (b"hello").len()
    );
    let prepared = tx.prepare::<64>(false).unwrap().unwrap();
    let reservation = tx.reserve_transmission(&prepared, 0).unwrap();
    let intent = rx.stop_intent(0, 7).unwrap();
    assert!(tx.prepare::<64>(false).unwrap().is_none());
    publication.commit(reservation).unwrap();
    assert!(
        tx.prepare::<64>(false).unwrap().is_none(),
        "adapter completion must not secretly apply the stop observation"
    );
    reset.apply(intent).unwrap();
    let reset_frame = tx.prepare::<64>(false).unwrap().unwrap();
    let mut encoded = [0; 64];
    let len = packet::encode_frame(
        &Frame::ResetStream {
            id: 0,
            error_code: 7,
            final_size: 5,
        },
        &mut encoded,
    )
    .unwrap();
    assert_eq!(reset_frame.bytes(), &encoded[..len]);
    let reservation = tx.reserve_transmission(&reset_frame, 1).unwrap();
    publication.commit(reservation).unwrap();
    assert!(!app.send_complete(stream).unwrap());
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(1)])
        .unwrap();
    while let Some(receipt) = reset.take_delivery().unwrap() {
        tx.record_delivery(receipt).unwrap();
    }
    assert!(app.send_complete(stream).unwrap());
}

#[test]
fn stream_limits_and_non_application_ack_are_rejected() {
    let scope = ApplicationKeyScope::new(12);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Server,
        local(Role::Client),
        local(Role::Server),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets { mut rx, .. } = core.split();
    assert_eq!(
        rx.apply(&Frame::Stream {
            id: 4,
            offset: 0,
            fin: true,
            data: b"x"
        }),
        Err(Error::Streams(streams::Error::StreamLimit))
    );
    assert_eq!(
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[Some(PacketNumber {
                space: PacketNumberSpace::Handshake,
                value: 0
            })]),
        Err(Error::Binding)
    );
}
#[test]
fn fin_delivery_waits_for_all_bytes_then_moves_once_to_the_observer() {
    let scope = ApplicationKeyScope::new(990);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY; 2];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        mut rx,
        mut tx,
        mut publication,
        reset: mut effects,
    } = core.split();
    let stream = app.open_local().unwrap();
    let mut source = app.take_production(stream).unwrap();
    let allocation = actor_test_allocator::NoAlloc::start();
    app.enqueue_prefix(&mut source, b"abc", false).unwrap();
    app.enqueue_prefix(&mut source, b"", true).unwrap();
    for pn in 0..2 {
        let prepared = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
        publication.commit(reservation).unwrap();
    }
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(1)])
        .unwrap();
    assert!(effects.take_delivery().unwrap().is_none());
    assert!(!app.send_complete(stream).unwrap());
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(0)])
        .unwrap();
    let receipt = effects.take_delivery().unwrap().unwrap();
    assert!(effects.take_delivery().unwrap().is_none());
    assert!(
        !app.send_complete(stream).unwrap(),
        "taking evidence does not mean the projected consumer received it"
    );
    tx.record_delivery(receipt).unwrap();
    assert!(app.send_complete(stream).unwrap());
    effects
        .apply(rx.stop_intent(stream.id(), 9).unwrap())
        .unwrap();
    assert!(
        tx.prepare::<64>(false).unwrap().is_none(),
        "late STOP cannot reopen a completed production"
    );
    assert!(effects.take_delivery().unwrap().is_none());
    allocation.finish();
}
#[test]
fn delivered_receipt_cannot_cross_actual_tables() {
    let scope = ApplicationKeyScope::new(991);
    let mut sa = [StreamSlot::<8>::EMPTY];
    let mut ca = [SendChunk::<8>::EMPTY];
    let mut ra = [PacketReference::EMPTY; 2];
    let mut sb = [StreamSlot::<8>::EMPTY];
    let mut cb = [SendChunk::<8>::EMPTY];
    let mut rb = [PacketReference::EMPTY; 2];
    let mut a = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut sa,
        &mut ca,
        &mut ra,
    )
    .unwrap();
    let mut b = StreamNumbers::new(
        &scope,
        Role::Client,
        local(Role::Server),
        local(Role::Client),
        &mut sb,
        &mut cb,
        &mut rb,
    )
    .unwrap();
    let Facets {
        mut app,
        rx,
        mut tx,
        mut publication,
        reset: mut effects,
    } = a.split();
    let Facets {
        app: mut other_app,
        tx: mut other_tx,
        ..
    } = b.split();
    let stream = app.open_local().unwrap();
    assert_eq!(stream, other_app.open_local().unwrap());
    let mut source = app.take_production(stream).unwrap();
    let allocation = actor_test_allocator::NoAlloc::start();
    app.enqueue_prefix(&mut source, b"", true).unwrap();
    let prepared = tx.prepare::<64>(false).unwrap().unwrap();
    let reservation = tx.reserve_transmission(&prepared, 0).unwrap();
    publication.commit(reservation).unwrap();
    rx.core
        .numbers
        .borrow_mut()
        .acknowledge(&[packet(0)])
        .unwrap();
    let receipt = effects.take_delivery().unwrap().unwrap();
    assert!(matches!(
        other_tx.record_delivery(receipt),
        Err(Error::Binding)
    ));
    assert!(!app.send_complete(stream).unwrap());
    assert!(!other_app.send_complete(stream).unwrap());
    assert!(effects.take_delivery().unwrap().is_none());
    allocation.finish();
}
#[test]
fn peer_stream_credit_follows_real_reclaim_and_retries_until_ack() {
    use crate::quic::application::imp::reclaim::Joined;
    let scope = ApplicationKeyScope::new(1108);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY; 2];
    let mut references = [PacketReference::EMPTY; 8];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Server,
        Limits {
            max_data: 1024,
            ..local(Role::Client)
        },
        local(Role::Server),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        mut rx,
        mut tx,
        mut publication,
        reset: mut effects,
    } = core.split();
    for index in 0..70u64 {
        let id = index * 4;
        rx.apply(&Frame::Stream {
            id,
            offset: 0,
            fin: true,
            data: b"x",
        })
        .unwrap();
        let stream = app
            .ready_streams()
            .unwrap()
            .into_iter()
            .flatten()
            .next()
            .unwrap();
        let mut bytes = [0; 8];
        assert!(app.read(stream, &mut bytes).unwrap().fin);
        let input = app.release_input(id).unwrap().unwrap();
        let mut production = app.take_production(stream).unwrap();
        app.enqueue_prefix(&mut production, b"y", true).unwrap();
        let source = app.release_production(production).unwrap();
        let prepared = tx.prepare::<128>(false).unwrap().unwrap();
        assert!(prepared.controls.max_streams_bidi.is_none());
        let reservation = tx.reserve_transmission(&prepared, index * 3).unwrap();
        publication.commit(reservation).unwrap();
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(index * 3)])
            .unwrap();
        let delivered = effects.take_delivery().unwrap().unwrap();
        let delivery = tx.record_delivery(delivered).unwrap();
        assert!(tx.reclaimable(source.origin()).unwrap());
        assert_eq!(rx.core.numbers.borrow().bidi_credit.current, index + 1);
        effects
            .reclaim(Joined::new(source, input, delivery).unwrap())
            .unwrap();
        let update = tx.prepare::<128>(false).unwrap().unwrap();
        assert_eq!(update.controls.max_streams_bidi, Some(index + 2));
        let reservation = tx.reserve_transmission(&update, index * 3 + 1).unwrap();
        publication.cancel(reservation).unwrap();
        assert_eq!(
            tx.prepare::<128>(false)
                .unwrap()
                .unwrap()
                .controls
                .max_streams_bidi,
            Some(index + 2)
        );
        let reservation = tx.reserve_transmission(&update, index * 3 + 1).unwrap();
        publication.commit(reservation).unwrap();
        rx.core.numbers.borrow_mut().lost(index * 3 + 1).unwrap();
        let retry = tx.prepare::<128>(false).unwrap().unwrap();
        assert_eq!(retry.controls.max_streams_bidi, Some(index + 2));
        let reservation = tx.reserve_transmission(&retry, index * 3 + 2).unwrap();
        publication.commit(reservation).unwrap();
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(index * 3 + 2)])
            .unwrap();
        assert!(tx.prepare::<128>(false).unwrap().is_none());
    }
}

#[test]
fn owned_release_receipts_reuse_one_slot_and_ignore_only_closed_stream_frames() {
    use crate::quic::application::imp::reclaim::Joined;
    let scope = ApplicationKeyScope::new(1107);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY; 2];
    let mut references = [PacketReference::EMPTY; 8];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Client,
        Limits {
            max_streams_bidi: 4,
            ..local(Role::Server)
        },
        local(Role::Client),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        mut rx,
        mut tx,
        mut publication,
        reset: mut effects,
    } = core.split();
    let allocation = actor_test_allocator::NoAlloc::start();
    for pn in 0..3 {
        let stream = app.open_local().unwrap();
        assert_eq!(stream.id(), pn * 4);
        assert_eq!(stream.slot(), 0);
        let mut production = app.take_production(stream).unwrap();
        assert!(matches!(
            app.release_input(stream.id()),
            Err(Error::Binding)
        ));
        app.enqueue_prefix(&mut production, b"x", true).unwrap();
        let source = app.release_production(production).unwrap();
        rx.apply(&Frame::Stream {
            id: stream.id(),
            offset: 0,
            fin: true,
            data: b"y",
        })
        .unwrap();
        assert!(
            matches!(app.release_input(stream.id()), Err(Error::Binding)),
            "unread input cannot be released"
        );
        let mut bytes = [0; 8];
        let read = app.read(stream, &mut bytes).unwrap();
        assert!(read.fin);
        assert_eq!(read.len, 1);
        let input = app.release_input(stream.id()).unwrap().unwrap();
        assert!(app.release_input(stream.id()).unwrap().is_none());
        assert!(!tx.reclaimable(source.origin()).unwrap());
        let prepared = tx.prepare::<128>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
        publication.commit(reservation).unwrap();
        assert!(effects.take_delivery().unwrap().is_none());
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(pn)])
            .unwrap();
        let delivered = effects.take_delivery().unwrap().unwrap();
        let delivery = tx.record_delivery(delivered).unwrap();
        assert!(tx.reclaimable(source.origin()).unwrap());
        let joined = Joined::new(source, input, delivery).unwrap();
        effects.reclaim(joined).unwrap();
        assert!(matches!(
            app.read(stream, &mut bytes),
            Err(Error::Streams(streams::Error::StaleHandle))
        ));
        assert!(app.release_input(stream.id()).unwrap().is_none());
        rx.apply(&Frame::Stream {
            id: stream.id(),
            offset: 0,
            fin: true,
            data: b"y",
        })
        .unwrap();
        rx.apply(&Frame::ResetStream {
            id: stream.id(),
            error_code: 1,
            final_size: 1,
        })
        .unwrap();
        rx.apply(&Frame::MaxStreamData {
            id: stream.id(),
            maximum: 8,
        })
        .unwrap();
        assert!(matches!(
            rx.stop_intent(stream.id(), 1),
            Err(Error::Streams(streams::Error::Retired))
        ));
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(pn)])
            .unwrap();
    }
    assert!(matches!(
        rx.apply(&Frame::Stream {
            id: 2,
            offset: 0,
            fin: true,
            data: b""
        }),
        Err(Error::Streams(streams::Error::StreamState))
    ));
    assert!(matches!(
        rx.stop_intent(3, 1),
        Err(Error::Streams(streams::Error::StreamState))
    ));
    allocation.finish();
}
#[test]
fn small_reads_batch_credit_at_half_the_backed_window() {
    let scope = ApplicationKeyScope::new(77);
    let mut slots = [StreamSlot::<8>::EMPTY];
    let mut chunks = [SendChunk::<8>::EMPTY];
    let mut references = [PacketReference::EMPTY; 4];
    let mut core = StreamNumbers::new(
        &scope,
        Role::Server,
        local(Role::Client),
        local(Role::Server),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let Facets {
        mut app,
        mut rx,
        tx,
        ..
    } = core.split();
    rx.apply(&Frame::Stream {
        id: 0,
        offset: 0,
        fin: false,
        data: b"abcd",
    })
    .unwrap();
    let stream = app.readable_stream().unwrap().unwrap();
    for byte in b"abc" {
        let mut one = [0; 1];
        assert_eq!(app.read(stream, &mut one).unwrap().len, 1);
        assert_eq!(one[0], *byte);
        assert!(tx.prepare::<64>(false).unwrap().is_none());
    }
    let mut one = [0; 1];
    assert_eq!(app.read(stream, &mut one).unwrap().len, 1);
    assert_eq!(one[0], b'd');
    let update = tx.prepare::<64>(false).unwrap().unwrap();
    let expected = [
        Frame::MaxData { maximum: 12 },
        Frame::MaxStreamData { id: 0, maximum: 12 },
    ];
    let mut bytes = [0; 64];
    let mut len = 0;
    for frame in expected {
        len += packet::encode_frame(&frame, &mut bytes[len..]).unwrap();
    }
    assert_eq!(update.bytes(), &bytes[..len]);
}

#[test]
fn credit_batching_keeps_tiny_windows_and_final_offset_live() {
    assert!(Credit::new(1).should_update(2, 1));
    assert!(!Credit::new(8).should_update(11, 8));
    assert!(Credit::new(8).should_update(12, 8));
    assert!(!Credit::new(8).should_update(8, 8));
    assert!(Credit::new(streams::MAX_OFFSET - 3).should_update(streams::MAX_OFFSET, 1024));
}
#[test]
fn unidirectional_streams_own_only_their_real_half() {
    for role in [Role::Client, Role::Server] {
        let scope = ApplicationKeyScope::new(741);
        let mut slots = [StreamSlot::<8>::EMPTY; 2];
        let mut chunks = [SendChunk::<8>::EMPTY; 2];
        let mut references = [PacketReference::EMPTY; 4];
        let limits = Limits {
            max_data: 16,
            max_streams_uni: 1,
            stream_data_uni: 8,
            ..Limits::ZERO
        };
        let mut core = StreamNumbers::new(
            &scope,
            role,
            limits,
            limits,
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let roles = core.split();
        let mut app = roles.app;
        let mut rx = roles.rx;
        let local = app.open_local_uni().unwrap();
        let mut production = app.take_production(local).unwrap();
        assert!(app.take_production(local).is_err());
        assert!(
            app.core
                .numbers
                .borrow()
                .state(local)
                .unwrap()
                .input_release
                .is_none()
        );
        assert!(app.ready_streams().unwrap().iter().all(Option::is_none));
        assert_eq!(
            app.enqueue_prefix(&mut production, b"control", false)
                .unwrap(),
            7
        );
        let peer_id = if role == Role::Client { 3 } else { 2 };
        rx.apply(&Frame::Stream {
            id: peer_id,
            offset: 0,
            fin: true,
            data: b"settings",
        })
        .unwrap();
        let peer = app.readable_stream().unwrap().unwrap();
        assert_eq!(peer.id(), peer_id);
        assert!(app.take_production(peer).is_err());
        let mut bytes = [0; 8];
        let read = app.read(peer, &mut bytes).unwrap();
        assert!(read.fin);
        assert_eq!(&bytes, b"settings");
        assert!(app.release_input(peer.id()).unwrap().is_some());
        assert!(app.release_input(peer.id()).unwrap().is_none());
        assert!(app.ready_streams().unwrap().iter().all(Option::is_none));
        assert!(app.open_local_uni().is_err());
    }
}
