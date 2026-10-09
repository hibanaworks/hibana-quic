use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    EndpointError,
    runtime::{SessionKitStorage, ids::SessionId},
};
use hibana_quic::{
    quic::retry::client_global as p, runtime::carrier::CarrierStorage, runtime::join2,
};
#[test]
fn retry_rekey_is_outside_the_receive_and_publication_rolls() {
    for (retry, repeat) in [(false, false), (true, false), (true, true)] {
        let refused = core::cell::Cell::new(false);
        let (owner_program, io_program) = p::programs();
        let carrier = CarrierStorage::<1, 16, 8>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(1200);
        let session = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut owner = session.enter(sid, &owner_program).unwrap();
        let mut io = session.enter(sid, &io_program).unwrap();
        let mut task = pin!(join2(
            async {
                owner.send::<p::Packet>(&()).await?;
                owner.offer().await?.recv::<p::Accepted>().await?;
                owner.send::<p::Settled>(&()).await?;
                owner.send::<p::Listen>(&()).await?;
                owner.offer().await?.recv::<p::Observed>().await?;
                owner.send::<p::Taken>(&()).await?;
                owner.send::<p::Quiesce>(&()).await?;
                owner.recv::<p::Quiescent>().await.inspect_err(|&e| {
                    eprintln!("owner Quiescent: {e:?}");
                })?;
                if retry {
                    owner.send::<p::Rekey>(&()).await?;
                    owner.recv::<p::Rekeyed>().await.inspect_err(|&e| {
                        eprintln!("owner Rekeyed: {e:?}");
                    })?;
                    if repeat {
                        let result = owner.send::<p::Rekey>(&()).await;
                        assert!(result.is_err(), "second Retry branch was accepted");
                        refused.set(true);
                        return result;
                    }
                    owner.send::<p::RetriedPacket>(&()).await?;
                    owner.offer().await?.recv::<p::RetriedAccepted>().await?;
                    owner.send::<p::RetriedSettled>(&()).await?;
                    owner.send::<p::RetriedListen>(&()).await?;
                    owner.offer().await?.recv::<p::RetriedObserved>().await?;
                    owner.send::<p::RetriedTaken>(&()).await?;
                }
                if retry {
                    owner.send::<p::RetriedQuiesce>(&()).await?;
                    owner
                        .recv::<p::RetriedQuiescent>()
                        .await
                        .inspect_err(|&e| {
                            eprintln!("owner Quiescent: {e:?}");
                        })?;
                }
                if !retry {
                    owner.send::<p::Bypass>(&()).await?;
                    owner.recv::<p::Bypassed>().await?;
                }
                owner.send::<p::Proceed>(&()).await?;
                owner.recv::<p::Joined>().await?;
                Ok::<(), EndpointError>(())
            },
            async {
                io.recv::<p::Packet>().await?;
                io.send::<p::Accepted>(&()).await?;
                io.recv::<p::Settled>().await?;
                loop {
                    let branch = io.offer().await?;
                    match branch.label() {
                        0 => {
                            branch.recv::<p::Packet>().await?;
                            io.send::<p::Accepted>(&()).await?;
                            io.recv::<p::Settled>().await?;
                        }
                        4 => {
                            branch.recv::<p::Listen>().await?;
                            io.send::<p::Observed>(&()).await?;
                            io.recv::<p::Taken>().await.inspect_err(|&e| {
                                eprintln!("io Taken: {e:?}");
                            })?;
                        }
                        14 => {
                            branch.recv::<p::Quiesce>().await?;
                            io.send::<p::Quiescent>(&()).await?;
                            break;
                        }
                        label => panic!("unexpected work label {label}"),
                    }
                }
                let branch = io.offer().await?;
                match branch.label() {
                    8 => {
                        branch.recv::<p::Rekey>().await?;
                        io.send::<p::Rekeyed>(&()).await?;
                        loop {
                            let branch = io.offer().await?;
                            match branch.label() {
                                20 => {
                                    branch.recv::<p::RetriedPacket>().await?;
                                    io.send::<p::RetriedAccepted>(&()).await?;
                                    io.recv::<p::RetriedSettled>().await?;
                                }
                                24 => {
                                    branch.recv::<p::RetriedListen>().await?;
                                    io.send::<p::RetriedObserved>(&()).await?;
                                    io.recv::<p::RetriedTaken>().await.inspect_err(|&e| {
                                        eprintln!("io Taken: {e:?}");
                                    })?;
                                }
                                28 => {
                                    branch.recv::<p::RetriedQuiesce>().await?;
                                    io.send::<p::RetriedQuiescent>(&()).await?;
                                    break;
                                }
                                label => panic!("unexpected work label {label}"),
                            }
                        }
                        io.recv::<p::Proceed>().await?;
                    }
                    12 => {
                        branch.recv::<p::Bypass>().await?;
                        io.send::<p::Bypassed>(&()).await?;
                        io.recv::<p::Proceed>().await?;
                    }
                    label => panic!("unexpected one-shot choice {label}"),
                }
                io.send::<p::Joined>(&()).await?;
                Ok(())
            }
        ));
        let mut completed = false;
        for _ in 0..2000 {
            if let Poll::Ready(result) = task.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            {
                if repeat {
                    assert!(refused.get());
                    assert!(result.is_err());
                } else {
                    result.unwrap();
                }
                completed = true;
                break;
            }
        }
        assert!(completed);
    }
}
