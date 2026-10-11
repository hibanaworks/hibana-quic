use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
struct Input {
    next: usize,
    total: usize,
    pending: bool,
}
impl ClientRequests for Input {
    async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
        if self.pending {
            return Err(());
        }
        if self.next == self.total {
            return Ok(None);
        }
        output[..8].copy_from_slice(b"GET /x\r\n");
        self.pending = true;
        Ok(Some(8))
    }
    fn started(&mut self, id: u64) -> Result<(), ()> {
        if !self.pending || id != self.next as u64 * 4 {
            return Err(());
        }
        self.pending = false;
        self.next += 1;
        Ok(())
    }
}
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture unexpectedly pending"),
    }
}
fn limits() -> RememberedLimits {
    // Two bidi requests, total 16 bytes, 8 bytes per client-created stream.
    RememberedLimits::from_authenticated_server_parameters(&[
        0, 0, 15, 0, 4, 1, 16, 6, 1, 8, 8, 1, 2,
    ])
    .unwrap()
}
#[test]
fn bounded_intent_keeps_unsent_suffix_and_pairs_callbacks_once() {
    let scope = ApplicationKeyScope::new(999);
    let mut slots = [const { RequestSlot::EMPTY }; 3];
    let mut requests = Requests::new(&scope, &mut slots, limits(), 3, MAX_REQUEST_BYTES).unwrap();
    let mut input = Input {
        next: 0,
        total: 3,
        pending: false,
    };
    ready(crate::quic::localside::early_client::prepare(
        &mut requests,
        &mut input,
    ))
    .unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(input.next, 3);
    let mut plain = [0; 64];
    let len = requests.encode(0, &mut plain).unwrap().unwrap();
    requests.accepted(0, 3, &plain[..len]).unwrap();
    assert!(matches!(
        requests.accepted(0, 3, &plain[..len]),
        Err(Error::Binding)
    ));
    assert!(requests.encode(1, &mut plain).unwrap().is_some());
    assert_eq!(requests.encode(2, &mut plain).unwrap(), None);
    assert_eq!(requests.bytes(2).unwrap(), b"GET /x\r\n");
    assert!(matches!(
        ready(crate::quic::localside::early_client::prepare(
            &mut requests,
            &mut input
        )),
        Err(Error::Binding)
    ));
    let mut replay = requests.replay(0);
    let mut bytes = [0; MAX_REQUEST_BYTES];
    for index in 0..3 {
        assert_eq!(ready(replay.next(&mut bytes)).unwrap(), Some(8));
        replay.started(index * 4).unwrap();
    }
    assert_eq!(ready(replay.next(&mut bytes)).unwrap(), None);
    assert_eq!(
        input.next, 3,
        "replay must not call the original started again"
    );
}
#[test]
fn early_publication_is_bounded_by_actual_future_stream_storage() {
    let scope = ApplicationKeyScope::new(1000);
    for (slots_budget, chunk, expected) in [(1, 1024, true), (0, 1024, false), (2, 4, false)] {
        let mut slots = [const { RequestSlot::EMPTY }; 2];
        let mut requests =
            Requests::new(&scope, &mut slots, limits(), slots_budget, chunk).unwrap();
        let mut input = Input {
            next: 0,
            total: 2,
            pending: false,
        };
        ready(crate::quic::localside::early_client::prepare(
            &mut requests,
            &mut input,
        ))
        .unwrap();
        assert_eq!(
            requests.encode(0, &mut [0; 64]).unwrap().is_some(),
            expected
        );
        assert!(requests.encode(1, &mut [0; 64]).unwrap().is_none());
        assert_eq!(requests.bytes(1).unwrap(), b"GET /x\r\n");
    }
}

#[test]
fn request_validation_rejects_mutation_and_line_injection() {
    assert!(replay_safe_get(b"GET /safe\r\n"));
    for bytes in [
        b"POST /x\r\n".as_slice(),
        b"GET /x\r\nGET /y\r\n",
        b"GET /x y\r\n",
        b"GET /x",
    ] {
        assert!(!replay_safe_get(bytes));
    }
}
