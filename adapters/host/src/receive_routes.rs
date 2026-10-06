//! Bounded host datagram routing. This owns only received bytes, never QUIC
//! progress, keys, completion permission, or a connection's retirement decision.
//! A single physical reader dispatches to independently owned receivers.
use hibana_quic::path::Address;
use std::{
    cell::RefCell,
    collections::VecDeque,
    future::poll_fn,
    rc::Rc,
    task::{Poll, Waker},
};

struct Entry<const BYTES: usize> {
    address: Address,
    ids: Vec<Vec<u8>>,
    packets: VecDeque<Packet<BYTES>>,
    receiver: Option<Waker>,
}
struct Inner<const BYTES: usize> {
    entries: Vec<Option<Entry<BYTES>>>,
    queue_capacity: usize,
}
pub struct Packet<const BYTES: usize> {
    bytes: [u8; BYTES],
    len: usize,
    ecn: Option<hibana_quic::ecn::Codepoint>,
}
impl<const BYTES: usize> Packet<BYTES> {
    pub fn ecn(&self) -> Option<hibana_quic::ecn::Codepoint> {
        self.ecn
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
pub struct Dispatcher<const BYTES: usize> {
    inner: Rc<RefCell<Inner<BYTES>>>,
}
/// A unique receive capability. It is neither Clone nor independently reusable.
pub struct Receiver<const BYTES: usize> {
    inner: Rc<RefCell<Inner<BYTES>>>,
    slot: usize,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Capacity,
    InvalidIdentity,
    DuplicateIdentity,
    Closed,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Queued,
    Unknown,
    Full,
    Oversized,
}
impl<const BYTES: usize> Dispatcher<BYTES> {
    pub fn new(connections: usize, queued_per_connection: usize) -> Result<Self, Error> {
        if BYTES == 0
            || connections == 0
            || connections > 64
            || queued_per_connection == 0
            || queued_per_connection > 32
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            inner: Rc::new(RefCell::new(Inner {
                entries: (0..connections).map(|_| None).collect(),
                queue_capacity: queued_per_connection,
            })),
        })
    }
    /// Register the original destination CID and the issued local CID together.
    /// Exact path matching prevents foreign packets from crediting a connection.
    pub fn register(&mut self, address: Address, ids: &[&[u8]]) -> Result<Receiver<BYTES>, Error> {
        if ids.is_empty()
            || ids.len() > 2
            || ids.iter().any(|id| id.is_empty() || id.len() > 20)
            || (ids.len() == 2 && ids[0] == ids[1])
        {
            return Err(Error::InvalidIdentity);
        }
        let mut inner = self.inner.borrow_mut();
        if inner.entries.iter().flatten().any(|entry| {
            entry.address == address && entry.ids.iter().any(|old| ids.contains(&old.as_slice()))
        }) {
            return Err(Error::DuplicateIdentity);
        }
        let slot = inner
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let queue_capacity = inner.queue_capacity;
        inner.entries[slot] = Some(Entry {
            address,
            ids: ids.iter().map(|id| id.to_vec()).collect(),
            packets: VecDeque::with_capacity(queue_capacity),
            receiver: None,
        });
        Ok(Receiver {
            inner: self.inner.clone(),
            slot,
        })
    }
    /// The physical reader supplies the parsed destination CID. Authentication
    /// and every QUIC decision remain with the receiving Hibana connection.
    pub fn deliver(
        &mut self,
        address: Address,
        destination: &[u8],
        bytes: &[u8],
        ecn: Option<hibana_quic::ecn::Codepoint>,
    ) -> Delivery {
        if bytes.len() > BYTES {
            return Delivery::Oversized;
        }
        let wake = {
            let mut inner = self.inner.borrow_mut();
            let capacity = inner.queue_capacity;
            let Some(entry) = inner.entries.iter_mut().flatten().find(|entry| {
                entry.address == address && entry.ids.iter().any(|id| id == destination)
            }) else {
                return Delivery::Unknown;
            };
            if entry.packets.len() == capacity {
                return Delivery::Full;
            }
            let mut packet = Packet {
                bytes: [0; BYTES],
                len: bytes.len(),
                ecn,
            };
            packet.bytes[..bytes.len()].copy_from_slice(bytes);
            entry.packets.push_back(packet);
            entry.receiver.take()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
        Delivery::Queued
    }
}
impl<const BYTES: usize> Drop for Dispatcher<BYTES> {
    fn drop(&mut self) {
        let released: Vec<_> = self
            .inner
            .borrow_mut()
            .entries
            .iter_mut()
            .filter_map(Option::take)
            .collect();
        for mut entry in released {
            if let Some(waker) = entry.receiver.take() {
                waker.wake();
            }
        }
    }
}
impl<const BYTES: usize> Receiver<BYTES> {
    pub async fn receive(&mut self) -> Result<Packet<BYTES>, Error> {
        poll_fn(|cx| {
            // Clone/drop callbacks execute outside the interior borrow.
            let replacement = cx.waker().clone();
            let previous = {
                let mut inner = self.inner.borrow_mut();
                let Some(entry) = inner.entries[self.slot].as_mut() else {
                    return Poll::Ready(Err(Error::Closed));
                };
                if let Some(packet) = entry.packets.pop_front() {
                    return Poll::Ready(Ok(packet));
                }
                entry.receiver.replace(replacement)
            };
            drop(previous);
            Poll::Pending
        })
        .await
    }
}
impl<const BYTES: usize> Drop for Receiver<BYTES> {
    fn drop(&mut self) {
        let released = self.inner.borrow_mut().entries[self.slot].take();
        drop(released);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, pin::pin, task::Context};
    fn address(port: u16) -> Address {
        Address {
            local: "127.0.0.1:443".parse().unwrap(),
            remote: format!("127.0.0.1:{port}").parse().unwrap(),
        }
    }
    #[test]
    fn waiting_old_receiver_does_not_block_new_connection() {
        let mut routes = Dispatcher::<32>::new(2, 2).unwrap();
        let mut old = routes
            .register(address(1), &[b"old-original", b"old-local"])
            .unwrap();
        let mut new = routes
            .register(address(1), &[b"new-original", b"new-local"])
            .unwrap();
        let mut old_read = pin!(old.receive());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(old_read.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            routes.deliver(
                address(1),
                b"new-local",
                b"new packet",
                Some(hibana_quic::ecn::Codepoint::Ect1)
            ),
            Delivery::Queued
        );
        let mut new_read = pin!(new.receive());
        let Poll::Ready(Ok(packet)) = new_read.as_mut().poll(&mut cx) else {
            panic!("new owner did not receive");
        };
        assert_eq!(packet.bytes(), b"new packet");
        assert_eq!(packet.ecn(), Some(hibana_quic::ecn::Codepoint::Ect1));
        assert!(old_read.as_mut().poll(&mut cx).is_pending());
    }
    #[test]
    fn physical_reader_closure_wakes_and_closes_receivers() {
        let mut routes = Dispatcher::<8>::new(1, 1).unwrap();
        let mut receiver = routes.register(address(1), &[b"cid"]).unwrap();
        let mut read = pin!(receiver.receive());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(read.as_mut().poll(&mut cx).is_pending());
        drop(routes);
        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Err(Error::Closed))
        ));
    }
    #[test]
    fn queue_identity_and_lifetime_are_bounded() {
        let mut routes = Dispatcher::<8>::new(1, 1).unwrap();
        let receiver = routes.register(address(1), &[b"cid"]).unwrap();
        assert!(matches!(
            routes.register(address(1), &[b"cid"]),
            Err(Error::DuplicateIdentity)
        ));
        assert!(matches!(
            routes.register(address(2), &[b"other"]),
            Err(Error::Capacity)
        ));
        assert_eq!(
            routes.deliver(address(2), b"cid", b"x", None),
            Delivery::Unknown
        );
        assert_eq!(
            routes.deliver(address(1), b"cid", b"123456789", None),
            Delivery::Oversized
        );
        assert_eq!(
            routes.deliver(address(1), b"cid", b"x", None),
            Delivery::Queued
        );
        assert_eq!(
            routes.deliver(address(1), b"cid", b"y", None),
            Delivery::Full
        );
        drop(receiver);
        assert_eq!(
            routes.deliver(address(1), b"cid", b"z", None),
            Delivery::Unknown
        );
        let _new = routes.register(address(2), &[b"new"]).unwrap();
        assert_eq!(
            routes.deliver(address(1), b"cid", b"old", None),
            Delivery::Unknown
        );
    }
}
