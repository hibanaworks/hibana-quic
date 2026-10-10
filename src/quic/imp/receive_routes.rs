//! Caller-owned, bounded datagram queues for independently owned receivers.
//! The physical reader copies only the initialized datagram prefix into a queue;
//! receiving copies that prefix into the connection's supplied buffer. No heap
//! storage, reference counting, protocol progress, or key ownership is involved.
use crate::io::{Address, Codepoint};
use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Poll, Waker},
};

struct Identity {
    address: Address,
    ids: [[u8; 20]; 2],
    lengths: [u8; 2],
}
impl Identity {
    fn contains(&self, id: &[u8]) -> bool {
        self.lengths
            .iter()
            .enumerate()
            .any(|(i, &len)| len != 0 && &self.ids[i][..len as usize] == id)
    }
}
struct Buffered<const BYTES: usize> {
    bytes: [u8; BYTES],
    len: usize,
    ecn: Option<Codepoint>,
}
impl<const BYTES: usize> Buffered<BYTES> {
    const EMPTY: Self = Self {
        bytes: [0; BYTES],
        len: 0,
        ecn: None,
    };
}
struct Queue<const BYTES: usize, const QUEUED: usize> {
    identity: Option<Identity>,
    packets: [Buffered<BYTES>; QUEUED],
    head: usize,
    len: usize,
    receiver: Option<Waker>,
}
/// One caller-owned connection queue. Capacity is fixed before any I/O.
pub struct Slot<const BYTES: usize, const QUEUED: usize = 8> {
    queue: RefCell<Queue<BYTES, QUEUED>>,
}
impl<const BYTES: usize, const QUEUED: usize> Default for Slot<BYTES, QUEUED> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const BYTES: usize, const QUEUED: usize> Slot<BYTES, QUEUED> {
    pub const fn new() -> Self {
        Self {
            queue: RefCell::new(Queue {
                identity: None,
                packets: [const { Buffered::EMPTY }; QUEUED],
                head: 0,
                len: 0,
                receiver: None,
            }),
        }
    }
}
/// Unique physical-reader capability, borrowing the caller's slot array.
pub struct Dispatcher<'a, const BYTES: usize, const QUEUED: usize = 8> {
    slots: &'a [Slot<BYTES, QUEUED>],
}
/// Unique receive capability; cannot outlive or duplicate its caller-owned slot.
pub struct Receiver<'a, const BYTES: usize, const QUEUED: usize = 8> {
    slot: &'a Slot<BYTES, QUEUED>,
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
impl<'a, const BYTES: usize, const QUEUED: usize> Dispatcher<'a, BYTES, QUEUED> {
    pub fn new(slots: &'a mut [Slot<BYTES, QUEUED>]) -> Result<Self, Error> {
        if BYTES == 0 || slots.is_empty() || slots.len() > 64 || QUEUED == 0 || QUEUED > 32 {
            return Err(Error::Capacity);
        }
        Ok(Self { slots })
    }
    pub fn register(
        &mut self,
        address: Address,
        ids: &[&[u8]],
    ) -> Result<Receiver<'a, BYTES, QUEUED>, Error> {
        if ids.is_empty()
            || ids.len() > 2
            || ids.iter().any(|id| id.is_empty() || id.len() > 20)
            || (ids.len() == 2 && ids[0] == ids[1])
        {
            return Err(Error::InvalidIdentity);
        }
        for slot in self.slots {
            if slot
                .queue
                .borrow()
                .identity
                .as_ref()
                .is_some_and(|old| old.address == address && ids.iter().any(|id| old.contains(id)))
            {
                return Err(Error::DuplicateIdentity);
            }
        }
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.queue.borrow().identity.is_none())
            .ok_or(Error::Capacity)?;
        let mut identity = Identity {
            address,
            ids: [[0; 20]; 2],
            lengths: [0; 2],
        };
        for (i, id) in ids.iter().enumerate() {
            identity.ids[i][..id.len()].copy_from_slice(id);
            identity.lengths[i] = id.len() as u8;
        }
        let previous = {
            let mut queue = slot.queue.borrow_mut();
            queue.identity = Some(identity);
            queue.head = 0;
            queue.len = 0;
            queue.receiver.take()
        };
        drop(previous);
        Ok(Receiver { slot })
    }
    pub fn deliver(
        &mut self,
        address: Address,
        destination: &[u8],
        bytes: &[u8],
        ecn: Option<Codepoint>,
    ) -> Delivery {
        if bytes.len() > BYTES {
            return Delivery::Oversized;
        }
        for slot in self.slots {
            let wake = {
                let mut queue = slot.queue.borrow_mut();
                if !queue
                    .identity
                    .as_ref()
                    .is_some_and(|id| id.address == address && id.contains(destination))
                {
                    continue;
                }
                if queue.len == QUEUED {
                    return Delivery::Full;
                }
                let index = (queue.head + queue.len) % QUEUED;
                let packet = &mut queue.packets[index];
                packet.bytes[..bytes.len()].copy_from_slice(bytes);
                packet.len = bytes.len();
                packet.ecn = ecn;
                queue.len += 1;
                queue.receiver.take()
            };
            if let Some(waker) = wake {
                waker.wake();
            }
            return Delivery::Queued;
        }
        Delivery::Unknown
    }
}
impl<const BYTES: usize, const QUEUED: usize> Drop for Dispatcher<'_, BYTES, QUEUED> {
    fn drop(&mut self) {
        // Close every queue before invoking any reentrant wake callback.
        for slot in self.slots {
            let mut queue = slot.queue.borrow_mut();
            queue.identity = None;
            queue.len = 0;
        }
        for slot in self.slots {
            let wake = slot.queue.borrow_mut().receiver.take();
            if let Some(waker) = wake {
                waker.wake();
            }
        }
    }
}
impl<const BYTES: usize, const QUEUED: usize> Receiver<'_, BYTES, QUEUED> {
    pub async fn receive(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<crate::quic::ReceivedDatagram, Error> {
        poll_fn(|cx| {
            let replacement = cx.waker().clone();
            let previous = {
                let mut queue = self.slot.queue.borrow_mut();
                let Some(identity) = &queue.identity else {
                    return Poll::Ready(Err(Error::Closed));
                };
                let address = identity.address;
                if queue.len != 0 {
                    let packet = &queue.packets[queue.head];
                    if packet.len > bytes.len() {
                        return Poll::Ready(Err(Error::Capacity));
                    }
                    bytes[..packet.len].copy_from_slice(&packet.bytes[..packet.len]);
                    let result = crate::quic::ReceivedDatagram {
                        path: Some(address),
                        len: packet.len,
                        ecn: packet.ecn,
                    };
                    queue.head = (queue.head + 1) % QUEUED;
                    queue.len -= 1;
                    return Poll::Ready(Ok(result));
                }
                queue.receiver.replace(replacement)
            };
            drop(previous);
            Poll::Pending
        })
        .await
    }
}
impl<const BYTES: usize, const QUEUED: usize> Drop for Receiver<'_, BYTES, QUEUED> {
    fn drop(&mut self) {
        let previous = {
            let mut queue = self.slot.queue.borrow_mut();
            queue.identity = None;
            queue.len = 0;
            queue.receiver.take()
        };
        drop(previous);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::{future::Future, pin::pin, task::Context};
    fn address(port: u16) -> Address {
        Address {
            local: "127.0.0.1:443".parse().unwrap(),
            remote: format!("127.0.0.1:{port}").parse().unwrap(),
        }
    }
    #[test]
    fn waiting_old_receiver_does_not_block_new_connection() {
        let mut slots = [const { Slot::<32, 2>::new() }; 2];
        let mut routes = Dispatcher::new(&mut slots).unwrap();
        let mut old = routes
            .register(address(1), &[b"old-original", b"old-local"])
            .unwrap();
        let mut new = routes
            .register(address(1), &[b"new-original", b"new-local"])
            .unwrap();
        let mut old_bytes = [0; 32];
        let mut old_read = pin!(old.receive(&mut old_bytes));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(old_read.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            routes.deliver(
                address(1),
                b"new-local",
                b"new packet",
                Some(crate::io::Codepoint::Ect1)
            ),
            Delivery::Queued
        );
        let mut new_bytes = [0; 32];
        let packet = {
            let mut new_read = pin!(new.receive(&mut new_bytes));
            let Poll::Ready(Ok(packet)) = new_read.as_mut().poll(&mut cx) else {
                panic!("new owner did not receive");
            };
            packet
        };
        assert_eq!(&new_bytes[..packet.len], b"new packet");
        assert_eq!(packet.ecn, Some(crate::io::Codepoint::Ect1));
        assert!(old_read.as_mut().poll(&mut cx).is_pending());
    }
    #[test]
    fn physical_reader_closure_wakes_and_closes_receivers() {
        let mut slots = [Slot::<8, 1>::new()];
        let mut routes = Dispatcher::new(&mut slots).unwrap();
        let mut receiver = routes.register(address(1), &[b"cid"]).unwrap();
        let mut bytes = [0; 8];
        let mut read = pin!(receiver.receive(&mut bytes));
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
        let mut slots = [Slot::<8, 1>::new()];
        let mut routes = Dispatcher::new(&mut slots).unwrap();
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
