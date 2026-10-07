//! Authenticated challenge data, consumed only by real UDP acceptance through
//! the existing Hibana Datagram/Accepted-or-Rejected/Settled exchange.
use core::cell::RefCell;
const CAPACITY: usize = 4;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Response {
    sequence: u64,
    pub(crate) data: [u8; 8],
}
struct Observations {
    next: u64,
    pending: [Option<Response>; CAPACITY],
    accepted: u64,
}
pub(crate) struct Responses(RefCell<Observations>);
impl Responses {
    pub(crate) const fn new() -> Self {
        Self(RefCell::new(Observations {
            next: 0,
            pending: [None; CAPACITY],
            accepted: 0,
        }))
    }
    pub(crate) fn observe(&self, data: [u8; 8]) -> Result<(), ()> {
        let mut n = self.0.try_borrow_mut().map_err(|_| ())?;
        if n.pending.iter().flatten().any(|r| r.data == data) {
            return Ok(());
        }
        let slot = n.pending.iter().position(Option::is_none).ok_or(())?;
        let sequence = n.next;
        n.next = n.next.checked_add(1).ok_or(())?;
        n.pending[slot] = Some(Response { sequence, data });
        Ok(())
    }
    pub(crate) fn pending(&self) -> Result<Option<Response>, ()> {
        Ok(self
            .0
            .try_borrow()
            .map_err(|_| ())?
            .pending
            .iter()
            .flatten()
            .min_by_key(|r| r.sequence)
            .copied())
    }
    pub(crate) fn accepted(&self, response: Response) -> Result<(), ()> {
        let mut n = self.0.try_borrow_mut().map_err(|_| ())?;
        let slot = n
            .pending
            .iter()
            .position(|r| *r == Some(response))
            .ok_or(())?;
        n.accepted = n.accepted.checked_add(1).ok_or(())?;
        n.pending[slot] = None;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retain_until_matching_actual_acceptance() {
        let q = Responses::new();
        q.observe([1; 8]).unwrap();
        let first = q.pending().unwrap().unwrap();
        q.observe([1; 8]).unwrap();
        q.observe([2; 8]).unwrap();
        assert_eq!(q.pending().unwrap(), Some(first));
        q.accepted(first).unwrap();
        assert!(q.accepted(first).is_err());
        assert_eq!(q.pending().unwrap().unwrap().data, [2; 8]);
        q.observe([1; 8]).unwrap();
        q.accepted(q.pending().unwrap().unwrap()).unwrap();
        let repeat = q.pending().unwrap().unwrap();
        assert_ne!(first.sequence, repeat.sequence);
        assert!(q.accepted(first).is_err());
        q.accepted(repeat).unwrap();
        assert_eq!(q.pending().unwrap(), None);
    }
    #[test]
    fn overflow_preserves_retained_data() {
        let q = Responses::new();
        for n in 0..CAPACITY {
            q.observe([n as u8; 8]).unwrap();
        }
        let first = q.pending().unwrap();
        assert!(q.observe([9; 8]).is_err());
        assert_eq!(q.pending().unwrap(), first);
    }
}
