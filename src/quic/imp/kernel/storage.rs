//! Caller-owned, fixed-capacity byte storage with checked descriptor ownership.
//!
//! Descriptors are deliberately copyable: serialization and Rust moves are not
//! ownership proofs. Every operation checks the pool, connection generation,
//! slot generation, owner, and exact byte range against this pool's ledger.
//! These are internal handles, not cryptographic capabilities for network input.

/// The role currently allowed to access a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerId(pub u16);

/// A serializable handle. Editing or replaying fields does not edit the ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub pool: u64,
    pub connection_generation: u64,
    pub slot: usize,
    pub generation: u64,
    pub owner: OwnerId,
    pub offset: usize,
    pub len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Full,
    InvalidRange,
    WrongPool,
    WrongConnection,
    InvalidSlot,
    StaleLease,
    WrongOwner,
    GenerationExhausted,
    Retired,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    owner: Option<OwnerId>,
    offset: usize,
    len: usize,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 0,
        owner: None,
        offset: 0,
        len: 0,
    };
}

/// A pool borrowing its byte arena directly from the caller.
///
/// `pool` must be unique among live pools in a connection, and the caller must
/// never reuse a `(pool, connection_generation)` pair while old descriptors can
/// arrive. Neither the pool nor its bookkeeping is cloneable. Byte borrows are
/// tied to the pool borrow, so transfer/release cannot race an outstanding view.
pub struct LeasePool<'a, const SLOTS: usize, const BYTES: usize> {
    pool: u64,
    connection_generation: u64,
    storage: &'a mut [[u8; BYTES]; SLOTS],
    slots: [Slot; SLOTS],
    retired: bool,
}

impl<'a, const SLOTS: usize, const BYTES: usize> LeasePool<'a, SLOTS, BYTES> {
    pub fn new(
        pool: u64,
        connection_generation: u64,
        storage: &'a mut [[u8; BYTES]; SLOTS],
    ) -> Self {
        Self {
            pool,
            connection_generation,
            storage,
            slots: [Slot::EMPTY; SLOTS],
            retired: false,
        }
    }

    /// Reserve one entire slot, exposing only the requested range. Newly
    /// exposed bytes are zeroed, including when the slot changes owners.
    pub fn acquire(
        &mut self,
        owner: OwnerId,
        offset: usize,
        len: usize,
    ) -> Result<Lease, StorageError> {
        if self.retired {
            return Err(StorageError::Retired);
        }
        let end = offset.checked_add(len).ok_or(StorageError::InvalidRange)?;
        if end > BYTES {
            return Err(StorageError::InvalidRange);
        }
        let mut exhausted = false;
        for index in 0..SLOTS {
            let slot = &mut self.slots[index];
            if slot.owner.is_some() {
                continue;
            }
            let Some(generation) = slot.generation.checked_add(1) else {
                exhausted = true;
                continue;
            };
            self.storage[index][offset..end].fill(0);
            *slot = Slot {
                generation,
                owner: Some(owner),
                offset,
                len,
            };
            return Ok(Lease {
                pool: self.pool,
                connection_generation: self.connection_generation,
                slot: index,
                generation,
                owner,
                offset,
                len,
            });
        }
        Err(if exhausted {
            StorageError::GenerationExhausted
        } else {
            StorageError::Full
        })
    }

    /// Check a descriptor and the authority of the requesting role.
    pub fn validate(&self, owner: OwnerId, lease: &Lease) -> Result<(), StorageError> {
        if self.retired {
            return Err(StorageError::Retired);
        }
        if lease.pool != self.pool {
            return Err(StorageError::WrongPool);
        }
        if lease.connection_generation != self.connection_generation {
            return Err(StorageError::WrongConnection);
        }
        let slot = self
            .slots
            .get(lease.slot)
            .ok_or(StorageError::InvalidSlot)?;
        if slot.generation != lease.generation || slot.owner.is_none() {
            return Err(StorageError::StaleLease);
        }
        if slot.owner != Some(owner) || lease.owner != owner {
            return Err(StorageError::WrongOwner);
        }
        if slot.offset != lease.offset || slot.len != lease.len {
            return Err(StorageError::InvalidRange);
        }
        Ok(())
    }

    pub fn bytes(&self, owner: OwnerId, lease: &Lease) -> Result<&[u8], StorageError> {
        self.validate(owner, lease)?;
        // The exact range was checked against a range validated by acquire.
        Ok(&self.storage[lease.slot][lease.offset..lease.offset + lease.len])
    }

    pub fn bytes_mut(&mut self, owner: OwnerId, lease: &Lease) -> Result<&mut [u8], StorageError> {
        self.validate(owner, lease)?;
        Ok(&mut self.storage[lease.slot][lease.offset..lease.offset + lease.len])
    }

    /// Transfer invalidates *all* copies of the old descriptor, even for a
    /// transfer back to the same role. Counter exhaustion leaves ownership
    /// unchanged; generations never wrap.
    pub fn transfer(
        &mut self,
        owner: OwnerId,
        lease: &Lease,
        new_owner: OwnerId,
    ) -> Result<Lease, StorageError> {
        self.validate(owner, lease)?;
        let generation = lease
            .generation
            .checked_add(1)
            .ok_or(StorageError::GenerationExhausted)?;
        let slot = &mut self.slots[lease.slot];
        slot.generation = generation;
        slot.owner = Some(new_owner);
        Ok(Lease {
            generation,
            owner: new_owner,
            ..*lease
        })
    }

    pub fn release(&mut self, owner: OwnerId, lease: &Lease) -> Result<(), StorageError> {
        self.validate(owner, lease)?;
        self.slots[lease.slot].owner = None;
        Ok(())
    }

    /// Permanently revoke this connection's pool. A new connection requires
    /// a fresh, caller-issued connection generation; this object cannot revive.
    pub fn retire(&mut self) {
        self.retired = true;
        for slot in &mut self.slots {
            slot.owner = None;
        }
    }

    pub fn active_leases(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.owner.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: OwnerId = OwnerId(1);
    const B: OwnerId = OwnerId(2);

    #[test]
    fn transfer_and_reuse_invalidate_copied_descriptors() {
        let mut arena = [[0; 8]; 1];
        let mut pool = LeasePool::new(1, 7, &mut arena);
        let original = pool.acquire(A, 2, 3).unwrap();
        pool.bytes_mut(A, &original)
            .unwrap()
            .copy_from_slice(b"abc");
        let transferred = pool.transfer(A, &original, B).unwrap();
        assert_eq!(pool.bytes(B, &transferred).unwrap(), b"abc");
        assert_eq!(pool.release(A, &original), Err(StorageError::StaleLease));
        assert_eq!(
            pool.transfer(A, &original, B),
            Err(StorageError::StaleLease)
        );
        let returned = pool.transfer(B, &transferred, A).unwrap();
        assert_eq!(pool.bytes(A, &original), Err(StorageError::StaleLease));
        pool.release(A, &returned).unwrap();
        assert_eq!(pool.release(A, &returned), Err(StorageError::StaleLease));
        let reused = pool.acquire(A, 2, 3).unwrap();
        assert_eq!(pool.bytes(A, &reused).unwrap(), &[0; 3]);
        assert_eq!(pool.bytes(A, &returned), Err(StorageError::StaleLease));
    }

    #[test]
    fn descriptor_fields_and_requester_are_all_checked() {
        let mut arena = [[0; 8]; 1];
        let mut pool = LeasePool::new(3, 4, &mut arena);
        let lease = pool.acquire(A, 1, 3).unwrap();
        assert_eq!(pool.bytes(B, &lease), Err(StorageError::WrongOwner));
        for (changed, expected) in [
            (Lease { pool: 9, ..lease }, StorageError::WrongPool),
            (
                Lease {
                    connection_generation: 9,
                    ..lease
                },
                StorageError::WrongConnection,
            ),
            (Lease { slot: 1, ..lease }, StorageError::InvalidSlot),
            (
                Lease {
                    generation: 9,
                    ..lease
                },
                StorageError::StaleLease,
            ),
            (Lease { owner: B, ..lease }, StorageError::WrongOwner),
            (Lease { offset: 2, ..lease }, StorageError::InvalidRange),
            (
                Lease {
                    len: usize::MAX,
                    ..lease
                },
                StorageError::InvalidRange,
            ),
        ] {
            assert_eq!(pool.bytes(A, &changed), Err(expected));
        }
        assert_eq!(pool.active_leases(), 1);
    }

    #[test]
    fn bounded_capacity_invalid_ranges_and_zero_size() {
        let mut arena = [[0; 8]; 1];
        let mut pool = LeasePool::new(1, 1, &mut arena);
        assert_eq!(
            pool.acquire(A, usize::MAX, 1),
            Err(StorageError::InvalidRange)
        );
        assert_eq!(pool.acquire(A, 7, 2), Err(StorageError::InvalidRange));
        let empty = pool.acquire(A, 8, 0).unwrap();
        assert!(pool.bytes(A, &empty).unwrap().is_empty());
        assert_eq!(pool.acquire(A, 0, 1), Err(StorageError::Full));
        let mut no_slots = [];
        let mut empty_pool = LeasePool::<0, 8>::new(2, 1, &mut no_slots);
        assert_eq!(empty_pool.acquire(A, 0, 0), Err(StorageError::Full));
    }

    #[test]
    fn generation_never_wraps() {
        let mut arena = [[0; 8]; 1];
        let mut pool = LeasePool::new(1, 1, &mut arena);
        pool.slots[0].generation = u64::MAX - 1;
        let lease = pool.acquire(A, 0, 8).unwrap();
        assert_eq!(lease.generation, u64::MAX);
        assert_eq!(
            pool.transfer(A, &lease, B),
            Err(StorageError::GenerationExhausted)
        );
        assert!(pool.bytes(A, &lease).is_ok());
        pool.release(A, &lease).unwrap();
        assert_eq!(
            pool.acquire(A, 0, 8),
            Err(StorageError::GenerationExhausted)
        );
    }

    #[test]
    fn retired_connection_cannot_revive() {
        let mut arena = [[0; 8]; 1];
        let lease = {
            let mut pool = LeasePool::new(1, 1, &mut arena);
            let lease = pool.acquire(A, 0, 8).unwrap();
            pool.retire();
            assert_eq!(pool.bytes(A, &lease), Err(StorageError::Retired));
            assert_eq!(pool.release(A, &lease), Err(StorageError::Retired));
            assert_eq!(pool.acquire(A, 0, 8), Err(StorageError::Retired));
            assert_eq!(pool.active_leases(), 0);
            lease
        };
        let new_pool = LeasePool::new(1, 2, &mut arena);
        assert_eq!(
            new_pool.bytes(A, &lease),
            Err(StorageError::WrongConnection)
        );
    }
}
