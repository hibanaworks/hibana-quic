//! Actual CID issuance and reliable publication receipts; not a parallel
//! connection phase controller. The existing projected publisher owns effects.
use crate::{
    connection_id::{Cid, CidError, LocalCid, LocalCidSlot, LocalCidTable},
    crypto::directional::ApplicationKeyScope,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;
pub struct Storage<'a> {
    pub slots: &'a mut [LocalCidSlot],
    pub seed: &'a [u8; 32],
}
pub(crate) struct Ids<'a, 'scope> {
    scope: &'scope ApplicationKeyScope,
    table: LocalCidTable<'a>,
    seed: &'a [u8; 32],
    pending: Option<LocalCid>,
    sent: Option<u64>,
    lost: [Option<u64>; 8],
}
impl<'a, 'scope> Ids<'a, 'scope> {
    pub(crate) fn new(
        storage: Storage<'a>,
        scope: &'scope ApplicationKeyScope,
        initial: &[u8],
        limit: u64,
        preferred: Option<super::preferred::Preferred>,
    ) -> Result<Self, CidError> {
        let mut table = LocalCidTable::new(1, 1, storage.slots, limit)?;
        let first = table.issue_initial(Cid::new(initial)?, None)?;
        table.mark_advertised(first.handle)?;
        if let Some(p) = preferred {
            let preferred = table.issue_preferred(p.cid, p.token)?;
            table.mark_advertised(preferred.handle)?;
        }
        Ok(Self {
            scope,
            table,
            seed: storage.seed,
            pending: None,
            sent: None,
            lost: [None; 8],
        })
    }
    pub(crate) fn routes(&self, cid: &[u8]) -> bool {
        self.table.route(cid).is_some()
    }
    pub(crate) fn prepare(&mut self) -> Result<Option<LocalCid>, CidError> {
        if self.sent.is_some() {
            return Ok(None);
        }
        if self.pending.is_none() && self.table.can_issue() {
            let mut info = [0u8; 24];
            info[..16].copy_from_slice(b"hibana quic cid ");
            info[16..].copy_from_slice(&self.table.next_sequence().to_be_bytes());
            let mut output = Zeroizing::new([0u8; 24]);
            Hkdf::<Sha256>::new(None, self.seed)
                .expand(&info, &mut *output)
                .map_err(|_| CidError::InvalidCapacity)?;
            let cid = Cid::new(&output[..8])?;
            let token = crate::connection_id::ResetToken::new(
                output[8..]
                    .try_into()
                    .map_err(|_| CidError::InvalidCapacity)?,
            );
            self.pending = Some(self.table.issue(cid, token, 0)?);
        }
        Ok(self.pending)
    }
    pub(crate) fn accepted(&mut self, cid: LocalCid, packet: u64) -> Result<(), CidError> {
        if self.pending.as_ref().map(|x| x.handle) != Some(cid.handle) || self.sent.is_some() {
            return Err(CidError::UnknownSequence);
        }
        self.table.mark_advertised(cid.handle)?;
        self.sent = Some(packet);
        Ok(())
    }
    pub(crate) fn retire(&mut self, sequence: u64, packet_cid: &[u8]) -> Result<(), CidError> {
        self.table.retire_authenticated(sequence, packet_cid)?;
        if self
            .pending
            .as_ref()
            .is_some_and(|x| x.sequence == sequence)
        {
            self.pending = None;
            self.sent = None;
            self.lost.fill(None);
        }
        Ok(())
    }
    pub(crate) fn acknowledge(
        &mut self,
        grant: &crate::quic::recovery::FrameAcknowledgments<'scope>,
    ) -> Result<(), CidError> {
        if !core::ptr::eq(self.scope, grant.scope()) {
            return Err(CidError::UnknownSequence);
        }
        if grant
            .packets()
            .iter()
            .flatten()
            .any(|pn| self.sent == Some(pn.value) || self.lost.contains(&Some(pn.value)))
        {
            self.pending = None;
            self.sent = None;
            self.lost.fill(None);
        }
        Ok(())
    }
    pub(crate) fn loss(
        &mut self,
        grant: &crate::quic::recovery::ApplicationLoss<'scope>,
    ) -> Result<(), CidError> {
        if !core::ptr::eq(self.scope, grant.scope()) {
            return Err(CidError::UnknownSequence);
        }
        if self.sent == Some(grant.packet().value) {
            let slot = self
                .lost
                .iter_mut()
                .find(|x| x.is_none())
                .ok_or(CidError::HistoryFull)?;
            *slot = self.sent.take();
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_advertisement_gates_retirement() {
        let scope = ApplicationKeyScope::new(77);
        let mut slots = [LocalCidSlot::EMPTY; 8];
        let seed = [29; 32];
        let mut ids = Ids::new(
            Storage {
                slots: &mut slots,
                seed: &seed,
            },
            &scope,
            b"initial-",
            2,
            None,
        )
        .unwrap();
        let first = ids.prepare().unwrap().unwrap();
        assert_eq!(first.sequence, 1);
        assert!(ids.routes(first.cid.as_bytes()));
        assert!(ids.retire(1, b"initial-").is_err());
        assert_eq!(ids.prepare().unwrap().unwrap().cid, first.cid);
        ids.accepted(first, 3).unwrap();
        assert!(ids.prepare().unwrap().is_none());
        assert!(ids.accepted(first, 4).is_err());
        assert!(ids.retire(1, first.cid.as_bytes()).is_err());
        ids.retire(1, b"initial-").unwrap();
        assert!(!ids.routes(first.cid.as_bytes()));
        let next = ids.prepare().unwrap().unwrap();
        assert_eq!(next.sequence, 2);
        assert_ne!(next.cid, first.cid);
        assert!(next.token != first.token);
    }
}
