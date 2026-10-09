//! Authenticated peer CID facts and unique reliable retirement-frame ownership.
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::imp::kernel::connection_id::Cid;
use crate::quic::imp::kernel::connection_id::CidError;
use crate::quic::imp::kernel::connection_id::PeerCid;
use crate::quic::imp::kernel::connection_id::PeerCidSlot;
use crate::quic::imp::kernel::connection_id::PeerCidTable;
use crate::quic::imp::kernel::connection_id::ResetToken;
use crate::quic::imp::kernel::connection_id::Retirement;
use crate::quic::path::Address;
pub struct Storage<'a> {
    pub slots: &'a mut [PeerCidSlot<4>],
    pub active_limit: u64,
}
pub(crate) struct Peers<'a, 'scope> {
    scope: &'scope ApplicationKeyScope,
    table: PeerCidTable<'a, 4>,
    retirement: Option<Retirement>,
    sent: Option<u64>,
    lost: [Option<u64>; 8],
}
impl<'a, 'scope> Peers<'a, 'scope> {
    pub(crate) fn new(
        storage: Storage<'a>,
        scope: &'scope ApplicationKeyScope,
        initial: &[u8],
        initial_path: Option<Address>,
        preferred: Option<super::preferred::Preferred>,
        initial_token: Option<ResetToken>,
    ) -> Result<Self, CidError> {
        let mut table = PeerCidTable::new(
            2,
            1,
            storage.slots,
            storage.active_limit,
            Cid::new(initial)?,
        )?;
        if let Some(token) = initial_token {
            table.install_initial_token_verified(token)?;
        }
        // The caller crossed the completed physical handshake prefix before this
        // constructor. Its final peer CID was actually used on the admitted path.
        if let Some(path) = initial_path {
            let cid = table.initial()?;
            table.record_sent(cid.handle, path.local, path.remote)?;
        }
        if let Some(p) = preferred {
            table.accept_preferred_verified(p.cid, p.token)?;
        }
        Ok(Self {
            scope,
            table,
            retirement: None,
            sent: None,
            lost: [None; 8],
        })
    }
    pub(crate) fn receive(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        cid: &[u8],
        token: [u8; 16],
    ) -> Result<(), CidError> {
        self.table.accept_new_authenticated(
            sequence,
            retire_prior_to,
            Cid::new(cid)?,
            ResetToken::new(token),
        )?;
        Ok(())
    }
    pub(crate) fn choose(
        &self,
        path: Address,
        preferred: Option<Cid>,
    ) -> Result<PeerCid, CidError> {
        self.table
            .active()
            .filter(|cid| {
                self.table
                    .check_send(cid.handle, path.local, path.remote)
                    .is_ok()
            })
            .min_by_key(|cid| {
                (
                    preferred.is_some_and(|wanted| wanted != cid.cid),
                    cid.sequence,
                )
            })
            .ok_or(CidError::UnusedConnectionId)
    }
    pub(crate) fn accepted(&mut self, cid: PeerCid, path: Address) -> Result<(), CidError> {
        self.table.record_sent(cid.handle, path.local, path.remote)
    }
    pub(crate) fn retire_previous(
        &mut self,
        old: Address,
        new: Address,
        preferred: Option<Cid>,
    ) -> Result<(), CidError> {
        let selected = self.choose(new, preferred)?;
        let old = self
            .table
            .active()
            .find(|cid| {
                cid.handle != selected.handle
                    && self
                        .table
                        .check_send(cid.handle, old.local, old.remote)
                        .is_ok()
            })
            .map(|cid| cid.handle);
        if let Some(handle) = old {
            self.table.retire(handle)?;
        }
        Ok(())
    }
    pub(crate) fn prepare_retirement(&mut self, dcid: Cid) -> Result<Option<u64>, CidError> {
        if self.sent.is_some() {
            return Ok(None);
        }
        if self.retirement.is_none() {
            let handle = self.table.queued_retirements().next();
            if let Some(handle) = handle {
                self.retirement = self.table.take_retirement(handle, dcid)?;
            }
        }
        self.retirement
            .as_ref()
            .map(|r| {
                r.frame(dcid)?;
                Ok(r.sequence())
            })
            .transpose()
    }
    pub(crate) fn retirement_accepted(
        &mut self,
        sequence: u64,
        packet: u64,
    ) -> Result<(), CidError> {
        if self.retirement.as_ref().map(Retirement::sequence) != Some(sequence)
            || self.sent.is_some()
        {
            return Err(CidError::UnknownSequence);
        }
        self.sent = Some(packet);
        Ok(())
    }
    pub(crate) fn acknowledge(
        &mut self,
        grant: &crate::quic::imp::recovery::FrameAcknowledgments<'scope>,
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
            self.retirement = None;
            self.sent = None;
            self.lost.fill(None);
        }
        Ok(())
    }
    pub(crate) fn loss(
        &mut self,
        grant: &crate::quic::imp::recovery::ApplicationLoss<'scope>,
    ) -> Result<(), CidError> {
        if !core::ptr::eq(self.scope, grant.scope()) {
            return Err(CidError::UnknownSequence);
        }
        if self.sent == Some(grant.packet().value) {
            let slot = self
                .lost
                .iter_mut()
                .find(|v| v.is_none())
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
    fn new_local_path_uses_unused_cid_and_keeps_retirement_resource() {
        let scope = ApplicationKeyScope::new(222);
        let mut slots: [PeerCidSlot<4>; 8] = core::array::from_fn(|_| PeerCidSlot::EMPTY);
        let old = Address {
            local: "127.0.0.1:1000".parse().unwrap(),
            remote: "127.0.0.1:2000".parse().unwrap(),
        };
        let new = Address {
            local: "127.0.0.1:1001".parse().unwrap(),
            ..old
        };
        let mut peers = Peers::new(
            Storage {
                slots: &mut slots,
                active_limit: 2,
            },
            &scope,
            &[1; 8],
            Some(old),
            None,
            None,
        )
        .unwrap();
        assert!(peers.choose(new, None).is_err());
        peers.receive(1, 0, &[2; 8], [3; 16]).unwrap();
        let next = peers.choose(new, None).unwrap();
        assert_eq!(next.sequence, 1);
        peers.accepted(next, new).unwrap();
        peers.retire_previous(old, new, None).unwrap();
        // A delayed challenge on the old path must wait for a usable CID.
        // Never reuse its retired CID, or reuse the new path's bound CID.
        assert!(peers.choose(old, None).is_err());
        assert_eq!(peers.prepare_retirement(next.cid).unwrap(), Some(0));
        assert_eq!(peers.prepare_retirement(next.cid).unwrap(), Some(0));
        peers.retirement_accepted(0, 12).unwrap();
        assert_eq!(peers.prepare_retirement(next.cid).unwrap(), None);
        peers.receive(2, 0, &[4; 8], [5; 16]).unwrap();
        let reply = peers.choose(old, None).unwrap();
        assert_eq!(reply.sequence, 2);
        peers.accepted(reply, old).unwrap();
        assert_eq!(peers.choose(new, None).unwrap().sequence, 1);
    }
}
