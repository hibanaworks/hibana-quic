//! Owned transcript input, output and authenticated handoff material.
//! Packet authentication and CRYPTO reassembly precede creation of CryptoInput.
use crate::{
    crypto::{
        IntegrityBudget,
        directional::{ApplicationKeyScope, ApplicationReadKeys, ApplicationWriteKeys},
    },
    quic::early_data::{EarlyStatus, RememberedLimits, ReplayClaim},
    quic::kernel::packet::MAX_VARINT,
    tls::handshake::key_source::{
        EarlyKeyMaterial, FinishedAuthenticated, KeySource, ReceivePacketKey, TransmitPacketKey,
    },
    tls::{Error, Level, Observations},
};
use core::cell::RefCell;

pub struct CryptoInput<'scope, const N: usize> {
    scope: &'scope ApplicationKeyScope,
    level: Level,
    offset: u64,
    bytes: [u8; N],
    len: usize,
}
impl<'scope, const N: usize> CryptoInput<'scope, N> {
    pub(super) fn new(
        scope: &'scope ApplicationKeyScope,
        level: Level,
        offset: u64,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::InvalidInput);
        }
        if bytes.len() > N {
            return Err(Error::Capacity);
        }
        range_end(offset, bytes.len())?;
        let mut stored = [0; N];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            scope,
            level,
            offset,
            bytes: stored,
            len: bytes.len(),
        })
    }
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub const fn level(&self) -> Level {
        self.level
    }
    pub const fn offset(&self) -> u64 {
        self.offset
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> Drop for CryptoInput<'_, N> {
    fn drop(&mut self) {
        use hibana_tls::secret::Erase;
        self.bytes.erase();
    }
}
pub struct CryptoFlight<const N: usize> {
    pub(super) level: Level,
    pub(super) offset: u64,
    pub(super) bytes: [u8; N],
    pub(super) len: usize,
}
impl<const N: usize> CryptoFlight<N> {
    pub const fn level(&self) -> Level {
        self.level
    }
    pub const fn offset(&self) -> u64 {
        self.offset
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> Drop for CryptoFlight<N> {
    fn drop(&mut self) {
        use hibana_tls::secret::Erase;
        self.bytes.erase();
    }
}
pub use hibana_tls::handshake::key_source::{Finished, PeerParameters};

pub struct Transcript<'scope, 'cfg, 'buf> {
    pub(super) source: KeySource<'scope, 'cfg, 'buf>,
    pub(super) received: [u64; 3],
    pub(super) sent: [u64; 3],
}
impl<'scope, 'cfg, 'buf> Transcript<'scope, 'cfg, 'buf> {
    pub fn new(source: KeySource<'scope, 'cfg, 'buf>) -> Self {
        Self {
            source,
            received: [0; 3],
            sent: [0; 3],
        }
    }
    fn ensure_live(&self) -> Result<(), Error> {
        if self.source.last_failure().is_some() {
            Err(Error::Handshake)
        } else {
            Ok(())
        }
    }
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.source.scope()
    }
    pub fn version(&self) -> crate::quic::kernel::version::Version {
        self.source.version()
    }
    pub fn side(&self) -> crate::tls::schedule::Side {
        self.source.side()
    }
    pub fn received_offset(&self, level: Level) -> u64 {
        self.received[level_index(level)]
    }
    pub fn observations(&self) -> Observations {
        self.source.observations()
    }
    pub fn negotiated_suite(&self) -> Option<crate::crypto::CipherSuite> {
        self.source.negotiated_suite()
    }
    pub fn negotiated_group(&self) -> Option<u16> {
        self.source.negotiated_group()
    }
    pub fn write_failure_diagnostic(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.source.write_failure_diagnostic(output)
    }
    pub fn receive<const N: usize>(
        &mut self,
        finished: &FinishedAuthenticated<'scope>,
        input: CryptoInput<'scope, N>,
    ) -> Result<(), Error> {
        self.ensure_live()?;
        if !core::ptr::eq(input.scope(), self.scope()) {
            return Err(Error::InvalidInput);
        }
        let index = level_index(input.level());
        if input.offset() != self.received[index] {
            return Err(Error::InvalidInput);
        }
        let end = range_end(input.offset(), input.bytes().len())?;
        self.source
            .receive(finished, input.level(), input.bytes())?;
        self.received[index] = end;
        Ok(())
    }
    pub fn transmit<const N: usize>(&mut self) -> Result<Option<CryptoFlight<N>>, Error> {
        self.ensure_live()?;
        let mut bytes = [0; N];
        let Some(output) = self.source.transmit(&mut bytes)? else {
            return Ok(None);
        };
        if output.len == 0 || output.len > N {
            return Err(Error::InvalidInput);
        }
        let index = level_index(output.level);
        let offset = self.sent[index];
        let end = range_end(offset, output.len)?;
        self.sent[index] = end;
        Ok(Some(CryptoFlight {
            level: output.level,
            offset,
            bytes,
            len: output.len,
        }))
    }
    pub fn take_handshake_keys(
        &mut self,
    ) -> Result<(ReceivePacketKey<'scope>, TransmitPacketKey<'scope>), Error> {
        self.ensure_live()?;
        Ok(self.source.take_handshake_keys()?.install())
    }
    pub fn take_application_keys(
        &mut self,
    ) -> Result<(ApplicationReadKeys<'scope>, ApplicationWriteKeys<'scope>), Error> {
        self.ensure_live()?;
        let (installation, local, remote) = self.source.take_application_keys()?.into_parts();
        ApplicationReadKeys::install(installation, local, remote).map_err(|error| match error {
            crate::crypto::Error::KeyUpdateNotAllowed => Error::KeyUpdateNotAllowed,
            crate::crypto::Error::KeyDiscarded => Error::KeysUnavailable,
            _ => Error::InvalidInput,
        })
    }
    pub fn take_finished<const P: usize>(&mut self) -> Result<Finished<'scope, P>, Error> {
        self.ensure_live()?;
        self.source.take_finished_with_parameters()
    }
    pub fn take_integrity_budget(&mut self) -> Result<IntegrityBudget, Error> {
        self.ensure_live()?;
        self.source.take_integrity_budget()
    }
    pub fn take_early_admission(
        &mut self,
    ) -> Result<crate::quic::early_data::owner::Admission<'scope>, Error> {
        self.ensure_live()?;
        self.source.take_early_admission()
    }
    pub fn take_early_key(&mut self) -> Result<EarlyKeyMaterial<'scope>, Error> {
        self.ensure_live()?;
        self.source.take_early_key()
    }
    pub fn early_status(&self) -> EarlyStatus {
        self.source.early_status()
    }
    pub fn early_generation(&self) -> Option<u64> {
        self.source.early_generation()
    }
    pub fn remembered_early_limits(&self) -> Option<RememberedLimits> {
        self.source.remembered_early_limits()
    }
    pub fn take_early_replay_claim(&mut self) -> Option<ReplayClaim> {
        self.source.take_early_replay_claim()
    }
    pub fn discard_pending_early_key(&mut self) {
        self.source.discard_pending_early_key();
    }
    pub fn discard_pending_keys(&mut self, level: Level) {
        self.source.discard_pending_keys(level);
    }
    pub fn retire(mut self) {
        for level in [Level::Initial, Level::Handshake, Level::OneRtt] {
            self.source.discard_pending_keys(level);
        }
        self.source.discard_pending_early_key();
    }
}
pub(super) fn level_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::OneRtt => 2,
    }
}
pub(super) fn range_end(offset: u64, len: usize) -> Result<u64, Error> {
    let end = offset
        .checked_add(u64::try_from(len).map_err(|_| Error::Capacity)?)
        .ok_or(Error::Capacity)?;
    if end > MAX_VARINT {
        Err(Error::InvalidInput)
    } else {
        Ok(end)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxError {
    Borrowed,
    Occupied,
    Empty,
}
pub(crate) struct Inbox<T> {
    slot: RefCell<Option<T>>,
}
impl<T> Inbox<T> {
    pub(crate) const fn new() -> Self {
        Self {
            slot: RefCell::new(None),
        }
    }
    pub(crate) fn put(&self, value: T) -> Result<(), InboxError> {
        let mut slot = self
            .slot
            .try_borrow_mut()
            .map_err(|_| InboxError::Borrowed)?;
        if slot.is_some() {
            return Err(InboxError::Occupied);
        }
        *slot = Some(value);
        Ok(())
    }
    pub(crate) fn take(&self) -> Result<T, InboxError> {
        self.slot
            .try_borrow_mut()
            .map_err(|_| InboxError::Borrowed)?
            .take()
            .ok_or(InboxError::Empty)
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.slot.borrow().is_none()
    }
}
impl<T> Default for Inbox<T> {
    fn default() -> Self {
        Self::new()
    }
}
