//! Reconstructed transcript ownership adapter. Requires fresh validation.
//! Packet authentication and CRYPTO reassembly precede creation of CryptoInput.
use crate::{
    bounded_tls::{
        State,
        key_source::{
            EarlyKeyMaterial, FinishedAuthenticated, KeySource, ReceivePacketKey, TransmitPacketKey,
        },
    },
    crypto::{
        IntegrityBudget,
        directional::{ApplicationKeyScope, ApplicationReadKeys, ApplicationWriteKeys},
    },
    early_data::{EarlyStatus, RememberedLimits, ReplayClaim},
    packet::MAX_VARINT,
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
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}
pub struct CryptoFlight<const N: usize> {
    level: Level,
    offset: u64,
    bytes: [u8; N],
    len: usize,
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
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}
pub struct PeerParameters<const P: usize> {
    bytes: [u8; P],
    len: usize,
}
impl<const P: usize> PeerParameters<P> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
#[must_use = "Finished authority must cross the validated application boundary"]
pub struct Finished<'scope, const P: usize> {
    receipt: FinishedAuthenticated<'scope>,
    parameters: PeerParameters<P>,
}
impl<'scope, const P: usize> Finished<'scope, P> {
    pub fn receipt(&self) -> &FinishedAuthenticated<'scope> {
        &self.receipt
    }
    pub fn parameters(&self) -> &[u8] {
        self.parameters.bytes()
    }
    pub fn into_parts(self) -> (FinishedAuthenticated<'scope>, PeerParameters<P>) {
        (self.receipt, self.parameters)
    }
    pub fn into_receipt(self) -> FinishedAuthenticated<'scope> {
        self.receipt
    }
}

pub struct Transcript<'scope, 'cfg, 'buf> {
    source: KeySource<'scope, 'cfg, 'buf>,
    received: [u64; 3],
    sent: [u64; 3],
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
        if self.source.state() == State::Failed {
            Err(Error::Handshake)
        } else {
            Ok(())
        }
    }
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.source.scope()
    }
    pub fn side(&self) -> crate::tls_schedule::Side {
        self.source.side()
    }
    pub fn state(&self) -> State {
        self.source.state()
    }
    pub(crate) fn material(&mut self) -> &mut crate::bounded_tls::BoundedTls<'cfg, 'buf> {
        self.source.material()
    }
    pub(crate) fn record_verified_consumed(&mut self, consumed: [u64; 2]) -> Result<(), Error> {
        for (index, end) in consumed.into_iter().enumerate() {
            if end < self.received[index] || end > MAX_VARINT {
                return Err(Error::InvalidInput);
            }
            self.received[index] = end;
        }
        Ok(())
    }
    pub fn received_offset(&self, level: Level) -> u64 {
        self.received[level_index(level)]
    }
    pub fn observations(&self) -> Observations {
        self.source.observations()
    }
    pub fn is_resumed(&self) -> bool {
        self.source.is_resumed()
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
    pub fn receive<const N: usize>(&mut self, input: CryptoInput<'scope, N>) -> Result<(), Error> {
        self.ensure_live()?;
        if !core::ptr::eq(input.scope(), self.scope()) {
            return Err(Error::InvalidInput);
        }
        let index = level_index(input.level());
        if input.offset() != self.received[index] {
            return Err(Error::InvalidInput);
        }
        let end = range_end(input.offset(), input.bytes().len())?;
        self.source.receive(input.level(), input.bytes())?;
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
        self.source.take_application_keys()?.install()
    }
    pub fn take_finished<const P: usize>(&mut self) -> Result<Finished<'scope, P>, Error> {
        self.ensure_live()?;
        if self.source.state() != State::Connected {
            return Err(Error::KeysUnavailable);
        }
        let raw = self
            .source
            .peer_transport_parameters()
            .ok_or(Error::KeysUnavailable)?;
        if raw.len() > P {
            return Err(Error::Capacity);
        }
        let mut bytes = [0; P];
        bytes[..raw.len()].copy_from_slice(raw);
        let parameters = PeerParameters {
            bytes,
            len: raw.len(),
        };
        let receipt = self.source.take_finished()?;
        Ok(Finished {
            receipt,
            parameters,
        })
    }
    pub fn take_integrity_budget(&mut self) -> Result<IntegrityBudget, Error> {
        self.ensure_live()?;
        self.source.take_integrity_budget()
    }
    pub fn take_early_admission(
        &mut self,
    ) -> Result<crate::early_data::owner::Admission<'scope>, Error> {
        self.ensure_live()?;
        self.source.take_early_admission()
    }
    pub fn take_early_key(&mut self) -> Result<EarlyKeyMaterial<'scope>, Error> {
        self.ensure_live()?;
        self.source.take_early_key()
    }
    pub fn resumed(&self) -> bool {
        self.source.resumed()
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
fn level_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::OneRtt => 2,
    }
}
fn range_end(offset: u64, len: usize) -> Result<u64, Error> {
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
