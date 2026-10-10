//! Authenticated early-data receipts, bounded byte storage and exchange slots.
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::early_data::Failure;
use crate::quic::imp::tls::Inbox;
use hibana_tls::{handshake::keys::FinishedAuthenticated, secret::Erase};
/// Created only by the authenticated receive boundary, never by a wire label.
pub struct AuthenticatedInput<'scope, const N: usize> {
    pub(crate) scope: &'scope ApplicationKeyScope,
    pub(crate) generation: u64,
    pub(crate) packet: u64,
    pub(crate) bytes: [u8; N],
    pub(crate) len: usize,
    pub(crate) ecn: Option<crate::io::Codepoint>,
}
impl<const N: usize> Drop for AuthenticatedInput<'_, N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
/// Proof that every authenticated frame in this packet was retained by the
/// quarantine owner. This authorizes ACK accounting only after real Finished.
#[must_use]
pub struct StoredPacket<'scope> {
    pub(in crate::quic::early_data) scope: &'scope ApplicationKeyScope,
    pub(in crate::quic::early_data) generation: u64,
    pub(in crate::quic::early_data) packet: u64,
    pub(in crate::quic::early_data) ack_eliciting: bool,
    pub(in crate::quic::early_data) ecn: Option<crate::io::Codepoint>,
}
impl<'scope> StoredPacket<'scope> {
    pub(crate) fn ecn(&self) -> Option<crate::io::Codepoint> {
        self.ecn
    }
    pub(crate) fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn packet_number(&self) -> u64 {
        self.packet
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }
}

pub struct Range<const N: usize> {
    pub id: u64,
    pub offset: u64,
    pub fin: bool,
    pub(crate) bytes: [u8; N],
    pub(crate) len: usize,
}
impl<const N: usize> Drop for Range<N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
pub struct ControlBlock<const N: usize> {
    pub(crate) bytes: [u8; N],
    pub(crate) len: usize,
}
impl<const N: usize> Drop for ControlBlock<N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
pub struct Exchange<'scope, const N: usize> {
    pub(crate) input: Inbox<AuthenticatedInput<'scope, N>>,
    pub(in crate::quic::early_data) stored: Inbox<StoredPacket<'scope>>,
    pub(crate) finished: Inbox<FinishedAuthenticated<'scope>>,
    pub(crate) returned_finished: Inbox<FinishedAuthenticated<'scope>>,
    pub(crate) output: Inbox<Range<N>>,
    pub(crate) controls: Inbox<ControlBlock<N>>,
}
impl<const N: usize> Exchange<'_, N> {
    pub const fn new() -> Self {
        Self {
            input: Inbox::new(),
            stored: Inbox::new(),
            finished: Inbox::new(),
            returned_finished: Inbox::new(),
            output: Inbox::new(),
            controls: Inbox::new(),
        }
    }
}

impl<const N: usize> Default for Exchange<'_, N> {
    fn default() -> Self {
        Self::new()
    }
}

pub use hibana_tls::handshake::keys::Admission;
impl<'scope, const N: usize> AuthenticatedInput<'scope, N> {
    pub fn packet_number(&self) -> u64 {
        self.packet
    }
    pub fn from_authentication(
        receipt: hibana_tls::handshake::keys::AuthenticatedEarlyRead<'scope>,
        generation: u64,
        plaintext: &[u8],
        ecn: Option<crate::io::Codepoint>,
    ) -> Result<Self, Failure> {
        if plaintext.len() > N || !receipt.authenticates_plaintext(plaintext) {
            return Err(Failure::Binding);
        }
        let mut bytes = [0; N];
        bytes[..plaintext.len()].copy_from_slice(plaintext);
        Ok(Self {
            scope: receipt.scope(),
            generation,
            packet: receipt.packet_number(),
            bytes,
            len: plaintext.len(),
            ecn,
        })
    }
}
impl<const N: usize> Range<N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> ControlBlock<N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<'scope, const N: usize> Exchange<'scope, N> {
    pub fn take_stored(&self) -> Result<StoredPacket<'scope>, Failure> {
        self.stored.take().map_err(|_| Failure::Binding)
    }
    pub fn store_input(&self, value: AuthenticatedInput<'scope, N>) -> Result<(), Failure> {
        self.input.put(value).map_err(|_| Failure::Binding)
    }
    pub fn store_finished(&self, value: FinishedAuthenticated<'scope>) -> Result<(), Failure> {
        self.finished.put(value).map_err(|_| Failure::Binding)
    }
    pub fn take_finished(&self) -> Result<FinishedAuthenticated<'scope>, Failure> {
        self.returned_finished.take().map_err(|_| Failure::Binding)
    }
    pub fn take_range(&self) -> Result<Range<N>, Failure> {
        self.output.take().map_err(|_| Failure::Binding)
    }
    pub fn take_controls(&self) -> Result<ControlBlock<N>, Failure> {
        self.controls.take().map_err(|_| Failure::Binding)
    }
}
