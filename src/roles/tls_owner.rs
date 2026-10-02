//! A whole TLS Provider owned by one projected role, including its coupled
//! ApplicationKeys lifecycle. No mutable Provider or key handle escapes.
//!
//! Snapshots are copied observations, not permission to authenticate, mutate an
//! ACK ledger, or initiate an update. The owner still checks every operation.
//! The source of ConfirmHandshake/ValidatedAck must supply actual QUIC evidence.
//! Early opens carry separate affine evidence; the actual replay claim moves
//! into the receive quarantine and cannot authorize ordinary delivery.
//! Initial integration requires the affine integrity-budget loan below.
use super::{
    packet_protection::{Descriptor, Packet},
    protocol_tls as p,
};
use crate::{
    crypto,
    early_data::EarlyStatus,
    mailbox::{Receiver, Sender},
    runtime,
    tls::{self, Level, Provider},
};
use core::cell::RefCell;
use hibana::{Endpoint, EndpointError};
use zeroize::{Zeroize, Zeroizing};

pub struct Bytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Bytes<N> {
    pub fn new(input: &[u8]) -> Result<Self, tls::Error> {
        if input.len() > N {
            return Err(tls::Error::Capacity);
        }
        let mut result = Self {
            bytes: [0; N],
            len: input.len(),
        };
        result.bytes[..input.len()].copy_from_slice(input);
        Ok(result)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> Drop for Bytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot<const P: usize> {
    pub handshaking: bool,
    pub handshake_keys: bool,
    pub one_rtt_keys: bool,
    pub early_keys: bool,
    pub early_status: EarlyStatus,
    pub early_generation: Option<u64>,
    pub remembered_early_limits: Option<crate::early_data::RememberedLimits>,
    pub observations: tls::Observations,
    pub diagnostic: tls::FailureDiagnostic,
    pub key_phase: bool,
    pub send_generation: u64,
    pub receive_generation: u64,
    pub negotiated_group: Option<u16>,
    parameters: [u8; P],
    parameters_len: Option<usize>,
}
impl<const P: usize> Snapshot<P> {
    pub fn peer_parameters(&self) -> Option<&[u8]> {
        self.parameters_len.map(|n| &self.parameters[..n])
    }
}
fn snapshot<T: Provider, const P: usize>(provider: &T) -> Result<Snapshot<P>, Error> {
    let mut parameters = [0; P];
    let parameters_len = if let Some(bytes) = provider.peer_transport_parameters() {
        if bytes.len() > P {
            return Err(Error::ParameterCapacity);
        }
        parameters[..bytes.len()].copy_from_slice(bytes);
        Some(bytes.len())
    } else {
        None
    };
    Ok(Snapshot {
        handshaking: provider.is_handshaking(),
        handshake_keys: provider.has_keys(Level::Handshake),
        one_rtt_keys: provider.has_keys(Level::OneRtt),
        early_keys: provider.has_early_keys(),
        early_status: provider.early_status(),
        early_generation: provider.early_generation(),
        remembered_early_limits: provider.remembered_early_limits(),
        observations: provider.observations(),
        diagnostic: tls::FailureDiagnostic::capture(provider),
        key_phase: provider.key_phase(),
        send_generation: provider.key_generation(),
        receive_generation: provider.receive_key_generation(),
        negotiated_group: provider.negotiated_group(),
        parameters,
        parameters_len,
    })
}
/// Private identity and non-Clone budget; no arbitrary budget can be inserted
/// into the ReturnIntegrity command. The client exposes only a consuming loan.
pub struct IntegrityGrant {
    descriptor: Descriptor,
    budget: crypto::IntegrityBudget,
}
pub struct IntegrityReturn(IntegrityGrant);
/// Affine evidence minted only after the owned provider authenticates a packet.
#[derive(Debug)]
pub struct OpenReceipt {
    descriptor: Descriptor,
    level: Level,
    packet_number: u64,
    key_generation: u64,
    plaintext_digest: [u8; 32],
}
impl OpenReceipt {
    pub const fn generation(&self) -> u64 {
        self.descriptor.generation
    }
    pub const fn operation_id(&self) -> u64 {
        self.descriptor.sequence
    }
    pub const fn level(&self) -> Level {
        self.level
    }
    pub const fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub const fn key_generation(&self) -> u64 {
        self.key_generation
    }
    pub fn authenticates_plaintext(&self, plaintext: &[u8]) -> bool {
        self.plaintext_digest == super::sealed_packet::plaintext_digest(plaintext)
    }
}
/// Distinct early evidence cannot be substituted for an ordinary Open receipt.
#[derive(Debug)]
pub struct EarlyOpenReceipt {
    descriptor: Descriptor,
    packet_number: u64,
    plaintext_digest: [u8; 32],
}
impl EarlyOpenReceipt {
    pub const fn generation(&self) -> u64 {
        self.descriptor.generation
    }
    pub const fn operation_id(&self) -> u64 {
        self.descriptor.sequence
    }
    pub const fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub fn authenticates_plaintext(&self, plaintext: &[u8]) -> bool {
        self.plaintext_digest == super::sealed_packet::plaintext_digest(plaintext)
    }
}
#[derive(Debug)]
pub struct FinishedReceipt {
    descriptor: Descriptor,
    peer_parameters_digest: Option<[u8; 32]>,
    early_status: EarlyStatus,
}
impl FinishedReceipt {
    pub const fn generation(&self) -> u64 {
        self.descriptor.generation
    }
    pub const fn operation_id(&self) -> u64 {
        self.descriptor.sequence
    }
    /// Binds this actual Finished transition to the exact peer parameter bytes
    /// observed by its TLS owner. A copied Snapshot is not this authority.
    pub fn authenticates_peer_parameters(&self, parameters: &[u8]) -> bool {
        self.peer_parameters_digest == Some(peer_parameters_digest(parameters))
    }
    pub const fn early_status(&self) -> EarlyStatus {
        self.early_status
    }
    fn from_provider<T: Provider>(descriptor: Descriptor, provider: &T) -> Self {
        Self {
            descriptor,
            peer_parameters_digest: provider
                .peer_transport_parameters()
                .map(peer_parameters_digest),
            early_status: provider.early_status(),
        }
    }
}
fn peer_parameters_digest(parameters: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"hibana-quic:verified-peer-parameters:v1\0");
    digest.update((parameters.len() as u64).to_be_bytes());
    digest.update(parameters);
    digest.finalize().into()
}
pub struct OpenedEarlyPacket<const N: usize> {
    pub packet: Packet<N>,
    pub receipt: EarlyOpenReceipt,
}

/// One-time client early-send permission from the actual restored TLS keys.
#[derive(Debug)]
pub struct EarlySendReady {
    generation: u64,
    early_generation: u64,
    limits: crate::early_data::RememberedLimits,
}
impl EarlySendReady {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn early_generation(&self) -> u64 {
        self.early_generation
    }
    pub const fn remembered_limits(&self) -> crate::early_data::RememberedLimits {
        self.limits
    }
}
fn early_send_ready<T: Provider>(provider: &T, generation: u64) -> Option<EarlySendReady> {
    if !provider.has_early_keys() || provider.early_status() != EarlyStatus::Offered {
        return None;
    }
    Some(EarlySendReady {
        generation,
        early_generation: provider.early_generation()?,
        limits: provider.remembered_early_limits()?,
    })
}
/// The server's actual burned replay claim and its authenticated ticket limits
/// move together; callers cannot replace the limits beside a valid claim.
pub struct EarlyReplayGrant {
    generation: u64,
    early_generation: u64,
    claim: crate::early_data::ReplayClaim,
    limits: crate::early_data::RememberedLimits,
}
impl EarlyReplayGrant {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn early_generation(&self) -> u64 {
        self.early_generation
    }
    pub const fn remembered_limits(&self) -> crate::early_data::RememberedLimits {
        self.limits
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::early_data::ReplayClaim,
        crate::early_data::RememberedLimits,
    ) {
        (self.claim, self.limits)
    }
}
/// Revokes sent 0-RTT accounting only after a real TLS rejection or a transport
/// Retry already validated against the current connection's Retry policy.
#[derive(Debug)]
pub struct EarlyRejectedGrant {
    generation: u64,
}
impl EarlyRejectedGrant {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn after_validated_retry(generation: u64) -> Self {
        Self { generation }
    }
}

pub enum Command<const N: usize> {
    ReceiveCrypto {
        level: Level,
        bytes: Bytes<N>,
    },
    TakeCryptoFlight {
        max_len: usize,
    },
    OpenEarly(Packet<N>),
    SealEarly(Packet<N>),
    EarlyHeaderMask {
        local: bool,
        sample: [u8; 16],
    },
    TakeEarlyReplayClaim,
    DiscardEarly,
    OpenHandshake(Packet<N>),
    OpenOneRtt {
        packet: Packet<N>,
        phase: bool,
        now: u64,
        pto: u64,
    },
    SealHandshake(Packet<N>),
    SealOneRtt(Packet<N>),
    HeaderMask {
        level: Level,
        local: bool,
        sample: [u8; 16],
    },
    ConfirmHandshake,
    ValidatedAck {
        sent_pn: u64,
        received_generation: u64,
        now: u64,
        pto: u64,
    },
    MaintainKeys {
        now: u64,
        pto: u64,
    },
    InitiateUpdate {
        now: u64,
        pto: u64,
    },
    DiscardHandshake,
    LoanIntegrity,
    ReturnIntegrity(IntegrityReturn),
    Retire,
}
pub enum Outcome<const N: usize> {
    Installed {
        early_send: Option<EarlySendReady>,
    },
    CryptoAccepted {
        finished: Option<FinishedReceipt>,
        early_rejected: Option<EarlyRejectedGrant>,
    },
    CryptoOutput {
        level: Level,
        bytes: Bytes<N>,
    },
    NoCryptoOutput,
    EarlyOpened(OpenedEarlyPacket<N>),
    EarlyReplayClaim(EarlyReplayGrant),
    NoEarlyReplayClaim,
    EarlyDiscarded,
    Opened {
        packet: Packet<N>,
        generation: u64,
        key_updated: bool,
        receipt: OpenReceipt,
    },
    Sealed(super::sealed_packet::SealedPacket<N>),
    HeaderMask([u8; 5]),
    HandshakeConfirmed,
    AckApplied,
    KeysMaintained,
    KeyUpdated,
    HandshakeDiscarded,
    Failed(tls::Error),
    IntegrityGranted(IntegrityGrant),
    LoanUnavailable,
    IntegrityRestored,
    Retired,
}
pub struct Reply<const N: usize, const P: usize> {
    pub descriptor: Descriptor,
    pub snapshot: Snapshot<P>,
    pub outcome: Outcome<N>,
}
struct Request<const N: usize> {
    descriptor: Descriptor,
    command: Command<N>,
}
pub struct Exchange<const N: usize, const P: usize> {
    request: RefCell<Option<Request<N>>>,
    reply: RefCell<Option<Reply<N, P>>>,
}
impl<const N: usize, const P: usize> Exchange<N, P> {
    pub const fn new() -> Self {
        Self {
            request: RefCell::new(None),
            reply: RefCell::new(None),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.request.borrow().is_none() && self.reply.borrow().is_none()
    }
    fn put_request(&self, request: Request<N>) -> Result<(), Error> {
        let mut slot = self.request.borrow_mut();
        if slot.is_some() || self.reply.borrow().is_some() {
            return Err(Error::OccupiedSlot);
        }
        *slot = Some(request);
        Ok(())
    }
    fn take_request(&self, wire: [u8; 16]) -> Result<Request<N>, Error> {
        let request = self.request.borrow_mut().take().ok_or(Error::MissingSlot)?;
        if encode(request.descriptor) != wire {
            return Err(Error::Correlation);
        }
        Ok(request)
    }
    fn put_reply<T: Provider>(
        &self,
        provider: &T,
        descriptor: Descriptor,
        outcome: Outcome<N>,
    ) -> Result<(), Error> {
        let reply = Reply {
            descriptor,
            snapshot: snapshot(provider)?,
            outcome,
        };
        let mut slot = self.reply.borrow_mut();
        if slot.is_some() {
            return Err(Error::OccupiedSlot);
        }
        *slot = Some(reply);
        Ok(())
    }
    fn take_reply(&self, descriptor: Descriptor) -> Result<Reply<N, P>, Error> {
        let reply = self.reply.borrow_mut().take().ok_or(Error::MissingSlot)?;
        if reply.descriptor != descriptor {
            return Err(Error::Correlation);
        }
        Ok(reply)
    }
}
impl<const N: usize, const P: usize> Default for Exchange<N, P> {
    fn default() -> Self {
        Self::new()
    }
}
struct Clear<'a, const N: usize, const P: usize>(&'a Exchange<N, P>);
impl<const N: usize, const P: usize> Drop for Clear<'_, N, P> {
    fn drop(&mut self) {
        self.0.request.borrow_mut().take();
        self.0.reply.borrow_mut().take();
    }
}
#[derive(Debug)]
pub enum Error {
    Hibana(EndpointError),
    CommandsClosed,
    RepliesClosed,
    OccupiedSlot,
    MissingSlot,
    Correlation,
    UnexpectedCommand,
    UnexpectedLabel(u8),
    SequenceExhausted,
    ParameterCapacity,
    PacketBounds,
    IntegrityUnavailable,
}
impl From<EndpointError> for Error {
    fn from(e: EndpointError) -> Self {
        Self::Hibana(e)
    }
}
fn encode(d: Descriptor) -> [u8; 16] {
    let mut b = [0; 16];
    b[..8].copy_from_slice(&d.generation.to_be_bytes());
    b[8..].copy_from_slice(&d.sequence.to_be_bytes());
    b
}
fn same(observed: [u8; 16], expected: [u8; 16]) -> Result<(), Error> {
    if observed == expected {
        Ok(())
    } else {
        Err(Error::Correlation)
    }
}
/// All endpoint values stay with the encompassing global-session owner.
pub async fn run_borrowed<
    T: Provider,
    const C: u8,
    const O: u8,
    const N: usize,
    const P: usize,
    const Q: usize,
    const R: usize,
>(
    client: &mut Endpoint<'_, C>,
    owner: &mut Endpoint<'_, O>,
    generation: u64,
    provider: T,
    commands: Receiver<'_, '_, Command<N>, Q>,
    replies: Sender<'_, '_, Reply<N, P>, R>,
    exchange: &mut Exchange<N, P>,
) -> Result<(), Error> {
    if !exchange.is_empty() {
        return Err(Error::OccupiedSlot);
    }
    let exchange = &*exchange;
    let _clear = Clear(exchange);
    let mut command = core::pin::pin!(command_role(
        client, generation, commands, replies, exchange
    ));
    let mut owner = core::pin::pin!(provider_role(owner, generation, provider, exchange));
    runtime::TaskSet::new([command.as_mut(), owner.as_mut()]).await
}

async fn command_role<
    const C: u8,
    const N: usize,
    const P: usize,
    const Q: usize,
    const R: usize,
>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    mut commands: Receiver<'_, '_, Command<N>, Q>,
    mut replies: Sender<'_, '_, Reply<N, P>, R>,
    exchange: &Exchange<N, P>,
) -> Result<(), Error> {
    let installed = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(installed);
    endpoint.send::<p::Install>(&wire).await?;
    same(endpoint.recv::<p::Installed>().await?, wire)?;
    replies
        .send(exchange.take_reply(installed)?)
        .await
        .map_err(|_| Error::RepliesClosed)?;
    let mut sequence = 1u64;
    loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        let wire = encode(descriptor);
        match command {
            command @ Command::ReceiveCrypto { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::CryptoInput>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::CRYPTO_ACCEPTED => branch.recv::<p::CryptoAccepted>().await?,
                    p::CRYPTO_REJECTED => branch.recv::<p::CryptoRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::TakeCryptoFlight { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::CryptoOutput>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::CRYPTO_OUTPUT_READY => branch.recv::<p::CryptoOutputReady>().await?,
                    p::NO_CRYPTO_OUTPUT => branch.recv::<p::NoCryptoOutput>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::OpenEarly(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::OpenEarly>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::EARLY_OPENED => branch.recv::<p::EarlyOpened>().await?,
                    p::EARLY_OPEN_REJECTED => branch.recv::<p::EarlyOpenRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::SealEarly(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::SealEarly>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::EARLY_SEALED => branch.recv::<p::EarlySealed>().await?,
                    p::EARLY_SEAL_REJECTED => branch.recv::<p::EarlySealRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::EarlyHeaderMask { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::EarlyHeaderMask>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::EARLY_HEADER_MASK_READY => branch.recv::<p::EarlyHeaderMaskReady>().await?,
                    p::EARLY_HEADER_MASK_REJECTED => {
                        branch.recv::<p::EarlyHeaderMaskRejected>().await?
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::TakeEarlyReplayClaim => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::TakeEarlyReplayClaim>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::EARLY_REPLAY_CLAIM => branch.recv::<p::EarlyReplayClaim>().await?,
                    p::NO_EARLY_REPLAY_CLAIM => branch.recv::<p::NoEarlyReplayClaim>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::DiscardEarly => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::DiscardEarly>(&wire).await?;
                same(endpoint.recv::<p::EarlyDiscarded>().await?, wire)?;
            }
            command @ Command::OpenHandshake(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::OpenHandshake>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HANDSHAKE_OPENED => branch.recv::<p::HandshakeOpened>().await?,
                    p::HANDSHAKE_OPEN_REJECTED => branch.recv::<p::HandshakeOpenRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::OpenOneRtt { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::OpenOneRtt>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::ONE_RTT_OPENED => branch.recv::<p::OneRttOpened>().await?,
                    p::ONE_RTT_OPEN_REJECTED => branch.recv::<p::OneRttOpenRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::SealHandshake(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::SealHandshake>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HANDSHAKE_SEALED => branch.recv::<p::HandshakeSealed>().await?,
                    p::HANDSHAKE_SEAL_REJECTED => branch.recv::<p::HandshakeSealRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::SealOneRtt(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::SealOneRtt>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::ONE_RTT_SEALED => branch.recv::<p::OneRttSealed>().await?,
                    p::ONE_RTT_SEAL_REJECTED => branch.recv::<p::OneRttSealRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::HeaderMask { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::HeaderMask>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HEADER_MASK_READY => branch.recv::<p::HeaderMaskReady>().await?,
                    p::HEADER_MASK_REJECTED => branch.recv::<p::HeaderMaskRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::ConfirmHandshake => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::ConfirmHandshake>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HANDSHAKE_CONFIRMED => branch.recv::<p::HandshakeConfirmed>().await?,
                    p::CONFIRMATION_REJECTED => branch.recv::<p::ConfirmationRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::ValidatedAck { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::ValidatedAck>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::ACK_APPLIED => branch.recv::<p::AckApplied>().await?,
                    p::ACK_REJECTED => branch.recv::<p::AckRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::MaintainKeys { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::MaintainKeys>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::KEYS_MAINTAINED => branch.recv::<p::KeysMaintained>().await?,
                    p::MAINTENANCE_REJECTED => branch.recv::<p::MaintenanceRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::InitiateUpdate { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::InitiateUpdate>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::KEY_UPDATED => branch.recv::<p::KeyUpdated>().await?,
                    p::UPDATE_REJECTED => branch.recv::<p::UpdateRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::DiscardHandshake => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::DiscardHandshake>(&wire).await?;
                same(endpoint.recv::<p::HandshakeDiscarded>().await?, wire)?;
            }
            command @ Command::LoanIntegrity => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::LoanIntegrity>(&wire).await?;
                let branch = endpoint.offer().await?;
                let granted = match branch.label() {
                    p::INTEGRITY_GRANTED => {
                        same(branch.recv::<p::IntegrityGranted>().await?, wire)?;
                        true
                    }
                    p::LOAN_UNAVAILABLE => {
                        same(branch.recv::<p::LoanUnavailable>().await?, wire)?;
                        false
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                let reply = exchange.take_reply(descriptor)?;
                endpoint.send::<p::ResultTaken>(&wire).await?;
                replies
                    .send(reply)
                    .await
                    .map_err(|_| Error::RepliesClosed)?;
                sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
                if granted {
                    // No crypto operation can be admitted in the middle of the loan. The owner
                    // is parked at the corresponding typed Return, with an exhausted budget.
                    let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
                    let command @ Command::ReturnIntegrity(_) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let returned = Descriptor {
                        generation,
                        sequence,
                    };
                    let returned_wire = encode(returned);
                    exchange.put_request(Request {
                        descriptor: returned,
                        command,
                    })?;
                    endpoint
                        .send::<p::IntegrityReturned>(&returned_wire)
                        .await?;
                    same(
                        endpoint.recv::<p::IntegrityRestored>().await?,
                        returned_wire,
                    )?;
                    let reply = exchange.take_reply(returned)?;
                    endpoint.send::<p::ResultTaken>(&returned_wire).await?;
                    replies
                        .send(reply)
                        .await
                        .map_err(|_| Error::RepliesClosed)?;
                    sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
                }
                runtime::yield_now().await;
                continue;
            }
            command @ Command::Retire => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                commands.close();
                endpoint.send::<p::RetireRequested>(&wire).await?;
                same(endpoint.recv::<p::Retired>().await?, wire)?;
                endpoint.send::<p::RetirementAcknowledged>(&wire).await?;
                replies
                    .send(exchange.take_reply(descriptor)?)
                    .await
                    .map_err(|_| Error::RepliesClosed)?;
                return Ok(());
            }
            Command::ReturnIntegrity(_) => return Err(Error::UnexpectedCommand),
        }
        let reply = exchange.take_reply(descriptor)?;
        endpoint.send::<p::ResultTaken>(&wire).await?;
        replies
            .send(reply)
            .await
            .map_err(|_| Error::RepliesClosed)?;
        sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        runtime::yield_now().await;
    }
}

async fn provider_role<T: Provider, const O: u8, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, O>,
    generation: u64,
    mut provider: T,
    exchange: &Exchange<N, P>,
) -> Result<(), Error> {
    let installed = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(installed);
    same(endpoint.recv::<p::Install>().await?, wire)?;
    exchange.put_reply(
        &provider,
        installed,
        Outcome::Installed {
            early_send: early_send_ready(&provider, generation),
        },
    )?;
    endpoint.send::<p::Installed>(&wire).await?;
    loop {
        let branch = endpoint.offer().await?;
        let completed;
        match branch.label() {
            p::CRYPTO_INPUT => {
                let wire = branch.recv::<p::CryptoInput>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::ReceiveCrypto { level, bytes } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let previous_early = provider.early_status();
                    let was_handshaking = provider.is_handshaking();
                    match provider.receive(level, bytes.as_bytes()) {
                        Ok(()) => {
                            let finished = (was_handshaking && !provider.is_handshaking())
                                .then(|| FinishedReceipt::from_provider(descriptor, &provider));
                            let early_rejected = (previous_early != EarlyStatus::Rejected
                                && provider.early_status() == EarlyStatus::Rejected)
                                .then_some(EarlyRejectedGrant { generation });
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::CryptoAccepted {
                                    finished,
                                    early_rejected,
                                },
                            )?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::CryptoAccepted>(&wire).await?;
                } else {
                    endpoint.send::<p::CryptoRejected>(&wire).await?;
                }
            }
            p::CRYPTO_OUTPUT => {
                let wire = branch.recv::<p::CryptoOutput>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::TakeCryptoFlight { max_len } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let mut bytes = Bytes {
                        bytes: [0; N],
                        len: 0,
                    };
                    if max_len > N {
                        return Err(Error::PacketBounds);
                    }
                    match provider.transmit(&mut bytes.bytes[..max_len]) {
                        Ok(Some(output)) => {
                            if output.len > N {
                                return Err(Error::PacketBounds);
                            }
                            bytes.len = output.len;
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::CryptoOutput {
                                    level: output.level,
                                    bytes,
                                },
                            )?;
                            true
                        }
                        Ok(None) => {
                            exchange.put_reply(&provider, descriptor, Outcome::NoCryptoOutput)?;
                            false
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::CryptoOutputReady>(&wire).await?;
                } else {
                    endpoint.send::<p::NoCryptoOutput>(&wire).await?;
                }
            }
            p::OPEN_EARLY => {
                let wire = branch.recv::<p::OpenEarly>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::OpenEarly(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..len].copy_from_slice(packet.body());
                    let header = packet.header();
                    match provider.open_early(pn, header, &mut body[..len]) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            if provider.early_generation() != Some(generation) {
                                return Err(Error::Correlation);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::EarlyOpened(OpenedEarlyPacket {
                                    packet,
                                    receipt: EarlyOpenReceipt {
                                        descriptor,
                                        packet_number: pn,
                                        plaintext_digest: super::sealed_packet::plaintext_digest(
                                            &body[..len],
                                        ),
                                    },
                                }),
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::EarlyOpened>(&wire).await?;
                } else {
                    endpoint.send::<p::EarlyOpenRejected>(&wire).await?;
                }
            }
            p::SEAL_EARLY => {
                let wire = branch.recv::<p::SealEarly>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::SealEarly(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let plaintext_len = packet.body().len();
                    let plaintext_digest = super::sealed_packet::plaintext_digest(packet.body());
                    let mut body = Zeroizing::new([0; N]);
                    body[..plaintext_len].copy_from_slice(packet.body());
                    let header = packet.header();
                    let capacity = N - header.len();
                    match provider.seal_early(pn, header, &mut body[..capacity], plaintext_len) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::Sealed(super::sealed_packet::SealedPacket::from_owner(
                                    packet,
                                    descriptor,
                                    crypto::KeyKind::ZeroRtt,
                                    plaintext_digest,
                                )),
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::EarlySealed>(&wire).await?;
                } else {
                    endpoint.send::<p::EarlySealRejected>(&wire).await?;
                }
            }
            p::EARLY_HEADER_MASK => {
                let wire = branch.recv::<p::EarlyHeaderMask>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::EarlyHeaderMask { local, sample } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.early_header_mask(local, &sample) {
                        Ok(mask) => {
                            exchange.put_reply(&provider, descriptor, Outcome::HeaderMask(mask))?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::EarlyHeaderMaskReady>(&wire).await?;
                } else {
                    endpoint.send::<p::EarlyHeaderMaskRejected>(&wire).await?;
                }
            }
            p::TAKE_EARLY_REPLAY_CLAIM => {
                let wire = branch.recv::<p::TakeEarlyReplayClaim>().await?;
                completed = wire;
                let claimed = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::TakeEarlyReplayClaim = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    if let Some(claim) = provider.take_early_replay_claim() {
                        let limits = provider
                            .remembered_early_limits()
                            .ok_or(Error::Correlation)?;
                        let early_generation =
                            provider.early_generation().ok_or(Error::Correlation)?;
                        if claim.generation() != early_generation {
                            return Err(Error::Correlation);
                        }
                        let grant = EarlyReplayGrant {
                            generation,
                            early_generation,
                            claim,
                            limits,
                        };
                        exchange.put_reply(
                            &provider,
                            descriptor,
                            Outcome::EarlyReplayClaim(grant),
                        )?;
                        true
                    } else {
                        exchange.put_reply(&provider, descriptor, Outcome::NoEarlyReplayClaim)?;
                        false
                    }
                };
                if claimed {
                    endpoint.send::<p::EarlyReplayClaim>(&wire).await?;
                } else {
                    endpoint.send::<p::NoEarlyReplayClaim>(&wire).await?;
                }
            }
            p::DISCARD_EARLY => {
                let wire = branch.recv::<p::DiscardEarly>().await?;
                completed = wire;
                {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::DiscardEarly = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    provider.discard_early_keys();
                    exchange.put_reply(&provider, descriptor, Outcome::EarlyDiscarded)?;
                }
                endpoint.send::<p::EarlyDiscarded>(&wire).await?;
            }
            p::OPEN_HANDSHAKE => {
                let wire = branch.recv::<p::OpenHandshake>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::OpenHandshake(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..len].copy_from_slice(packet.body());
                    let header = packet.header();
                    match provider.open(Level::Handshake, pn, header, &mut body[..len]) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::Opened {
                                    packet,
                                    generation: 0,
                                    key_updated: false,
                                    receipt: OpenReceipt {
                                        descriptor,
                                        level: Level::Handshake,
                                        packet_number: pn,
                                        key_generation: 0,
                                        plaintext_digest: super::sealed_packet::plaintext_digest(
                                            &body[..len],
                                        ),
                                    },
                                },
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HandshakeOpened>(&wire).await?;
                } else {
                    endpoint.send::<p::HandshakeOpenRejected>(&wire).await?;
                }
            }
            p::OPEN_ONE_RTT => {
                let wire = branch.recv::<p::OpenOneRtt>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::OpenOneRtt {
                        packet,
                        phase,
                        now,
                        pto,
                    } = command
                    else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..len].copy_from_slice(packet.body());
                    let header = packet.header();
                    match provider.open_one_rtt(pn, phase, header, &mut body[..len], now, pto) {
                        Ok(opened) => {
                            if opened.len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..opened.len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::Opened {
                                    packet,
                                    generation: opened.generation,
                                    key_updated: opened.key_updated,
                                    receipt: OpenReceipt {
                                        descriptor,
                                        level: Level::OneRtt,
                                        packet_number: pn,
                                        key_generation: opened.generation,
                                        plaintext_digest: super::sealed_packet::plaintext_digest(
                                            &body[..opened.len],
                                        ),
                                    },
                                },
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::OneRttOpened>(&wire).await?;
                } else {
                    endpoint.send::<p::OneRttOpenRejected>(&wire).await?;
                }
            }
            p::SEAL_HANDSHAKE => {
                let wire = branch.recv::<p::SealHandshake>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::SealHandshake(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let plaintext_len = packet.body().len();
                    let plaintext_digest = super::sealed_packet::plaintext_digest(packet.body());
                    let mut body = Zeroizing::new([0; N]);
                    body[..plaintext_len].copy_from_slice(packet.body());
                    let header = packet.header();
                    let capacity = N - header.len();
                    match provider.seal(
                        Level::Handshake,
                        pn,
                        header,
                        &mut body[..capacity],
                        plaintext_len,
                    ) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::Sealed(super::sealed_packet::SealedPacket::from_owner(
                                    packet,
                                    descriptor,
                                    crypto::KeyKind::Handshake,
                                    plaintext_digest,
                                )),
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HandshakeSealed>(&wire).await?;
                } else {
                    endpoint.send::<p::HandshakeSealRejected>(&wire).await?;
                }
            }
            p::SEAL_ONE_RTT => {
                let wire = branch.recv::<p::SealOneRtt>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::SealOneRtt(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let plaintext_len = packet.body().len();
                    let plaintext_digest = super::sealed_packet::plaintext_digest(packet.body());
                    let mut body = Zeroizing::new([0; N]);
                    body[..plaintext_len].copy_from_slice(packet.body());
                    let header = packet.header();
                    let capacity = N - header.len();
                    match provider.seal(
                        Level::OneRtt,
                        pn,
                        header,
                        &mut body[..capacity],
                        plaintext_len,
                    ) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::Sealed(super::sealed_packet::SealedPacket::from_owner(
                                    packet,
                                    descriptor,
                                    crypto::KeyKind::OneRtt,
                                    plaintext_digest,
                                )),
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::OneRttSealed>(&wire).await?;
                } else {
                    endpoint.send::<p::OneRttSealRejected>(&wire).await?;
                }
            }
            p::HEADER_MASK => {
                let wire = branch.recv::<p::HeaderMask>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::HeaderMask {
                        level,
                        local,
                        sample,
                    } = command
                    else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.header_mask(level, local, &sample) {
                        Ok(mask) => {
                            exchange.put_reply(&provider, descriptor, Outcome::HeaderMask(mask))?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HeaderMaskReady>(&wire).await?;
                } else {
                    endpoint.send::<p::HeaderMaskRejected>(&wire).await?;
                }
            }
            p::CONFIRM_HANDSHAKE => {
                let wire = branch.recv::<p::ConfirmHandshake>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::ConfirmHandshake = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.confirm_handshake() {
                        Ok(()) => {
                            exchange.put_reply(
                                &provider,
                                descriptor,
                                Outcome::HandshakeConfirmed,
                            )?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HandshakeConfirmed>(&wire).await?;
                } else {
                    endpoint.send::<p::ConfirmationRejected>(&wire).await?;
                }
            }
            p::VALIDATED_ACK => {
                let wire = branch.recv::<p::ValidatedAck>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::ValidatedAck {
                        sent_pn,
                        received_generation,
                        now,
                        pto,
                    } = command
                    else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.acknowledge_one_rtt(sent_pn, received_generation, now, pto) {
                        Ok(()) => {
                            exchange.put_reply(&provider, descriptor, Outcome::AckApplied)?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::AckApplied>(&wire).await?;
                } else {
                    endpoint.send::<p::AckRejected>(&wire).await?;
                }
            }
            p::MAINTAIN_KEYS => {
                let wire = branch.recv::<p::MaintainKeys>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::MaintainKeys { now, pto } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.maintain_keys(now, pto) {
                        Ok(()) => {
                            exchange.put_reply(&provider, descriptor, Outcome::KeysMaintained)?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::KeysMaintained>(&wire).await?;
                } else {
                    endpoint.send::<p::MaintenanceRejected>(&wire).await?;
                }
            }
            p::INITIATE_UPDATE => {
                let wire = branch.recv::<p::InitiateUpdate>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::InitiateUpdate { now, pto } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.initiate_key_update(now, pto) {
                        Ok(()) => {
                            exchange.put_reply(&provider, descriptor, Outcome::KeyUpdated)?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(&provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::KeyUpdated>(&wire).await?;
                } else {
                    endpoint.send::<p::UpdateRejected>(&wire).await?;
                }
            }
            p::DISCARD_HANDSHAKE => {
                let wire = branch.recv::<p::DiscardHandshake>().await?;
                completed = wire;
                {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::DiscardHandshake = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    provider.discard_keys(Level::Handshake);
                    exchange.put_reply(&provider, descriptor, Outcome::HandshakeDiscarded)?;
                }
                endpoint.send::<p::HandshakeDiscarded>(&wire).await?;
            }
            p::LOAN_INTEGRITY => {
                let wire = branch.recv::<p::LoanIntegrity>().await?;
                let loan;
                let granted = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::LoanIntegrity = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    loan = descriptor;
                    if let Some(budget) = provider.integrity_budget() {
                        let budget = budget.take_for_role();
                        exchange.put_reply(
                            &provider,
                            descriptor,
                            Outcome::IntegrityGranted(IntegrityGrant { descriptor, budget }),
                        )?;
                        true
                    } else {
                        exchange.put_reply(&provider, descriptor, Outcome::LoanUnavailable)?;
                        false
                    }
                };
                if granted {
                    endpoint.send::<p::IntegrityGranted>(&wire).await?;
                    same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
                    // This directly projected receive prevents ALL crypto while the unique
                    // budget is away; cancellation leaves the Provider's exhausted tombstone.
                    let returned_wire = endpoint.recv::<p::IntegrityReturned>().await?;
                    completed = returned_wire;
                    {
                        let Request {
                            descriptor,
                            command,
                        } = exchange.take_request(returned_wire)?;
                        if descriptor.generation != generation
                            || descriptor.sequence
                                != loan
                                    .sequence
                                    .checked_add(1)
                                    .ok_or(Error::SequenceExhausted)?
                        {
                            return Err(Error::Correlation);
                        }
                        let Command::ReturnIntegrity(IntegrityReturn(grant)) = command else {
                            return Err(Error::UnexpectedCommand);
                        };
                        if grant.descriptor != loan {
                            return Err(Error::Correlation);
                        }
                        *provider
                            .integrity_budget()
                            .ok_or(Error::IntegrityUnavailable)? = grant.budget;
                        exchange.put_reply(&provider, descriptor, Outcome::IntegrityRestored)?;
                    }
                    endpoint
                        .send::<p::IntegrityRestored>(&returned_wire)
                        .await?;
                } else {
                    completed = wire;
                    endpoint.send::<p::LoanUnavailable>(&wire).await?;
                }
            }
            p::RETIRE_REQUESTED => {
                let wire = branch.recv::<p::RetireRequested>().await?;
                {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::Retire = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    provider.discard_keys(Level::Handshake);
                    provider.discard_keys(Level::OneRtt);
                    provider.discard_early_keys();
                    exchange.put_reply(&provider, descriptor, Outcome::Retired)?;
                }
                drop(provider);
                endpoint.send::<p::Retired>(&wire).await?;
                same(endpoint.recv::<p::RetirementAcknowledged>().await?, wire)?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        same(endpoint.recv::<p::ResultTaken>().await?, completed)?;
        runtime::yield_now().await;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    Closed,
    Correlation,
    UnexpectedReply,
    SequenceExhausted,
    Capacity,
    InitialProtection,
}
pub struct OpenedPacket<const N: usize> {
    pub packet: Packet<N>,
    pub generation: u64,
    pub key_updated: bool,
    pub receipt: OpenReceipt,
}
/// Mailbox-facing capability only. Endpoint operations remain literal in the
/// two local roles above; cancellation closes the unique admission capability.
pub struct Client<'c, 's, const N: usize, const P: usize, const Q: usize, const R: usize> {
    commands: Sender<'c, 's, Command<N>, Q>,
    replies: Receiver<'c, 's, Reply<N, P>, R>,
    generation: u64,
    sequence: u64,
    snapshot: Snapshot<P>,
    finished: Option<FinishedReceipt>,
    early_send: Option<EarlySendReady>,
    early_rejected: Option<EarlyRejectedGrant>,
}
struct Pending<'a, 'c, 's, const N: usize, const P: usize, const Q: usize, const R: usize> {
    client: &'a mut Client<'c, 's, N, P, Q, R>,
    completed: bool,
}
impl<const N: usize, const P: usize, const Q: usize, const R: usize> Drop
    for Pending<'_, '_, '_, N, P, Q, R>
{
    fn drop(&mut self) {
        if !self.completed {
            self.client.close();
        }
    }
}
impl<'c, 's, const N: usize, const P: usize, const Q: usize, const R: usize>
    Client<'c, 's, N, P, Q, R>
{
    pub async fn connect(
        commands: Sender<'c, 's, Command<N>, Q>,
        mut replies: Receiver<'c, 's, Reply<N, P>, R>,
        generation: u64,
    ) -> Result<Self, ClientError> {
        let reply = replies.recv().await.map_err(|_| ClientError::Closed)?;
        if reply.descriptor
            != (Descriptor {
                generation,
                sequence: 0,
            })
        {
            return Err(ClientError::Correlation);
        }
        let Outcome::Installed { early_send } = reply.outcome else {
            return Err(ClientError::UnexpectedReply);
        };
        Ok(Self {
            commands,
            replies,
            generation,
            sequence: 1,
            snapshot: reply.snapshot,
            finished: None,
            early_send,
            early_rejected: None,
        })
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn take_finished_receipt(&mut self) -> Option<FinishedReceipt> {
        self.finished.take()
    }
    pub fn take_early_send_ready(&mut self) -> Option<EarlySendReady> {
        self.early_send.take()
    }
    pub fn take_early_rejected(&mut self) -> Option<EarlyRejectedGrant> {
        self.early_rejected.take()
    }
    pub fn snapshot(&self) -> &Snapshot<P> {
        &self.snapshot
    }
    pub fn close(&mut self) {
        self.commands.close();
        self.replies.close();
    }
    async fn request(&mut self, command: Command<N>) -> Result<Outcome<N>, ClientError> {
        let expected = Descriptor {
            generation: self.generation,
            sequence: self.sequence,
        };
        let Some(next) = self.sequence.checked_add(1) else {
            self.close();
            return Err(ClientError::SequenceExhausted);
        };
        let mut pending = Pending {
            client: self,
            completed: false,
        };
        pending
            .client
            .commands
            .send(command)
            .await
            .map_err(|_| ClientError::Closed)?;
        let reply = pending
            .client
            .replies
            .recv()
            .await
            .map_err(|_| ClientError::Closed)?;
        if reply.descriptor != expected {
            return Err(ClientError::Correlation);
        }
        pending.client.snapshot = reply.snapshot;
        pending.client.sequence = next;
        pending.completed = true;
        Ok(reply.outcome)
    }
    pub async fn receive_crypto(
        &mut self,
        level: Level,
        bytes: &[u8],
    ) -> Result<Result<(), tls::Error>, ClientError> {
        let bytes = match Bytes::new(bytes) {
            Ok(bytes) => bytes,
            Err(error) => return Ok(Err(error)),
        };
        match self
            .request(Command::ReceiveCrypto { level, bytes })
            .await?
        {
            Outcome::CryptoAccepted {
                finished,
                early_rejected,
            } => {
                if let Some(grant) = early_rejected {
                    if self.early_rejected.is_some() {
                        self.close();
                        return Err(ClientError::UnexpectedReply);
                    }
                    self.early_rejected = Some(grant);
                }
                if let Some(finished) = finished {
                    if self.finished.is_some() {
                        self.close();
                        return Err(ClientError::UnexpectedReply);
                    }
                    self.finished = Some(finished);
                }
                Ok(Ok(()))
            }
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    /// Preserve the transport's actual flight-fragment capacity (currently900
    /// bytes), even when packet-protection buffers have larger capacity.
    pub async fn take_crypto_flight(
        &mut self,
        max_len: usize,
    ) -> Result<Result<Option<(Level, Bytes<N>)>, tls::Error>, ClientError> {
        if max_len == 0 || max_len > N {
            return Ok(Err(tls::Error::Capacity));
        }
        match self.request(Command::TakeCryptoFlight { max_len }).await? {
            Outcome::CryptoOutput { level, bytes } => Ok(Ok(Some((level, bytes)))),
            Outcome::NoCryptoOutput => Ok(Ok(None)),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn open_early(
        &mut self,
        packet: Packet<N>,
    ) -> Result<Result<OpenedEarlyPacket<N>, tls::Error>, ClientError> {
        match self.request(Command::OpenEarly(packet)).await? {
            Outcome::EarlyOpened(opened) => Ok(Ok(opened)),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn seal_early(
        &mut self,
        packet: Packet<N>,
    ) -> Result<Result<super::sealed_packet::SealedPacket<N>, tls::Error>, ClientError> {
        match self.request(Command::SealEarly(packet)).await? {
            Outcome::Sealed(packet) => Ok(Ok(packet)),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn early_header_mask(
        &mut self,
        local: bool,
        sample: [u8; 16],
    ) -> Result<Result<[u8; 5], tls::Error>, ClientError> {
        match self
            .request(Command::EarlyHeaderMask { local, sample })
            .await?
        {
            Outcome::HeaderMask(mask) => Ok(Ok(mask)),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn discard_early_keys(&mut self) -> Result<Result<(), tls::Error>, ClientError> {
        match self.request(Command::DiscardEarly).await? {
            Outcome::EarlyDiscarded => Ok(Ok(())),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn take_early_replay_grant(
        &mut self,
    ) -> Result<Option<EarlyReplayGrant>, ClientError> {
        match self.request(Command::TakeEarlyReplayClaim).await? {
            Outcome::EarlyReplayClaim(claim) => Ok(Some(claim)),
            Outcome::NoEarlyReplayClaim => Ok(None),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    /// Transitional legacy coordinator bridge; the full early owner consumes
    /// take_early_replay_grant so ticket limits cannot be replaced.
    pub async fn take_early_replay_claim(
        &mut self,
    ) -> Result<Option<crate::early_data::ReplayClaim>, ClientError> {
        Ok(self
            .take_early_replay_grant()
            .await?
            .map(|grant| grant.into_parts().0))
    }
    pub async fn open_handshake(
        &mut self,
        packet: Packet<N>,
    ) -> Result<Result<OpenedPacket<N>, tls::Error>, ClientError> {
        match self.request(Command::OpenHandshake(packet)).await? {
            Outcome::Opened {
                packet,
                generation,
                key_updated,
                receipt,
            } => Ok(Ok(OpenedPacket {
                packet,
                generation,
                key_updated,
                receipt,
            })),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn open_one_rtt(
        &mut self,
        packet: Packet<N>,
        phase: bool,
        now: u64,
        pto: u64,
    ) -> Result<Result<OpenedPacket<N>, tls::Error>, ClientError> {
        match self
            .request(Command::OpenOneRtt {
                packet,
                phase,
                now,
                pto,
            })
            .await?
        {
            Outcome::Opened {
                packet,
                generation,
                key_updated,
                receipt,
            } => Ok(Ok(OpenedPacket {
                packet,
                generation,
                key_updated,
                receipt,
            })),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn seal_handshake(
        &mut self,
        packet: Packet<N>,
    ) -> Result<Result<super::sealed_packet::SealedPacket<N>, tls::Error>, ClientError> {
        match self.request(Command::SealHandshake(packet)).await? {
            Outcome::Sealed(packet) => Ok(Ok(packet)),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn seal_one_rtt(
        &mut self,
        packet: Packet<N>,
    ) -> Result<Result<super::sealed_packet::SealedPacket<N>, tls::Error>, ClientError> {
        match self.request(Command::SealOneRtt(packet)).await? {
            Outcome::Sealed(packet) => Ok(Ok(packet)),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn header_mask(
        &mut self,
        level: Level,
        local: bool,
        sample: [u8; 16],
    ) -> Result<Result<[u8; 5], tls::Error>, ClientError> {
        match self
            .request(Command::HeaderMask {
                level,
                local,
                sample,
            })
            .await?
        {
            Outcome::HeaderMask(mask) => Ok(Ok(mask)),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn confirm_handshake(&mut self) -> Result<Result<(), tls::Error>, ClientError> {
        match self.request(Command::ConfirmHandshake).await? {
            Outcome::HandshakeConfirmed => Ok(Ok(())),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn acknowledge_one_rtt(
        &mut self,
        sent_pn: u64,
        received_generation: u64,
        now: u64,
        pto: u64,
    ) -> Result<Result<(), tls::Error>, ClientError> {
        match self
            .request(Command::ValidatedAck {
                sent_pn,
                received_generation,
                now,
                pto,
            })
            .await?
        {
            Outcome::AckApplied => Ok(Ok(())),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn maintain_keys(
        &mut self,
        now: u64,
        pto: u64,
    ) -> Result<Result<(), tls::Error>, ClientError> {
        match self.request(Command::MaintainKeys { now, pto }).await? {
            Outcome::KeysMaintained => Ok(Ok(())),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn initiate_key_update(
        &mut self,
        now: u64,
        pto: u64,
    ) -> Result<Result<(), tls::Error>, ClientError> {
        match self.request(Command::InitiateUpdate { now, pto }).await? {
            Outcome::KeyUpdated => Ok(Ok(())),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn discard_handshake(&mut self) -> Result<Result<(), tls::Error>, ClientError> {
        match self.request(Command::DiscardHandshake).await? {
            Outcome::HandshakeDiscarded => Ok(Ok(())),
            Outcome::Failed(e) => Ok(Err(e)),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }

    pub async fn loan_integrity(
        &mut self,
    ) -> Result<Option<IntegrityLoan<'_, 'c, 's, N, P, Q, R>>, ClientError> {
        match self.request(Command::LoanIntegrity).await? {
            Outcome::IntegrityGranted(grant) => Ok(Some(IntegrityLoan {
                client: self,
                grant: Some(grant),
                returned: false,
            })),
            Outcome::LoanUnavailable => Ok(None),
            _ => {
                self.close();
                Err(ClientError::UnexpectedReply)
            }
        }
    }
    pub async fn retire_snapshot(mut self) -> Result<Snapshot<P>, ClientError> {
        match self.request(Command::Retire).await? {
            Outcome::Retired => Ok(self.snapshot),
            _ => Err(ClientError::UnexpectedReply),
        }
    }
    pub async fn retire(self) -> Result<(), ClientError> {
        self.retire_snapshot().await.map(|_| ())
    }
}
impl<const N: usize, const P: usize, const Q: usize, const R: usize> Drop
    for Client<'_, '_, N, P, Q, R>
{
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) mod initial_open_seal {
    pub trait Sealed {}
}

/// Sealed integration point for an owned Initial-key capability. Implementors
/// must return the exact moved budget on cryptographic outcomes; only trusted
/// crate-owned capabilities can implement this boundary.
pub trait InitialOpen<const B: usize>: initial_open_seal::Sealed {
    fn generation(&self) -> u64;
    fn open_with_budget(
        &mut self,
        packet: Packet<B>,
        budget: crypto::IntegrityBudget,
    ) -> impl core::future::Future<
        Output = Result<
            (
                Result<super::packet_protection::OpenedPacket<B>, crypto::Error>,
                crypto::IntegrityBudget,
            ),
            ClientError,
        >,
    >;
}
impl<const B: usize, const IQ: usize, const IR: usize> initial_open_seal::Sealed
    for super::client::KeyClient<'_, '_, B, IQ, IR>
{
}
impl<const B: usize, const IQ: usize, const IR: usize> InitialOpen<B>
    for super::client::KeyClient<'_, '_, B, IQ, IR>
{
    fn generation(&self) -> u64 {
        self.generation()
    }
    async fn open_with_budget(
        &mut self,
        packet: Packet<B>,
        budget: crypto::IntegrityBudget,
    ) -> Result<
        (
            Result<super::packet_protection::OpenedPacket<B>, crypto::Error>,
            crypto::IntegrityBudget,
        ),
        ClientError,
    > {
        self.open(packet, budget)
            .await
            .map_err(|_| ClientError::InitialProtection)
    }
}

/// Non-Clone affine loan. Its identity and actual budget are private. The only
/// operation taking its budget is the sealed concrete key client's Open; there
/// is no public replacement-budget command or arbitrary callback escape.
#[must_use = "return the same integrity loan or terminate the owner"]
pub struct IntegrityLoan<'a, 'c, 's, const N: usize, const P: usize, const Q: usize, const R: usize>
{
    client: &'a mut Client<'c, 's, N, P, Q, R>,
    grant: Option<IntegrityGrant>,
    returned: bool,
}
impl<const N: usize, const P: usize, const Q: usize, const R: usize>
    IntegrityLoan<'_, '_, '_, N, P, Q, R>
{
    pub fn failed_packets(&self) -> Result<u64, ClientError> {
        self.grant
            .as_ref()
            .map(|g| g.budget.failed_packets())
            .ok_or(ClientError::Closed)
    }
    pub async fn open_initial<const B: usize>(
        &mut self,
        key: &mut impl InitialOpen<B>,
        packet: Packet<B>,
    ) -> Result<Result<super::packet_protection::OpenedPacket<B>, crypto::Error>, ClientError> {
        if key.generation() != self.client.generation {
            self.client.close();
            return Err(ClientError::Correlation);
        }
        let grant = self.grant.take().ok_or(ClientError::Closed)?;
        let descriptor = grant.descriptor;
        let mut pending = Pending {
            client: self.client,
            completed: false,
        };
        let (result, budget) = key
            .open_with_budget(packet, grant.budget)
            .await
            .map_err(|_| ClientError::InitialProtection)?;
        self.grant = Some(IntegrityGrant { descriptor, budget });
        pending.completed = true;
        Ok(result)
    }
    pub async fn return_to_owner(mut self) -> Result<(), ClientError> {
        let grant = self.grant.take().ok_or(ClientError::Closed)?;
        match self
            .client
            .request(Command::ReturnIntegrity(IntegrityReturn(grant)))
            .await?
        {
            Outcome::IntegrityRestored => {
                self.returned = true;
                Ok(())
            }
            _ => Err(ClientError::UnexpectedReply),
        }
    }
}
impl<const N: usize, const P: usize, const Q: usize, const R: usize> Drop
    for IntegrityLoan<'_, '_, '_, N, P, Q, R>
{
    fn drop(&mut self) {
        if !self.returned {
            self.client.close();
        }
    }
}
