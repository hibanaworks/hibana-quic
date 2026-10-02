//! One real packet-key owner driven by projected async roles.
//!
//! Inputs contain owned bounded bytes, never borrowed packet pointers or an
//! asserted authentication result. Only the crypto actor chooses Opened versus
//! OpenFailed after actual AEAD. Failure-detail variants remain result data.
//! One connection-wide integrity
//! budget moves into every Open and the same value is returned in its outcome.
//!
//! This service does not check replay, authenticated reserved bits, peer
//! identity, key-update permission, or whole-connection QUIC/TLS reachability.
//! Initial keys in particular are publicly derivable. Header masks alone are
//! not authentication. The caller retains those numerical/policy obligations.
//!
//! The current Hibana roll is elastic, including after its continuation. Final
//! retirement is enforced by consuming the actor and closing its unique command
//! receiver, not by a graph-only terminality claim. No Rust key-lifetime ledger
//! duplicates the local async continuation. Drop/cancellation wipes the owned
//! key and packet slots; a cancelled Open loses its budget with this terminated
//! service, so the enclosing connection must not manufacture a replacement.

use super::protocol::{self, KEY_CLIENT, KEY_CRYPTO};
use crate::{
    crypto::{self, IntegrityBudget, PacketKey},
    mailbox::{Receiver, Sender},
    runtime,
};
use core::cell::RefCell;
use hibana::{Endpoint, EndpointError};
use zeroize::Zeroize;

/// A copied packet fragment: authenticated header followed by body and spare
/// capacity for a sealing tag. This type wipes its storage on drop.
pub struct Packet<const N: usize> {
    packet_number: u64,
    header_len: usize,
    body_len: usize,
    bytes: [u8; N],
}
impl<const N: usize> Packet<N> {
    pub fn new(packet_number: u64, header: &[u8], body: &[u8]) -> Result<Self, crypto::Error> {
        if packet_number > crypto::MAX_PACKET_NUMBER {
            return Err(crypto::Error::InvalidPacketNumber);
        }
        let len = header
            .len()
            .checked_add(body.len())
            .ok_or(crypto::Error::BufferTooSmall)?;
        if len > N {
            return Err(crypto::Error::BufferTooSmall);
        }
        if len > crypto::MAX_PROTECTED_PACKET_LEN {
            return Err(crypto::Error::PacketTooLarge);
        }
        let mut bytes = [0; N];
        bytes[..header.len()].copy_from_slice(header);
        bytes[header.len()..len].copy_from_slice(body);
        Ok(Self {
            packet_number,
            header_len: header.len(),
            body_len: body.len(),
            bytes,
        })
    }
    pub const fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub fn header(&self) -> &[u8] {
        &self.bytes[..self.header_len]
    }
    pub fn body(&self) -> &[u8] {
        &self.bytes[self.header_len..self.header_len + self.body_len]
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.header_len + self.body_len]
    }
}
impl<const N: usize> Drop for Packet<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub enum Command<const N: usize> {
    Open {
        packet: Packet<N>,
        budget: IntegrityBudget,
    },
    Seal(Packet<N>),
    HeaderMask([u8; crypto::HP_SAMPLE_LEN]),
    RekeyInitial {
        destination: InitialDestination,
        client: bool,
    },
    Retire,
}

/// A copied Initial destination CID. Retry policy and CID attribution remain
/// with the connection owner; this value only establishes the byte bound.
pub struct InitialDestination {
    bytes: [u8; 20],
    len: u8,
}
impl InitialDestination {
    pub fn new(bytes: &[u8]) -> Result<Self, crypto::Error> {
        if bytes.len() > 20 {
            return Err(crypto::Error::InvalidConnectionId);
        }
        let mut destination = Self {
            bytes: [0; 20],
            len: bytes.len() as u8,
        };
        destination.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(destination)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// These variants describe results, not caller-granted protocol authority.
pub enum Outcome<const N: usize> {
    Installed,
    Opened {
        packet: Packet<N>,
        budget: IntegrityBudget,
    },
    AuthenticationRejected {
        error: crypto::Error,
        budget: IntegrityBudget,
    },
    OpenFailed {
        error: crypto::Error,
        budget: IntegrityBudget,
    },
    Sealed(Packet<N>),
    SealFailed(crypto::Error),
    HeaderMask([u8; 5]),
    HeaderMaskFailed(crypto::Error),
    InitialRekeyed,
    InitialRekeyFailed(crypto::Error),
    Retired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub generation: u64,
    pub sequence: u64,
}
impl Descriptor {
    fn wire(self) -> [u8; 16] {
        let mut wire = [0; 16];
        wire[..8].copy_from_slice(&self.generation.to_be_bytes());
        wire[8..].copy_from_slice(&self.sequence.to_be_bytes());
        wire
    }
}
pub struct Reply<const N: usize> {
    pub descriptor: Descriptor,
    pub outcome: Outcome<N>,
}
struct Request<const N: usize> {
    descriptor: Descriptor,
    command: Command<N>,
}

/// One in-flight copied request/result arena. `run` exclusively borrows it, and
/// every RefCell borrow ends before an await. It contains no endpoint state.
pub struct Exchange<const N: usize> {
    request: RefCell<Option<Request<N>>>,
    reply: RefCell<Option<Reply<N>>>,
}
impl<const N: usize> Exchange<N> {
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
        if request.descriptor.wire() != wire {
            return Err(Error::DescriptorMismatch);
        }
        Ok(request)
    }
    fn put_reply(&self, reply: Reply<N>) -> Result<(), Error> {
        let mut slot = self.reply.borrow_mut();
        if slot.is_some() {
            return Err(Error::OccupiedSlot);
        }
        *slot = Some(reply);
        Ok(())
    }
    fn take_reply(&self, descriptor: Descriptor) -> Result<Reply<N>, Error> {
        let reply = self.reply.borrow_mut().take().ok_or(Error::MissingSlot)?;
        if reply.descriptor != descriptor {
            return Err(Error::DescriptorMismatch);
        }
        Ok(reply)
    }
}
impl<const N: usize> Default for Exchange<N> {
    fn default() -> Self {
        Self::new()
    }
}
struct ClearExchange<'a, const N: usize>(&'a Exchange<N>);
impl<const N: usize> Drop for ClearExchange<'_, N> {
    fn drop(&mut self) {
        self.0.request.borrow_mut().take();
        self.0.reply.borrow_mut().take();
    }
}
#[derive(Debug)]
pub enum Error {
    Hibana(EndpointError),
    Operation {
        stage: &'static str,
        sequence: u64,
        error: EndpointError,
    },
    CommandsClosed,
    RepliesClosed,
    OccupiedSlot,
    MissingSlot,
    DescriptorMismatch,
    CommandMismatch,
    UnexpectedLabel(u8),
    SequenceExhausted,
    InvalidKey(crypto::Error),
}
impl From<EndpointError> for Error {
    fn from(error: EndpointError) -> Self {
        Self::Hibana(error)
    }
}

/// Run one complete installed key service. Endpoint values stay owned here
/// until BOTH borrowed role futures finish, including the retirement ack.
/// The caller supplies a non-reused connection generation and one owned key.
/// Commands/replies use real mailbox wakers and retain normal backpressure.
pub async fn run<const N: usize, const REQUESTS: usize, const REPLIES: usize>(
    mut client_endpoint: Endpoint<'_, KEY_CLIENT>,
    mut crypto_endpoint: Endpoint<'_, KEY_CRYPTO>,
    generation: u64,
    key: PacketKey,
    commands: Receiver<'_, '_, Command<N>, REQUESTS>,
    replies: Sender<'_, '_, Reply<N>, REPLIES>,
    exchange: &mut Exchange<N>,
) -> Result<(), Error> {
    run_borrowed(
        &mut client_endpoint,
        &mut crypto_endpoint,
        generation,
        key,
        commands,
        replies,
        exchange,
    )
    .await
}

/// Compose independent key facets in ONE global session. The enclosing owner
/// retains all endpoint values until every sibling service finishes; completion
/// of this borrowed service cannot close a still-active sibling's carrier.
pub async fn run_borrowed<
    const CLIENT: u8,
    const CRYPTO: u8,
    const N: usize,
    const REQUESTS: usize,
    const REPLIES: usize,
>(
    client_endpoint: &mut Endpoint<'_, CLIENT>,
    crypto_endpoint: &mut Endpoint<'_, CRYPTO>,
    generation: u64,
    key: PacketKey,
    commands: Receiver<'_, '_, Command<N>, REQUESTS>,
    replies: Sender<'_, '_, Reply<N>, REPLIES>,
    exchange: &mut Exchange<N>,
) -> Result<(), Error> {
    if !exchange.is_empty() {
        return Err(Error::OccupiedSlot);
    }
    let exchange = &*exchange;
    let _clear = ClearExchange(exchange);
    // Pin each child directly in this owner. Passing these large packet-bearing
    // futures through an owning join adds a second argument-to-pin storage
    // layer to the aggregate's layout on current rustc.
    let mut command = core::pin::pin!(command_role(
        client_endpoint,
        generation,
        commands,
        replies,
        exchange
    ));
    let mut crypto = core::pin::pin!(crypto_role(crypto_endpoint, key, exchange));
    runtime::TaskSet::new([command.as_mut(), crypto.as_mut()]).await
}

async fn command_role<
    const CLIENT: u8,
    const N: usize,
    const REQUESTS: usize,
    const REPLIES: usize,
>(
    endpoint: &mut Endpoint<'_, CLIENT>,
    generation: u64,
    mut commands: Receiver<'_, '_, Command<N>, REQUESTS>,
    mut replies: Sender<'_, '_, Reply<N>, REPLIES>,
    exchange: &Exchange<N>,
) -> Result<(), Error> {
    endpoint.send::<protocol::Install>(&generation).await?;
    if endpoint.recv::<protocol::Installed>().await? != generation {
        return Err(Error::DescriptorMismatch);
    }
    replies
        .send(Reply {
            descriptor: Descriptor {
                generation,
                sequence: 0,
            },
            outcome: Outcome::Installed,
        })
        .await
        .map_err(|_| Error::RepliesClosed)?;
    let mut sequence = 1_u64;
    loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        let wire = descriptor.wire();
        // Only the requested operation is selected here. The crypto actor
        // independently chooses its result after the actual primitive call.
        match command {
            command @ Command::Open { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<protocol::Open>(&wire).await?;
                let branch = endpoint.offer().await.map_err(|error| Error::Operation {
                    stage: "open_result",
                    sequence,
                    error,
                })?;
                let observed = match branch.label() {
                    protocol::OPENED => branch.recv::<protocol::Opened>().await?,
                    protocol::OPEN_FAILED => branch.recv::<protocol::OpenFailed>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                if observed != wire {
                    return Err(Error::DescriptorMismatch);
                }
            }
            command @ Command::Seal(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<protocol::Seal>(&wire).await?;
                let branch = endpoint.offer().await.map_err(|error| Error::Operation {
                    stage: "seal_result",
                    sequence,
                    error,
                })?;
                let observed = match branch.label() {
                    protocol::SEALED => branch.recv::<protocol::Sealed>().await?,
                    protocol::SEAL_FAILED => branch.recv::<protocol::SealFailed>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                if observed != wire {
                    return Err(Error::DescriptorMismatch);
                }
            }
            command @ Command::HeaderMask(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<protocol::HeaderMask>(&wire).await?;
                let branch = endpoint.offer().await.map_err(|error| Error::Operation {
                    stage: "mask_result",
                    sequence,
                    error,
                })?;
                let observed = match branch.label() {
                    protocol::HEADER_MASK_READY => {
                        branch.recv::<protocol::HeaderMaskReady>().await?
                    }
                    protocol::HEADER_MASK_FAILED => {
                        branch.recv::<protocol::HeaderMaskFailed>().await?
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                if observed != wire {
                    return Err(Error::DescriptorMismatch);
                }
            }
            command @ Command::RekeyInitial { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<protocol::RekeyInitial>(&wire).await?;
                let branch = endpoint.offer().await.map_err(|error| Error::Operation {
                    stage: "initial_rekey_result",
                    sequence,
                    error,
                })?;
                let observed = match branch.label() {
                    protocol::INITIAL_REKEYED => branch.recv::<protocol::InitialRekeyed>().await?,
                    protocol::INITIAL_REKEY_FAILED => {
                        branch.recv::<protocol::InitialRekeyFailed>().await?
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                if observed != wire {
                    return Err(Error::DescriptorMismatch);
                }
            }
            command @ Command::Retire => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                // Close admission now. Queued/stale commands are destroyed and
                // parked producers wake before actual retirement is requested.
                commands.close();
                endpoint.send::<protocol::RetireRequested>(&wire).await?;
                if endpoint.recv::<protocol::Retired>().await? != wire {
                    return Err(Error::DescriptorMismatch);
                }
                endpoint
                    .send::<protocol::RetirementAcknowledged>(&wire)
                    .await?;
                replies
                    .send(exchange.take_reply(descriptor)?)
                    .await
                    .map_err(|_| Error::RepliesClosed)?;
                return Ok(());
            }
        }
        let reply = exchange.take_reply(descriptor)?;
        // The reply bytes/budget now belong to this task, not the shared arena.
        endpoint.send::<protocol::ResultTaken>(&wire).await?;
        replies
            .send(reply)
            .await
            .map_err(|_| Error::RepliesClosed)?;
        sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        runtime::yield_now().await;
    }
}

async fn crypto_role<const CRYPTO: u8, const N: usize>(
    endpoint: &mut Endpoint<'_, CRYPTO>,
    mut key: PacketKey,
    exchange: &Exchange<N>,
) -> Result<(), Error> {
    let generation = endpoint.recv::<protocol::Install>().await?;
    // Reject a previously discarded key without inventing a separate lifetime
    // flag. The real owned primitive is the key's only numerical usage guard.
    key.ensure_active().map_err(Error::InvalidKey)?;
    endpoint.send::<protocol::Installed>(&generation).await?;
    loop {
        let branch = endpoint.offer().await.map_err(|error| Error::Operation {
            stage: "crypto_request",
            sequence: 0,
            error,
        })?;
        let completed;
        match branch.label() {
            protocol::OPEN => {
                let wire = branch.recv::<protocol::Open>().await?;
                completed = wire;
                let opened = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::DescriptorMismatch);
                    }
                    let Command::Open {
                        mut packet,
                        mut budget,
                    } = command
                    else {
                        return Err(Error::CommandMismatch);
                    };
                    let (header, body) = packet.bytes[..packet.header_len + packet.body_len]
                        .split_at_mut(packet.header_len);
                    match key.open(packet.packet_number, header, body, &mut budget) {
                        Ok(len) => {
                            packet.body_len = len;
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::Opened { packet, budget },
                            })?;
                            true
                        }
                        Err(error @ crypto::Error::AuthenticationFailed) => {
                            drop(packet);
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::AuthenticationRejected { error, budget },
                            })?;
                            false
                        }
                        Err(error) => {
                            drop(packet);
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::OpenFailed { error, budget },
                            })?;
                            false
                        }
                    }
                };
                if opened {
                    endpoint.send::<protocol::Opened>(&wire).await?;
                } else {
                    endpoint.send::<protocol::OpenFailed>(&wire).await?;
                }
            }
            protocol::SEAL => {
                let wire = branch.recv::<protocol::Seal>().await?;
                completed = wire;
                let sealed = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::DescriptorMismatch);
                    }
                    let Command::Seal(mut packet) = command else {
                        return Err(Error::CommandMismatch);
                    };
                    let (header, body) = packet.bytes.split_at_mut(packet.header_len);
                    match key.seal(packet.packet_number, header, body, packet.body_len) {
                        Ok(len) => {
                            packet.body_len = len;
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::Sealed(packet),
                            })?;
                            true
                        }
                        Err(error) => {
                            drop(packet);
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::SealFailed(error),
                            })?;
                            false
                        }
                    }
                };
                if sealed {
                    endpoint.send::<protocol::Sealed>(&wire).await?;
                } else {
                    endpoint.send::<protocol::SealFailed>(&wire).await?;
                }
            }
            protocol::HEADER_MASK => {
                let wire = branch.recv::<protocol::HeaderMask>().await?;
                completed = wire;
                let ready = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::DescriptorMismatch);
                    }
                    let Command::HeaderMask(sample) = command else {
                        return Err(Error::CommandMismatch);
                    };
                    match key.header_mask(&sample) {
                        Ok(mask) => {
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::HeaderMask(mask),
                            })?;
                            true
                        }
                        Err(error) => {
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::HeaderMaskFailed(error),
                            })?;
                            false
                        }
                    }
                };
                if ready {
                    endpoint.send::<protocol::HeaderMaskReady>(&wire).await?;
                } else {
                    endpoint.send::<protocol::HeaderMaskFailed>(&wire).await?;
                }
            }
            protocol::REKEY_INITIAL => {
                let wire = branch.recv::<protocol::RekeyInitial>().await?;
                completed = wire;
                let rekeyed = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::DescriptorMismatch);
                    }
                    let Command::RekeyInitial {
                        destination,
                        client,
                    } = command
                    else {
                        return Err(Error::CommandMismatch);
                    };
                    let replacement = if key.kind() == crypto::KeyKind::Initial {
                        crypto::initial_keys(destination.as_bytes())
                            .map(|keys| if client { keys.client } else { keys.server })
                    } else {
                        Err(crypto::Error::KeyUpdateNotAllowed)
                    };
                    let replacement = replacement.and_then(|mut replacement| {
                        replacement.inherit_send_usage(&key)?;
                        Ok(replacement)
                    });
                    match replacement {
                        Ok(replacement) => {
                            // Even re-deriving the SAME CID must not reset nonce or
                            // confidentiality counters. Retry never rewinds QUIC PNs.
                            key.discard();
                            key = replacement;
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::InitialRekeyed,
                            })?;
                            true
                        }
                        Err(error) => {
                            exchange.put_reply(Reply {
                                descriptor,
                                outcome: Outcome::InitialRekeyFailed(error),
                            })?;
                            false
                        }
                    }
                };
                if rekeyed {
                    endpoint.send::<protocol::InitialRekeyed>(&wire).await?;
                } else {
                    endpoint.send::<protocol::InitialRekeyFailed>(&wire).await?;
                }
            }
            protocol::RETIRE_REQUESTED => {
                let wire = branch.recv::<protocol::RetireRequested>().await?;
                {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::DescriptorMismatch);
                    }
                    let Command::Retire = command else {
                        return Err(Error::CommandMismatch);
                    };
                    key.discard();
                    exchange.put_reply(Reply {
                        descriptor,
                        outcome: Outcome::Retired,
                    })?;
                }
                drop(key);
                endpoint.send::<protocol::Retired>(&wire).await?;
                if endpoint.recv::<protocol::RetirementAcknowledged>().await? != wire {
                    return Err(Error::DescriptorMismatch);
                }
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        // Reuse of the request/result arena requires the real transfer ack.
        if endpoint.recv::<protocol::ResultTaken>().await? != completed {
            return Err(Error::DescriptorMismatch);
        }
        runtime::yield_now().await;
    }
}
