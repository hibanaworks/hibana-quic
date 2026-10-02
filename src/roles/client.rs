//! Application-facing admission for the packet-protection roles.
//!
//! No Hibana operation is hidden here: the readable endpoint local sides live
//! in packet_protection.rs. This client moves owned requests through the bounded
//! mailbox and checks correlation. Cancelling an in-flight call closes its
//! capability; callers must abandon the connection after a service error.
use super::packet_protection::{
    Command, Descriptor, InitialDestination, OpenedPacket, Outcome, Packet, Reply,
};
use crate::{
    crypto,
    mailbox::{Receiver, Sender},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Closed,
    Correlation,
    UnexpectedReply,
    SequenceExhausted,
}

pub struct KeyClient<
    'channel,
    'storage,
    const N: usize,
    const REQUESTS: usize,
    const REPLIES: usize,
> {
    commands: Sender<'channel, 'storage, Command<N>, REQUESTS>,
    replies: Receiver<'channel, 'storage, Reply<N>, REPLIES>,
    generation: u64,
    next_sequence: u64,
}

struct Pending<'a, 'channel, 'storage, const N: usize, const REQUESTS: usize, const REPLIES: usize>
{
    commands: &'a mut Sender<'channel, 'storage, Command<N>, REQUESTS>,
    replies: &'a mut Receiver<'channel, 'storage, Reply<N>, REPLIES>,
    completed: bool,
}
impl<const N: usize, const Q: usize, const R: usize> Drop for Pending<'_, '_, '_, N, Q, R> {
    fn drop(&mut self) {
        if !self.completed {
            self.commands.close();
            self.replies.close();
        }
    }
}

impl<'c, 's, const N: usize, const Q: usize, const R: usize> KeyClient<'c, 's, N, Q, R> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Becomes usable only after the actual installed exchange finishes.
    pub async fn connect(
        commands: Sender<'c, 's, Command<N>, Q>,
        mut replies: Receiver<'c, 's, Reply<N>, R>,
        generation: u64,
    ) -> Result<Self, Error> {
        let installed = replies.recv().await.map_err(|_| Error::Closed)?;
        if installed.descriptor
            != (Descriptor {
                generation,
                sequence: 0,
            })
        {
            return Err(Error::Correlation);
        }
        if !matches!(installed.outcome, Outcome::Installed) {
            return Err(Error::UnexpectedReply);
        }
        Ok(Self {
            commands,
            replies,
            generation,
            next_sequence: 1,
        })
    }

    async fn request(&mut self, command: Command<N>) -> Result<Outcome<N>, Error> {
        let expected = Descriptor {
            generation: self.generation,
            sequence: self.next_sequence,
        };
        let Some(next) = self.next_sequence.checked_add(1) else {
            self.close();
            return Err(Error::SequenceExhausted);
        };
        let mut pending = Pending {
            commands: &mut self.commands,
            replies: &mut self.replies,
            completed: false,
        };
        pending
            .commands
            .send(command)
            .await
            .map_err(|_| Error::Closed)?;
        let reply = pending.replies.recv().await.map_err(|_| Error::Closed)?;
        if reply.descriptor != expected {
            return Err(Error::Correlation);
        }
        pending.completed = true;
        self.next_sequence = next;
        Ok(reply.outcome)
    }
    pub async fn header_mask(
        &mut self,
        sample: [u8; crypto::HP_SAMPLE_LEN],
    ) -> Result<Result<[u8; 5], crypto::Error>, Error> {
        match self.request(Command::HeaderMask(sample)).await? {
            Outcome::HeaderMask(mask) => Ok(Ok(mask)),
            Outcome::HeaderMaskFailed(error) => Ok(Err(error)),
            _ => {
                self.close();
                Err(Error::UnexpectedReply)
            }
        }
    }
    /// Retry-authorized Initial key replacement. `client` selects the client
    /// traffic direction. The role derives and replaces keys; no integrity
    /// budget is reset, and the key's send-usage guards are retained.
    pub async fn rekey_initial(
        &mut self,
        destination_id: &[u8],
        client: bool,
    ) -> Result<Result<(), crypto::Error>, Error> {
        let destination = match InitialDestination::new(destination_id) {
            Ok(destination) => destination,
            Err(error) => return Ok(Err(error)),
        };
        match self
            .request(Command::RekeyInitial {
                destination,
                client,
            })
            .await?
        {
            Outcome::InitialRekeyed => Ok(Ok(())),
            Outcome::InitialRekeyFailed(error) => Ok(Err(error)),
            _ => {
                self.close();
                Err(Error::UnexpectedReply)
            }
        }
    }
    pub async fn seal(
        &mut self,
        packet: Packet<N>,
    ) -> Result<Result<super::sealed_packet::SealedPacket<N>, crypto::Error>, Error> {
        match self.request(Command::Seal(packet)).await? {
            Outcome::Sealed(packet) => Ok(Ok(packet)),
            Outcome::SealFailed(error) => Ok(Err(error)),
            _ => {
                self.close();
                Err(Error::UnexpectedReply)
            }
        }
    }
    /// The same global integrity budget returns on every cryptographic outcome.
    /// A service/cancellation error is terminal; it must never reset a budget
    /// and continue protecting a connection.
    pub async fn open(
        &mut self,
        packet: Packet<N>,
        budget: crypto::IntegrityBudget,
    ) -> Result<
        (
            Result<OpenedPacket<N>, crypto::Error>,
            crypto::IntegrityBudget,
        ),
        Error,
    > {
        match self.request(Command::Open { packet, budget }).await? {
            Outcome::Opened {
                packet,
                receipt,
                budget,
            } => Ok((Ok(OpenedPacket { packet, receipt }), budget)),
            Outcome::AuthenticationRejected { error, budget }
            | Outcome::OpenFailed { error, budget } => Ok((Err(error), budget)),
            _ => {
                self.close();
                Err(Error::UnexpectedReply)
            }
        }
    }
    /// Consumes the only external capability. It cannot be reused after the
    /// crypto role destroys the key and acknowledges retirement.
    pub async fn retire(mut self) -> Result<(), Error> {
        match self.request(Command::Retire).await? {
            Outcome::Retired => Ok(()),
            _ => Err(Error::UnexpectedReply),
        }
    }
    /// Abort admission; dropping the owned actor aggregate destroys key material.
    pub fn close(&mut self) {
        self.commands.close();
        self.replies.close();
    }
}
impl<const N: usize, const Q: usize, const R: usize> Drop for KeyClient<'_, '_, N, Q, R> {
    fn drop(&mut self) {
        self.close();
    }
}
