use super::*;
use crate::roles::protocol_early as p;
use crate::{
    mailbox::{Receiver, Sender},
    runtime,
};
use core::cell::RefCell;
use hibana::{Endpoint, EndpointError};

pub enum Command<const N: usize> {
    Receive(AuthenticatedPacket<N>),
    Checked(PathChecked),
    Finish(EarlyReady),
    Release,
    Settle(ReleaseCompletion),
    Inspect,
    Retire,
}
pub enum Outcome<const N: usize> {
    Installed,
    Check(PathCheck),
    Dropped,
    Admission(Admission<N>),
    Ready,
    Release(Option<Release<N>>),
    Settled,
    Inspected,
    Rejected(Fault),
    Retired,
}
pub struct Reply<const N: usize> {
    pub descriptor: Descriptor,
    pub snapshot: Snapshot,
    pub outcome: Outcome<N>,
}
struct Request<const N: usize> {
    descriptor: Descriptor,
    command: Command<N>,
}
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
    fn put(&self, request: Request<N>) -> Result<(), ServiceError> {
        if !self.is_empty() {
            return Err(ServiceError::OccupiedSlot);
        }
        *self.request.borrow_mut() = Some(request);
        Ok(())
    }
    fn take(&self, wire: [u8; 16]) -> Result<Request<N>, ServiceError> {
        let request = self
            .request
            .borrow_mut()
            .take()
            .ok_or(ServiceError::MissingSlot)?;
        same(encode(request.descriptor), wire)?;
        Ok(request)
    }
    fn reply(&self, reply: Reply<N>) -> Result<(), ServiceError> {
        let mut slot = self.reply.borrow_mut();
        if slot.is_some() {
            return Err(ServiceError::OccupiedSlot);
        }
        *slot = Some(reply);
        Ok(())
    }
    fn take_reply(&self, descriptor: Descriptor) -> Result<Reply<N>, ServiceError> {
        let reply = self
            .reply
            .borrow_mut()
            .take()
            .ok_or(ServiceError::MissingSlot)?;
        same(encode(reply.descriptor), encode(descriptor))?;
        Ok(reply)
    }
}
impl<const N: usize> Default for Exchange<N> {
    fn default() -> Self {
        Self::new()
    }
}
struct Clear<'a, const N: usize>(&'a Exchange<N>);
impl<const N: usize> Drop for Clear<'_, N> {
    fn drop(&mut self) {
        self.0.request.borrow_mut().take();
        self.0.reply.borrow_mut().take();
    }
}
#[derive(Debug)]
pub enum ServiceError {
    Hibana(EndpointError),
    HibanaStep { label: u8, source: EndpointError },
    CommandsClosed,
    RepliesClosed,
    OccupiedSlot,
    MissingSlot,
    Correlation,
    UnexpectedCommand,
    UnexpectedRetirementOutcome,
    CommandLabelMismatch { expected: u8, actual: u8 },
    UnexpectedContinuation { expected: u8, actual: u8 },
    UnexpectedLabel(u8),
    SequenceExhausted,
}
impl From<EndpointError> for ServiceError {
    fn from(e: EndpointError) -> Self {
        Self::Hibana(e)
    }
}
fn encode(d: Descriptor) -> [u8; 16] {
    let mut wire = [0; 16];
    wire[..8].copy_from_slice(&d.generation.to_be_bytes());
    wire[8..].copy_from_slice(&d.sequence.to_be_bytes());
    wire
}
fn same(a: [u8; 16], b: [u8; 16]) -> Result<(), ServiceError> {
    if a == b {
        Ok(())
    } else {
        Err(ServiceError::Correlation)
    }
}
fn bump(value: &mut u64) -> Result<(), ServiceError> {
    *value = value
        .checked_add(1)
        .ok_or(ServiceError::SequenceExhausted)?;
    Ok(())
}

/// Owns all resources for the lifetime of the encompassing projected session.
/// Dropping this future clears in-flight capabilities and zeroizes every slot.
pub async fn run_borrowed<
    const C: u8,
    const O: u8,
    const RX: usize,
    const CONTROL: usize,
    const N: usize,
    const Q: usize,
    const R: usize,
>(
    client: &mut Endpoint<'_, C>,
    owner: &mut Endpoint<'_, O>,
    state: State<'_, RX, CONTROL, N>,
    commands: Receiver<'_, '_, Command<N>, Q>,
    replies: Sender<'_, '_, Reply<N>, R>,
    exchange: &mut Exchange<N>,
) -> Result<(), ServiceError> {
    if !exchange.is_empty() {
        return Err(ServiceError::OccupiedSlot);
    }
    let exchange = &*exchange;
    let _clear = Clear(exchange);
    let generation = state.generation;
    let mut client = core::pin::pin!(command_role(
        client, generation, commands, replies, exchange
    ));
    let mut owner = core::pin::pin!(owner_role(owner, state, exchange));
    runtime::TaskSet::new([client.as_mut(), owner.as_mut()]).await
}
async fn command_role<const C: u8, const N: usize, const Q: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    mut commands: Receiver<'_, '_, Command<N>, Q>,
    mut replies: Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
) -> Result<(), ServiceError> {
    let installed = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(installed);
    endpoint
        .send::<p::Install>(&wire)
        .await
        .map_err(|source| ServiceError::HibanaStep {
            label: p::INSTALL,
            source,
        })?;
    same(endpoint.recv::<p::Installed>().await?, wire)?;
    replies
        .send(exchange.take_reply(installed)?)
        .await
        .map_err(|_| ServiceError::RepliesClosed)?;
    let mut sequence = 1;
    loop {
        let command = commands
            .recv()
            .await
            .map_err(|_| ServiceError::CommandsClosed)?;
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        let wire = encode(descriptor);
        let label = match &command {
            Command::Receive(_) => p::RECEIVE,
            Command::Finish(_) => p::FINISH,
            Command::Release => p::RELEASE,
            Command::Inspect => p::INSPECT,
            Command::Retire => p::RETIRE_REQUESTED,
            _ => {
                return Err(ServiceError::UnexpectedContinuation {
                    expected: 0,
                    actual: command_label(&command),
                });
            }
        };
        exchange.put(Request {
            descriptor,
            command,
        })?;
        match label {
            p::RECEIVE => endpoint.send::<p::Receive>(&wire).await.map_err(|source| {
                ServiceError::HibanaStep {
                    label: p::RECEIVE,
                    source,
                }
            })?,
            p::FINISH => endpoint.send::<p::Finish>(&wire).await.map_err(|source| {
                ServiceError::HibanaStep {
                    label: p::FINISH,
                    source,
                }
            })?,
            p::RELEASE => endpoint.send::<p::Release>(&wire).await.map_err(|source| {
                ServiceError::HibanaStep {
                    label: p::RELEASE,
                    source,
                }
            })?,
            p::INSPECT => endpoint.send::<p::Inspect>(&wire).await.map_err(|source| {
                ServiceError::HibanaStep {
                    label: p::INSPECT,
                    source,
                }
            })?,
            p::RETIRE_REQUESTED => {
                endpoint
                    .send::<p::RetireRequested>(&wire)
                    .await
                    .map_err(|source| ServiceError::HibanaStep {
                        label: p::RETIRE_REQUESTED,
                        source,
                    })?;
                same(endpoint.recv::<p::Retired>().await?, wire)?;
                replies
                    .send(exchange.take_reply(descriptor)?)
                    .await
                    .map_err(|_| ServiceError::RepliesClosed)?;
                endpoint
                    .send::<p::RetirementAcknowledged>(&wire)
                    .await
                    .map_err(|source| ServiceError::HibanaStep {
                        label: p::RETIREMENT_ACKNOWLEDGED,
                        source,
                    })?;
                return Ok(());
            }
            _ => return Err(ServiceError::UnexpectedCommand),
        }
        let result = client_reply(endpoint, descriptor, &mut replies, exchange).await?;
        bump(&mut sequence)?;
        if result == p::CHECK {
            let command = commands
                .recv()
                .await
                .map_err(|_| ServiceError::CommandsClosed)?;
            if !matches!(command, Command::Checked(_)) {
                return Err(ServiceError::UnexpectedContinuation {
                    expected: p::CHECKED,
                    actual: command_label(&command),
                });
            }
            let descriptor = Descriptor {
                generation,
                sequence,
            };
            let wire = encode(descriptor);
            exchange.put(Request {
                descriptor,
                command,
            })?;
            endpoint.send::<p::Checked>(&wire).await.map_err(|source| {
                ServiceError::HibanaStep {
                    label: p::CHECKED,
                    source,
                }
            })?;
            let result = client_reply(endpoint, descriptor, &mut replies, exchange).await?;
            if !matches!(result, p::APPLIED | p::REJECTED) {
                return Err(ServiceError::UnexpectedLabel(result));
            }
            bump(&mut sequence)?;
        }
        if matches!(result, p::APPLICATION | p::PATH) {
            loop {
                let command = commands
                    .recv()
                    .await
                    .map_err(|_| ServiceError::CommandsClosed)?;
                if !matches!(command, Command::Settle(_)) {
                    return Err(ServiceError::UnexpectedContinuation {
                        expected: p::SETTLE,
                        actual: command_label(&command),
                    });
                }
                let descriptor = Descriptor {
                    generation,
                    sequence,
                };
                let wire = encode(descriptor);
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Settle>(&wire).await.map_err(|source| {
                    ServiceError::HibanaStep {
                        label: p::SETTLE,
                        source,
                    }
                })?;
                let result = client_reply(endpoint, descriptor, &mut replies, exchange).await?;
                bump(&mut sequence)?;
                if result == p::APPLIED {
                    same(endpoint.recv::<p::Settled>().await?, wire)?;
                    break;
                }
                if result != p::REJECTED {
                    return Err(ServiceError::UnexpectedLabel(result));
                }
            }
        }
        runtime::yield_now().await;
    }
}
async fn client_reply<const C: u8, const N: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    descriptor: Descriptor,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
) -> Result<u8, ServiceError> {
    let branch = endpoint.offer().await?;
    let label = branch.label();
    let wire = match label {
        p::CHECK => branch.recv::<p::Check>().await?,
        p::DROPPED => branch.recv::<p::Dropped>().await?,
        p::READY => branch.recv::<p::Ready>().await?,
        p::DECLINED => branch.recv::<p::Declined>().await?,
        p::APPLICATION => branch.recv::<p::Application>().await?,
        p::PATH => branch.recv::<p::Path>().await?,
        p::EMPTY => branch.recv::<p::Empty>().await?,
        p::APPLIED => branch.recv::<p::Applied>().await?,
        p::REJECTED => branch.recv::<p::Rejected>().await?,
        label => return Err(ServiceError::UnexpectedLabel(label)),
    };
    same(wire, encode(descriptor))?;
    replies
        .send(exchange.take_reply(descriptor)?)
        .await
        .map_err(|_| ServiceError::RepliesClosed)?;
    endpoint
        .send::<p::ResultTaken>(&wire)
        .await
        .map_err(|source| ServiceError::HibanaStep {
            label: p::RESULT_TAKEN,
            source,
        })?;
    Ok(label)
}
async fn owner_role<const O: u8, const RX: usize, const CONTROL: usize, const N: usize>(
    endpoint: &mut Endpoint<'_, O>,
    mut state: State<'_, RX, CONTROL, N>,
    exchange: &Exchange<N>,
) -> Result<(), ServiceError> {
    let generation = state.generation;
    let descriptor = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = endpoint.recv::<p::Install>().await?;
    same(wire, encode(descriptor))?;
    exchange.reply(Reply {
        descriptor,
        snapshot: state.snapshot(),
        outcome: Outcome::Installed,
    })?;
    endpoint
        .send::<p::Installed>(&wire)
        .await
        .map_err(|source| ServiceError::HibanaStep {
            label: p::INSTALLED,
            source,
        })?;
    let mut sequence = 1;
    loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let wire = match label {
            p::RECEIVE => branch.recv::<p::Receive>().await?,
            p::FINISH => branch.recv::<p::Finish>().await?,
            p::RELEASE => branch.recv::<p::Release>().await?,
            p::INSPECT => branch.recv::<p::Inspect>().await?,
            p::RETIRE_REQUESTED => branch.recv::<p::RetireRequested>().await?,
            label => return Err(ServiceError::UnexpectedLabel(label)),
        };
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        let request = exchange.take(wire)?;
        same(encode(request.descriptor), encode(descriptor))?;
        if label == p::RETIRE_REQUESTED {
            if !matches!(request.command, Command::Retire) {
                return Err(ServiceError::CommandLabelMismatch {
                    expected: p::RETIRE_REQUESTED,
                    actual: command_label(&request.command),
                });
            }
            state.retire();
            exchange.reply(Reply {
                descriptor,
                snapshot: state.snapshot(),
                outcome: Outcome::Retired,
            })?;
            endpoint.send::<p::Retired>(&wire).await.map_err(|source| {
                ServiceError::HibanaStep {
                    label: p::RETIRED,
                    source,
                }
            })?;
            same(endpoint.recv::<p::RetirementAcknowledged>().await?, wire)?;
            return Ok(());
        }
        let outcome = execute(&mut state, label, request.command)?;
        let result = owner_reply(endpoint, descriptor, label, &state, outcome, exchange).await?;
        bump(&mut sequence)?;
        if result == p::CHECK {
            let wire = endpoint.recv::<p::Checked>().await?;
            let descriptor = Descriptor {
                generation,
                sequence,
            };
            let request = exchange.take(wire)?;
            same(encode(request.descriptor), encode(descriptor))?;
            let outcome = execute(&mut state, p::CHECKED, request.command)?;
            owner_reply(endpoint, descriptor, p::CHECKED, &state, outcome, exchange).await?;
            bump(&mut sequence)?;
        }
        if matches!(result, p::APPLICATION | p::PATH) {
            loop {
                let wire = endpoint.recv::<p::Settle>().await?;
                let descriptor = Descriptor {
                    generation,
                    sequence,
                };
                let request = exchange.take(wire)?;
                same(encode(request.descriptor), encode(descriptor))?;
                let outcome = execute(&mut state, p::SETTLE, request.command)?;
                let result =
                    owner_reply(endpoint, descriptor, p::SETTLE, &state, outcome, exchange).await?;
                bump(&mut sequence)?;
                if result == p::APPLIED {
                    endpoint.send::<p::Settled>(&wire).await.map_err(|source| {
                        ServiceError::HibanaStep {
                            label: p::SETTLED,
                            source,
                        }
                    })?;
                    break;
                }
            }
        }
        runtime::yield_now().await;
    }
}
fn execute<const RX: usize, const C: usize, const N: usize>(
    state: &mut State<'_, RX, C, N>,
    label: u8,
    command: Command<N>,
) -> Result<Outcome<N>, ServiceError> {
    let actual = command_label(&command);
    let result: Result<Outcome<N>, Fault> = match (label, command) {
        (p::RECEIVE, Command::Receive(packet)) => match state.begin_admission(packet) {
            Ok(Some(check)) => Ok(Outcome::Check(check)),
            Ok(None) | Err(Fault::Capacity) | Err(Fault::Early(early_data::Error::Capacity)) => {
                Ok(Outcome::Dropped)
            }
            Err(error) => Err(error),
        },
        (p::CHECKED, Command::Checked(proof)) => {
            state.commit_admission(proof).map(Outcome::Admission)
        }
        (p::FINISH, Command::Finish(ready)) => state.finish(ready).map(|()| Outcome::Ready),
        (p::RELEASE, Command::Release) => state.release().map(Outcome::Release),
        (p::SETTLE, Command::Settle(completion)) => {
            state.settle(completion).map(|()| Outcome::Settled)
        }
        (p::INSPECT, Command::Inspect) => Ok(Outcome::Inspected),
        _ => {
            return Err(ServiceError::CommandLabelMismatch {
                expected: label,
                actual,
            });
        }
    };
    Ok(result.unwrap_or_else(Outcome::Rejected))
}
async fn owner_reply<const O: u8, const RX: usize, const C: usize, const N: usize>(
    endpoint: &mut Endpoint<'_, O>,
    descriptor: Descriptor,
    operation: u8,
    state: &State<'_, RX, C, N>,
    outcome: Outcome<N>,
    exchange: &Exchange<N>,
) -> Result<u8, ServiceError> {
    let finish = operation == p::FINISH;
    let label = match &outcome {
        Outcome::Check(_) => p::CHECK,
        Outcome::Dropped => p::DROPPED,
        Outcome::Ready => p::READY,
        Outcome::Release(Some(Release::Application(_))) => p::APPLICATION,
        Outcome::Release(Some(Release::Path(_))) => p::PATH,
        Outcome::Release(None) => p::EMPTY,
        Outcome::Rejected(_) if finish => p::DECLINED,
        Outcome::Rejected(_) => p::REJECTED,
        _ => p::APPLIED,
    };
    exchange.reply(Reply {
        descriptor,
        snapshot: state.snapshot(),
        outcome,
    })?;
    let wire = encode(descriptor);
    match label {
        p::CHECK => {
            endpoint
                .send::<p::Check>(&wire)
                .await
                .map_err(|source| ServiceError::HibanaStep {
                    label: p::CHECK,
                    source,
                })?
        }
        p::DROPPED => {
            endpoint
                .send::<p::Dropped>(&wire)
                .await
                .map_err(|source| ServiceError::HibanaStep {
                    label: p::DROPPED,
                    source,
                })?
        }
        p::READY => {
            endpoint
                .send::<p::Ready>(&wire)
                .await
                .map_err(|source| ServiceError::HibanaStep {
                    label: p::READY,
                    source,
                })?
        }
        p::DECLINED => endpoint
            .send::<p::Declined>(&wire)
            .await
            .map_err(|source| ServiceError::HibanaStep {
                label: p::DECLINED,
                source,
            })?,
        p::APPLICATION => endpoint
            .send::<p::Application>(&wire)
            .await
            .map_err(|source| ServiceError::HibanaStep {
                label: p::APPLICATION,
                source,
            })?,
        p::PATH => {
            endpoint
                .send::<p::Path>(&wire)
                .await
                .map_err(|source| ServiceError::HibanaStep {
                    label: p::PATH,
                    source,
                })?
        }
        p::EMPTY => {
            endpoint
                .send::<p::Empty>(&wire)
                .await
                .map_err(|source| ServiceError::HibanaStep {
                    label: p::EMPTY,
                    source,
                })?
        }
        p::APPLIED => {
            endpoint
                .send::<p::Applied>(&wire)
                .await
                .map_err(|source| ServiceError::HibanaStep {
                    label: p::APPLIED,
                    source,
                })?
        }
        p::REJECTED => endpoint
            .send::<p::Rejected>(&wire)
            .await
            .map_err(|source| ServiceError::HibanaStep {
                label: p::REJECTED,
                source,
            })?,
        _ => return Err(ServiceError::UnexpectedLabel(label)),
    };
    same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
    Ok(label)
}

/// Convenience mailbox endpoint. The projected command role, rather than this
/// handle, owns admission/release continuation ordering.
pub struct Client<'a, 's, const N: usize, const Q: usize, const R: usize> {
    commands: Sender<'a, 's, Command<N>, Q>,
    replies: Receiver<'a, 's, Reply<N>, R>,
    generation: u64,
    sequence: u64,
    snapshot: Snapshot,
}
impl<'a, 's, const N: usize, const Q: usize, const R: usize> Client<'a, 's, N, Q, R> {
    pub async fn connect(
        commands: Sender<'a, 's, Command<N>, Q>,
        mut replies: Receiver<'a, 's, Reply<N>, R>,
        generation: u64,
    ) -> Result<Self, ServiceError> {
        let reply = replies
            .recv()
            .await
            .map_err(|_| ServiceError::RepliesClosed)?;
        if reply.descriptor
            != (Descriptor {
                generation,
                sequence: 0,
            })
            || !matches!(reply.outcome, Outcome::Installed)
        {
            return Err(ServiceError::Correlation);
        }
        Ok(Self {
            commands,
            replies,
            generation,
            sequence: 1,
            snapshot: reply.snapshot,
        })
    }
    pub const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }
    pub async fn request(&mut self, command: Command<N>) -> Result<Outcome<N>, ServiceError> {
        let descriptor = Descriptor {
            generation: self.generation,
            sequence: self.sequence,
        };
        self.commands
            .send(command)
            .await
            .map_err(|_| ServiceError::CommandsClosed)?;
        let reply = self
            .replies
            .recv()
            .await
            .map_err(|_| ServiceError::RepliesClosed)?;
        if reply.descriptor != descriptor {
            return Err(ServiceError::Correlation);
        }
        bump(&mut self.sequence)?;
        self.snapshot = reply.snapshot;
        Ok(reply.outcome)
    }
    pub async fn retire(mut self) -> Result<(), ServiceError> {
        if !matches!(self.request(Command::Retire).await?, Outcome::Retired) {
            return Err(ServiceError::UnexpectedRetirementOutcome);
        }
        Ok(())
    }
}

fn command_label<const N: usize>(command: &Command<N>) -> u8 {
    match command {
        Command::Receive(_) => p::RECEIVE,
        Command::Checked(_) => p::CHECKED,
        Command::Finish(_) => p::FINISH,
        Command::Release => p::RELEASE,
        Command::Settle(_) => p::SETTLE,
        Command::Inspect => p::INSPECT,
        Command::Retire => p::RETIRE_REQUESTED,
    }
}
