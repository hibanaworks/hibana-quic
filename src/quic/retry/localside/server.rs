//! Actual server Retry admission, written as the three projected locals.
//! Packet/token checks are data validation; progression belongs to Hibana.
use crate::entropy::Entropy;
use crate::quic::retry::imp::admission::{Observation, Reply};
use crate::quic::retry::{AdmittedInitial, Error};
type Result<T> = core::result::Result<T, Error>;
use super::super::imp::admission::Datagram;
use crate::io::Codepoint;
use crate::io::DatagramSocket;
use crate::quic::Clock;
use crate::quic::imp::kernel::packet::Header;
use crate::quic::imp::kernel::packet::LongType;
use crate::quic::imp::kernel::packet::PacketIter;
use crate::quic::retry;
use crate::quic::retry::global as p;
use crate::quic::retry::imp::ClientAddress;
use crate::quic::retry::imp::RetryTokens;
use crate::quic::retry::imp::TokenContext;
use crate::runtime::carrier::CarrierStorage;
use crate::runtime::join2;
use core::cell::{Cell, RefCell};
use hibana::runtime::{
    SessionKitStorage,
    ids::SessionId,
    resolver::{DecisionArm, ResolverError, ResolverRef},
};

pub async fn receive<const D: usize>(
    socket: &impl DatagramSocket,
    clock: &impl Clock,
    tokens: &mut RetryTokens<64>,
    entropy: &mut impl Entropy,
    sid: SessionId,
    slab: &mut [u8],
    scratch: &mut [u8],
) -> Result<AdmittedInitial<D>> {
    if D < 1200 || scratch.len().saturating_sub(21) < D {
        return Err("Retry storage capacity".into());
    }
    let send_result = Cell::new(None);
    let graph = p::choreography();
    let input_program = hibana::runtime::program::project::<{ p::INPUT }>(&graph);
    let owner_program = hibana::runtime::program::project::<{ p::OWNER }>(&graph);
    let output_program = hibana::runtime::program::project::<{ p::OUTPUT }>(&graph);
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut kit = SessionKitStorage::uninit();
    let session = kit
        .init()
        .rendezvous(slab, carrier.bind(sid).map_err(Error::from)?)
        .map_err(Error::from)?;
    session
        .set_resolver(
            &output_program,
            ResolverRef::<{ p::SEND_RESULT }>::decision_state(&send_result, |value| {
                value.get().ok_or_else(ResolverError::reject)
            }),
        )
        .map_err(Error::from)?;
    let mut input = session.enter(sid, &input_program).map_err(Error::from)?;
    let mut owner = session.enter(sid, &owner_program).map_err(Error::from)?;
    let mut output = session.enter(sid, &output_program).map_err(Error::from)?;
    let observed = RefCell::<Option<Observation<D>>>::new(None);
    let reply = RefCell::<Option<Reply<D>>>::new(None);
    let admitted = RefCell::<Option<AdmittedInitial<D>>>::new(None);

    let incoming = async {
        loop {
            crate::runtime::yield_now().await;
            let mut bytes = Datagram::<D>::new();
            let metadata = socket.receive_from(&mut bytes).await?;
            let address = metadata.path.ok_or("Retry datagram has no path")?;
            if metadata.len > bytes.len() {
                return Err("Retry receive length".into());
            }
            bytes.truncate(metadata.len);
            {
                let mut slot = observed
                    .try_borrow_mut()
                    .map_err(|_| "Retry observed borrow")?;
                if slot.is_some() {
                    return Err("Retry observed slot already occupied".into());
                }
                *slot = Some(Observation {
                    ecn: metadata.ecn,
                    address,
                    datagram: bytes,
                });
            }
            input.send::<p::Observed>(&()).await.map_err(Error::from)?;
            let selected = input.offer().await.map_err(Error::from)?;
            match selected.label() {
                4 => {
                    selected.recv::<p::Settled>().await.map_err(Error::from)?;
                }
                5 => {
                    selected.recv::<p::Ignored>().await.map_err(Error::from)?;
                }
                6 => {
                    selected.recv::<p::Admitted>().await.map_err(Error::from)?;
                    input.recv::<p::Joined>().await.map_err(Error::from)?;
                    return Ok::<(), Error>(());
                }
                label => return Err(Error::Label(label)),
            }
        }
    };
    let validation = async {
        loop {
            owner.recv::<p::Observed>().await.map_err(Error::from)?;
            let observation = observed
                .try_borrow_mut()
                .map_err(|_| "Retry observed borrow")?
                .take()
                .ok_or("Retry missing observed")?;
            let packet = PacketIter::new(&observation.datagram, 8, 8)
                .ok()
                .and_then(|mut packets| packets.next())
                .and_then(core::result::Result::ok);
            if let Some(packet) = packet.as_ref()
                && let Header::UnsupportedVersion {
                    destination_id,
                    source_id,
                    ..
                } = packet.header
                && destination_id.len() <= 20
                && source_id.len() <= 20
            {
                let mut bytes = Datagram::<D>::new();
                let mut random = [0; 1];
                entropy.try_fill_bytes(&mut random).map_err(Error::from)?;
                let end = super::super::imp::admission::version_negotiation(
                    destination_id,
                    source_id,
                    observation.datagram.len(),
                    random[0],
                    &mut bytes,
                )
                .ok_or("Version response amplification or capacity bound")?;
                bytes.truncate(end);
                {
                    let mut slot = reply
                        .try_borrow_mut()
                        .map_err(|_| "Version response borrow")?;
                    if slot.is_some() {
                        return Err("Version response slot occupied".into());
                    }
                    *slot = Some(Reply {
                        address: observation.address,
                        bytes,
                    });
                }
                owner.send::<p::Datagram>(&()).await.map_err(Error::from)?;
                let result = owner.offer().await.map_err(Error::from)?;
                match result.label() {
                    2 => {
                        result.recv::<p::Sent>().await.map_err(Error::from)?;
                    }
                    3 => {
                        result.recv::<p::Rejected>().await.map_err(Error::from)?;
                    }
                    label => return Err(Error::Label(label)),
                }
                send_result.set(None);
                owner.send::<p::Settled>(&()).await.map_err(Error::from)?;
                continue;
            }
            if observation.datagram.len() >= 1200
                && let Some(packet) = packet
                && let Header::Long {
                    kind: LongType::Initial,
                    version,
                    destination_id,
                    source_id,
                    token,
                    ..
                } = packet.header
                && version == crate::quic::imp::kernel::version::Version::V1
                && destination_id.len() >= 8
                && retry::imp::admission::initial_integrity(&packet, scratch).is_some()
            {
                let address = match observation.address.remote {
                    core::net::SocketAddr::V4(v4) => ClientAddress::V4 {
                        ip: v4.ip().octets(),
                        port: v4.port(),
                    },
                    core::net::SocketAddr::V6(v6) => ClientAddress::V6 {
                        ip: v6.ip().octets(),
                        port: v6.port(),
                    },
                };
                if token.is_empty() {
                    let retry_source = {
                        let mut bytes = [0; 8];
                        entropy.try_fill_bytes(&mut bytes).map_err(Error::from)?;
                        bytes
                    };
                    let mut token = [0; retry::imp::TOKEN_LEN];
                    let count = tokens
                        .issue(
                            clock.now(),
                            TokenContext {
                                original_destination_id: destination_id,
                                retry_source_id: &retry_source,
                                client_source_id: source_id,
                                address,
                            },
                            &mut token,
                        )
                        .map_err(Error::from)?;
                    let mut bytes = Datagram::<D>::new();
                    let size = retry::imp::encode_retry(
                        destination_id,
                        source_id,
                        &retry_source,
                        &token[..count],
                        0,
                        &mut bytes,
                        scratch,
                    )
                    .map_err(Error::from)?;
                    if size > observation.datagram.len().saturating_mul(3) {
                        return Err("Retry amplification bound".into());
                    }
                    bytes.truncate(size);
                    {
                        let mut slot = reply.try_borrow_mut().map_err(|_| "Retry reply borrow")?;
                        if slot.is_some() {
                            return Err("Retry reply slot already occupied".into());
                        }
                        *slot = Some(Reply {
                            address: observation.address,
                            bytes,
                        });
                    }
                    owner.send::<p::Datagram>(&()).await.map_err(Error::from)?;
                    let result = owner.offer().await.map_err(Error::from)?;
                    match result.label() {
                        2 => {
                            result.recv::<p::Sent>().await.map_err(Error::from)?;
                        }
                        3 => {
                            result.recv::<p::Rejected>().await.map_err(Error::from)?;
                        }
                        label => return Err(Error::Label(label)),
                    }
                    send_result.set(None);
                    owner.send::<p::Settled>(&()).await.map_err(Error::from)?;
                    continue;
                }
                if let Ok(token) =
                    tokens.validate(clock.now(), address, destination_id, source_id, token)
                {
                    {
                        let mut slot = admitted
                            .try_borrow_mut()
                            .map_err(|_| "Retry admitted borrow")?;
                        if slot.is_some() {
                            return Err("Retry admitted slot already occupied".into());
                        }
                        *slot = Some(AdmittedInitial {
                            address: observation.address,
                            datagram: observation.datagram,
                            ecn: observation.ecn,
                            token,
                        });
                    }
                    owner.send::<p::Admitted>(&()).await.map_err(Error::from)?;
                    owner.send::<p::Stop>(&()).await.map_err(Error::from)?;
                    owner.recv::<p::Stopped>().await.map_err(Error::from)?;
                    owner.send::<p::Joined>(&()).await.map_err(Error::from)?;
                    return Ok(());
                }
            }
            owner.send::<p::NoSend>(&()).await.map_err(Error::from)?;
            owner.recv::<p::NoSendSeen>().await.map_err(Error::from)?;
            owner.send::<p::Ignored>(&()).await.map_err(Error::from)?;
        }
    };
    let outgoing = async {
        loop {
            let selected = output.offer().await.map_err(Error::from)?;
            match selected.label() {
                1 => {
                    selected.recv::<p::Datagram>().await.map_err(Error::from)?;
                    let packet = reply
                        .try_borrow_mut()
                        .map_err(|_| "Retry reply borrow")?
                        .take()
                        .ok_or("Retry missing reply")?;
                    let result = socket
                        .send_to_path(&packet.bytes, packet.address, Codepoint::NotEct)
                        .await;
                    let accepted = matches!(result, Ok(size) if size == packet.bytes.len());
                    if send_result.get().is_some() {
                        return Err("Retry result still owned".into());
                    }
                    send_result.set(Some(if accepted {
                        DecisionArm::Left
                    } else {
                        DecisionArm::Right
                    }));
                    if accepted {
                        output.send::<p::Sent>(&()).await.map_err(Error::from)?;
                    } else {
                        output.send::<p::Rejected>(&()).await.map_err(Error::from)?;
                    }
                }
                9 => {
                    selected.recv::<p::NoSend>().await.map_err(Error::from)?;
                    output
                        .send::<p::NoSendSeen>(&())
                        .await
                        .map_err(Error::from)?;
                }
                7 => {
                    selected.recv::<p::Stop>().await.map_err(Error::from)?;
                    output.send::<p::Stopped>(&()).await.map_err(Error::from)?;
                    return Ok(());
                }
                label => return Err(Error::Label(label)),
            }
        }
    };
    join2(incoming, join2(validation, outgoing)).await?;
    let admitted = admitted
        .try_borrow_mut()
        .map_err(|_| "Retry admitted borrow")?
        .take()
        .ok_or("Retry missing admitted")?;
    Ok(admitted)
}
