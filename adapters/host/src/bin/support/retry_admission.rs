//! Actual server Retry admission, written as the three projected locals.
//! Packet/token checks are data validation; progression belongs to Hibana.
use super::{
    Result,
    direct_bootstrap::DATAGRAM,
    direct_wire::{HostClock, HostSocket},
};
use hibana::runtime::{
    SessionKitStorage,
    ids::SessionId,
    resolver::{DecisionArm, ResolverError, ResolverRef},
};
use hibana_quic::{
    carrier::CarrierStorage,
    connection::Clock,
    ecn::Codepoint,
    packet::{Header, LongType, PacketIter},
    path::Address,
    retry::{self, ClientAddress, RetryTokens, TokenContext, ValidatedToken, protocol as p},
    runtime::join2,
};
use std::cell::{Cell, RefCell};

pub struct AdmittedInitial {
    pub address: Address,
    pub datagram: Vec<u8>,
    pub token: ValidatedToken,
}
struct Observation {
    address: Address,
    datagram: Vec<u8>,
}
struct Reply {
    address: Address,
    bytes: Vec<u8>,
}

pub async fn receive<const S: usize, const T: usize>(
    socket: &HostSocket<'_, S, T>,
    clock: &HostClock<'_, S, T>,
    tokens: &mut RetryTokens<64>,
) -> Result<AdmittedInitial> {
    let send_result = Cell::new(None);
    let programs = p::programs();
    let carrier = Box::new(CarrierStorage::<1, 16, 8>::new());
    let mut slab = vec![0; 65536];
    let mut kit = Box::new(SessionKitStorage::uninit());
    let sid = SessionId::new(u32::from_be_bytes(super::random::<4>()?));
    let session = kit
        .init()
        .rendezvous(
            &mut slab,
            carrier
                .bind(sid)
                .map_err(|e| format!("Retry carrier: {e:?}"))?,
        )
        .map_err(|e| format!("Retry session: {e:?}"))?;
    session
        .set_resolver(
            &programs.output,
            ResolverRef::<{ p::SEND_RESULT }>::decision_state(&send_result, |value| {
                value.get().ok_or_else(ResolverError::reject)
            }),
        )
        .map_err(|e| format!("Retry resolver: {e:?}"))?;
    let mut input = session
        .enter(sid, &programs.input)
        .map_err(|e| format!("Retry input: {e:?}"))?;
    let mut owner = session
        .enter(sid, &programs.owner)
        .map_err(|e| format!("Retry owner: {e:?}"))?;
    let mut output = session
        .enter(sid, &programs.output)
        .map_err(|e| format!("Retry output: {e:?}"))?;
    let observed = RefCell::<Option<Observation>>::new(None);
    let reply = RefCell::<Option<Reply>>::new(None);
    let admitted = RefCell::<Option<AdmittedInitial>>::new(None);

    let incoming = async {
        loop {
            hibana_quic::runtime::yield_now().await;
            let mut bytes = vec![0; DATAGRAM];
            let metadata = match socket.recv_from(&mut bytes).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                Err(error) => return Err(format!("Retry receive: {error}")),
            };
            bytes.truncate(metadata.len);
            {
                let mut slot = observed
                    .try_borrow_mut()
                    .map_err(|_| "Retry observed borrow")?;
                if slot.is_some() {
                    return Err("Retry observed slot already occupied".into());
                }
                *slot = Some(Observation {
                    address: Address {
                        local: metadata.local,
                        remote: metadata.source,
                    },
                    datagram: bytes,
                });
            }
            input
                .send::<p::Observed>(&())
                .await
                .map_err(|e| format!("Retry observed: {e:?}"))?;
            let selected = input
                .offer()
                .await
                .map_err(|e| format!("Retry input outcome: {e:?}"))?;
            match selected.label() {
                4 => {
                    selected
                        .recv::<p::Settled>()
                        .await
                        .map_err(|e| format!("Retry settled: {e:?}"))?;
                }
                5 => {
                    selected
                        .recv::<p::Ignored>()
                        .await
                        .map_err(|e| format!("Retry ignored: {e:?}"))?;
                }
                6 => {
                    selected
                        .recv::<p::Admitted>()
                        .await
                        .map_err(|e| format!("Retry admitted: {e:?}"))?;
                    input
                        .recv::<p::Joined>()
                        .await
                        .map_err(|e| format!("Retry input join: {e:?}"))?;
                    return Ok::<(), String>(());
                }
                label => return Err(format!("Retry input label: {label}")),
            }
        }
    };
    let validation = async {
        loop {
            owner
                .recv::<p::Observed>()
                .await
                .map_err(|e| format!("Retry owner observation: {e:?}"))?;
            let observation = observed
                .try_borrow_mut()
                .map_err(|_| "Retry observed borrow")?
                .take()
                .ok_or_else(|| "Retry missing observed".to_owned())?;
            let packet = PacketIter::new(&observation.datagram, 8, 8)
                .ok()
                .and_then(|mut packets| packets.next())
                .and_then(std::result::Result::ok);
            if let Some(packet) = packet.as_ref()
                && let Header::UnsupportedVersion {
                    destination_id,
                    source_id,
                    ..
                } = packet.header
                && destination_id.len() <= 20
                && source_id.len() <= 20
            {
                let mut bytes = vec![0; 51];
                bytes[0] = 0x80 | (super::random::<1>()?[0] & 0x7f);
                let mut end = 5;
                bytes[end] = source_id.len() as u8;
                end += 1;
                bytes[end..end + source_id.len()].copy_from_slice(source_id);
                end += source_id.len();
                bytes[end] = destination_id.len() as u8;
                end += 1;
                bytes[end..end + destination_id.len()].copy_from_slice(destination_id);
                end += destination_id.len();
                bytes[end..end + 4].copy_from_slice(&hibana_quic::packet::QUIC_V1.to_be_bytes());
                end += 4;
                if end > observation.datagram.len().saturating_mul(3) {
                    return Err("Version response amplification bound".into());
                }
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
                owner
                    .send::<p::Datagram>(&())
                    .await
                    .map_err(|e| format!("Version response publish: {e:?}"))?;
                let result = owner
                    .offer()
                    .await
                    .map_err(|e| format!("Version response result: {e:?}"))?;
                match result.label() {
                    2 => {
                        result
                            .recv::<p::Sent>()
                            .await
                            .map_err(|e| format!("Version response sent: {e:?}"))?;
                    }
                    3 => {
                        result
                            .recv::<p::Rejected>()
                            .await
                            .map_err(|e| format!("Version response rejected: {e:?}"))?;
                    }
                    label => return Err(format!("Version response label: {label}")),
                }
                send_result.set(None);
                owner
                    .send::<p::Settled>(&())
                    .await
                    .map_err(|e| format!("Version response settle: {e:?}"))?;
                continue;
            }
            if observation.datagram.len() >= 1200
                && let Some(packet) = packet
                && let Header::Long {
                    kind: LongType::Initial,
                    destination_id,
                    source_id,
                    token,
                    ..
                } = packet.header
                && destination_id.len() >= 8
                && super::initial_integrity(&packet).is_some()
            {
                let address = match observation.address.remote {
                    std::net::SocketAddr::V4(v4) => ClientAddress::V4 {
                        ip: v4.ip().octets(),
                        port: v4.port(),
                    },
                    std::net::SocketAddr::V6(v6) => ClientAddress::V6 {
                        ip: v6.ip().octets(),
                        port: v6.port(),
                    },
                };
                if token.is_empty() {
                    let retry_source = super::random::<8>()?;
                    let mut token = [0; retry::TOKEN_LEN];
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
                        .map_err(|e| format!("Retry token issue: {e:?}"))?;
                    let mut bytes = vec![0; DATAGRAM];
                    let mut scratch = vec![0; DATAGRAM + 21];
                    let size = retry::encode_retry(
                        destination_id,
                        source_id,
                        &retry_source,
                        &token[..count],
                        0,
                        &mut bytes,
                        &mut scratch,
                    )
                    .map_err(|e| format!("Retry packet: {e:?}"))?;
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
                    owner
                        .send::<p::Datagram>(&())
                        .await
                        .map_err(|e| format!("Retry publish: {e:?}"))?;
                    let result = owner
                        .offer()
                        .await
                        .map_err(|e| format!("Retry publication result: {e:?}"))?;
                    match result.label() {
                        2 => {
                            result
                                .recv::<p::Sent>()
                                .await
                                .map_err(|e| format!("Retry sent: {e:?}"))?;
                        }
                        3 => {
                            result
                                .recv::<p::Rejected>()
                                .await
                                .map_err(|e| format!("Retry rejected: {e:?}"))?;
                        }
                        label => return Err(format!("Retry publication label: {label}")),
                    }
                    send_result.set(None);
                    owner
                        .send::<p::Settled>(&())
                        .await
                        .map_err(|e| format!("Retry settle: {e:?}"))?;
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
                            token,
                        });
                    }
                    owner
                        .send::<p::Admitted>(&())
                        .await
                        .map_err(|e| format!("Retry admit: {e:?}"))?;
                    owner
                        .send::<p::Stop>(&())
                        .await
                        .map_err(|e| format!("Retry stop: {e:?}"))?;
                    owner
                        .recv::<p::Stopped>()
                        .await
                        .map_err(|e| format!("Retry stopped: {e:?}"))?;
                    owner
                        .send::<p::Joined>(&())
                        .await
                        .map_err(|e| format!("Retry joined: {e:?}"))?;
                    return Ok(());
                }
            }
            owner
                .send::<p::NoSend>(&())
                .await
                .map_err(|e| format!("Retry no-send: {e:?}"))?;
            owner
                .recv::<p::NoSendSeen>()
                .await
                .map_err(|e| format!("Retry no-send seen: {e:?}"))?;
            owner
                .send::<p::Ignored>(&())
                .await
                .map_err(|e| format!("Retry discard: {e:?}"))?;
        }
    };
    let outgoing = async {
        loop {
            let selected = output
                .offer()
                .await
                .map_err(|e| format!("Retry output choice: {e:?}"))?;
            match selected.label() {
                1 => {
                    selected
                        .recv::<p::Datagram>()
                        .await
                        .map_err(|e| format!("Retry output receive: {e:?}"))?;
                    let packet = reply
                        .try_borrow_mut()
                        .map_err(|_| "Retry reply borrow")?
                        .take()
                        .ok_or_else(|| "Retry missing reply".to_owned())?;
                    let result = socket
                        .send_from(&packet.bytes, packet.address, Codepoint::NotEct)
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
                        output
                            .send::<p::Sent>(&())
                            .await
                            .map_err(|e| format!("Retry accepted edge: {e:?}"))?;
                    } else {
                        output
                            .send::<p::Rejected>(&())
                            .await
                            .map_err(|e| format!("Retry rejection edge: {e:?}"))?;
                    }
                }
                9 => {
                    selected
                        .recv::<p::NoSend>()
                        .await
                        .map_err(|e| format!("Retry discard output: {e:?}"))?;
                    output
                        .send::<p::NoSendSeen>(&())
                        .await
                        .map_err(|e| format!("Retry discard reply: {e:?}"))?;
                }
                7 => {
                    selected
                        .recv::<p::Stop>()
                        .await
                        .map_err(|e| format!("Retry output stop: {e:?}"))?;
                    output
                        .send::<p::Stopped>(&())
                        .await
                        .map_err(|e| format!("Retry output stopped: {e:?}"))?;
                    return Ok(());
                }
                label => return Err(format!("Retry output label: {label}")),
            }
        }
    };
    join2(incoming, join2(validation, outgoing)).await?;
    let admitted = admitted
        .try_borrow_mut()
        .map_err(|_| "Retry admitted borrow")?
        .take()
        .ok_or_else(|| "Retry missing admitted".to_owned())?;
    eprintln!("Retry admission joined with validated token");
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use super::super::direct_wire::{HostReactor, before_deadline};
    use super::*;
    use hibana_quic::packet::{LongHeader, encode_long_header};
    use rand_core::OsRng;
    use std::{
        net::UdpSocket,
        time::{Duration, Instant},
    };

    fn initial(destination: &[u8], token: &[u8], pn: u64) -> Vec<u8> {
        let mut bytes = vec![0; DATAGRAM];
        let header = LongHeader {
            kind: LongType::Initial,
            destination_id: destination,
            source_id: b"client01",
            token,
            packet_number: pn,
            packet_number_len: 4,
        };
        let header_len = encode_long_header(&header, 1176, &mut bytes).unwrap();
        let mut key = hibana_quic::crypto::initial_keys(destination)
            .unwrap()
            .client;
        let (aad, payload) = bytes[..header_len + 1176].split_at_mut(header_len);
        payload[0] = 1; // PING plus padding: this fixture tests admission, not TLS.
        key.seal(pn, aad, payload, 1160).unwrap();
        key.protect_header(&mut bytes[..header_len + 1176], header_len - 4)
            .unwrap();
        bytes.truncate(header_len + 1176);
        bytes
    }

    #[test]
    fn native_retry_admits_only_the_actual_valid_token_and_joins_output() {
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let server = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let client = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();
        let clock = HostClock::new(&reactor, Instant::now());
        let mut tokens = RetryTokens::<64>::generate(&mut OsRng, 7, 1_000_000).unwrap();
        let admitted = RefCell::new(None);
        let expected = RefCell::new(None);
        reactor
            .block_on(before_deadline(
                &clock,
                clock.start + Duration::from_secs(2),
                join2(
                    async {
                        let value = receive(&server, &clock, &mut tokens).await?;
                        *admitted.borrow_mut() = Some(value);
                        Ok(())
                    },
                    async {
                        let mut probe = vec![0; 1207];
                        probe[..7].copy_from_slice(b"\xc0WAIT\x00\x00");
                        client
                            .send_to(&probe, server_addr, Codepoint::NotEct)
                            .await
                            .map_err(|e| e.to_string())?;
                        let mut version = [0; 64];
                        let vn = client
                            .recv_from(&mut version)
                            .await
                            .map_err(|e| e.to_string())?;
                        assert_eq!(vn.source, server_addr);
                        assert_eq!(&version[1..vn.len], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                        client
                            .send_to(b"invalid input", server_addr, Codepoint::NotEct)
                            .await
                            .map_err(|e| e.to_string())?;
                        client
                            .send_to(
                                &initial(b"original", &[], 0),
                                server_addr,
                                Codepoint::NotEct,
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                        let mut reply = vec![0; DATAGRAM];
                        let received = client
                            .recv_from(&mut reply)
                            .await
                            .map_err(|e| e.to_string())?;
                        assert_eq!(received.source, server_addr);
                        let mut scratch = vec![0; DATAGRAM + 21];
                        let checked = retry::validate_retry(
                            b"original",
                            b"client01",
                            &reply[..received.len],
                            retry::TOKEN_LEN,
                            &mut scratch,
                        )
                        .unwrap();
                        let source = checked.source_id().to_vec();
                        let token = checked.token().to_vec();
                        let mut corrupt = token.clone();
                        corrupt[retry::TOKEN_LEN - 1] ^= 1;
                        client
                            .send_to(
                                &initial(&source, &corrupt, 1),
                                server_addr,
                                Codepoint::NotEct,
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                        client
                            .send_to(&initial(&source, &token, 2), server_addr, Codepoint::NotEct)
                            .await
                            .map_err(|e| e.to_string())?;
                        *expected.borrow_mut() = Some((source, token));
                        Ok::<(), String>(())
                    },
                ),
            ))
            .unwrap()
            .unwrap();
        let value = admitted.into_inner().unwrap();
        let (source, token) = expected.into_inner().unwrap();
        assert_eq!(value.address.remote, client_addr);
        assert_eq!(value.token.original_destination_id(), b"original");
        assert_eq!(value.token.retry_source_id(), source);
        assert_eq!(value.token.client_source_id(), b"client01");
        assert_eq!(tokens.issued_tokens(), 1);
        assert!(tokens.failed_authentications() >= 1);
        let packet = PacketIter::new(&value.datagram, 8, 8)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let Header::Long {
            token: admitted_token,
            ..
        } = packet.header
        else {
            panic!("Initial")
        };
        assert_eq!(admitted_token, token);
        assert_eq!(
            reactor.active_resources(),
            (2, 0),
            "admission left a timer owner"
        );
        drop(server);
        drop(client);
        assert_eq!(reactor.active_resources(), (0, 0));
    }
}
