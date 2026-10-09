
use core::cell::RefCell;
use hibana::runtime::ids::SessionId;
use hibana_quic::quic::application::imp::owned::DATAGRAM;
use hibana_quic::quic::imp::kernel::packet::LongHeader;
use hibana_quic::quic::imp::kernel::packet::encode_long_header;
use hibana_quic::quic::imp::kernel::packet::{Header, LongType, PacketIter};
use hibana_quic::quic::retry::{imp::RetryTokens, local::server::receive};
use hibana_quic::quic::{ecn::imp::Codepoint, retry};
use hibana_quic::runtime::join2;
use hibana_quic_pal::entropy::KernelEntropy;
use hibana_quic_pal::io::HostClock;
use hibana_quic_pal::io::{HostReactor, before_deadline};
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
    let mut tokens = RetryTokens::<64>::generate(&mut KernelEntropy, 7, 1_000_000).unwrap();
    let admitted = RefCell::new(None);
    let expected = RefCell::new(None);
    reactor
        .block_on(before_deadline(
            &clock,
            clock.start + Duration::from_secs(2),
            join2(
                async {
                    let mut slab = vec![0; 65536];
                    let mut scratch = vec![0; DATAGRAM + 21];
                    let value = receive::<DATAGRAM>(
                        &server,
                        &clock,
                        &mut tokens,
                        &mut KernelEntropy,
                        SessionId::new(1),
                        &mut slab,
                        &mut scratch,
                    )
                    .await
                    .map_err(|e| format!("{e:?}"))?;
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
                    let checked = retry::imp::validate_retry(
                        b"original",
                        b"client01",
                        &reply[..received.len],
                        retry::imp::TOKEN_LEN,
                        &mut scratch,
                    )
                    .unwrap();
                    let source = checked.source_id().to_vec();
                    let token = checked.token().to_vec();
                    let mut corrupt = token.clone();
                    corrupt[retry::imp::TOKEN_LEN - 1] ^= 1;
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
