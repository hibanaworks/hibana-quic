//! Real rustls/AEAD + Hibana wire tests. This allocating TLS backend is a
//! development reference, not evidence of allocation-free TLS or Neqo interop.
//! Initial keys and each complete TLS Provider run in real projected actor tasks.
//! Remaining non-key Driver services are still a separate migration. Original
//! data-plane assertions are preserved across the async API migration.
#![allow(long_running_const_eval)]
#[path = "support/async_initial_pair.rs"]
mod async_initial_pair;
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::handshake_endpoint::InitialProtection;
use hibana_quic::transport_endpoint as transport;
pub use hibana_quic::{accounting, handshake_endpoint, packet, streams, tls};
use hibana_quic::{
    carrier::{CarrierStorage, LocalCarrier},
    driver::{Driver, Roles},
    handshake::CryptoBuffer,
    handshake_endpoint::{Config, HandshakeEndpoint, Side},
    packet::encode_varint,
    protocol::*,
    streams::{Limits, PacketReference, SendChunk, StreamSlot},
};
use hibana_quic_reference_tls::{RustlsProvider, rustls};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    RootCertStore,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use std::pin::pin;
use transport::TransportEndpoint;

type Endpoint<'r, 's, 'tc, 'ts, 'i, 'q> =
    TransportEndpoint<'r, 's, 'tc, 'ts, 1024, 1024, 16, 64, InitialProtection<'i, 'q>>;
fn parameters(id: &[u8], original: Option<&[u8]>, limits: Limits) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0; 8];
    for (kind, data) in [(15, Some(id)), (0, original)] {
        if let Some(data) = data {
            let n = encode_varint(kind, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            let n = encode_varint(data.len() as u64, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            out.extend_from_slice(data);
        }
    }
    for (kind, value) in [
        (4, limits.max_data),
        (5, limits.stream_data_bidi_local),
        (6, limits.stream_data_bidi_remote),
        (7, limits.stream_data_uni),
        (8, limits.max_streams_bidi),
        (9, limits.max_streams_uni),
    ] {
        let mut value_bytes = [0; 8];
        let len = encode_varint(value, &mut value_bytes).unwrap();
        let n = encode_varint(kind, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
        let n = encode_varint(len as u64, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
        out.extend_from_slice(&value_bytes[..len]);
    }
    out
}
fn with_pair(
    f: impl AsyncFnOnce(&mut Endpoint<'_, '_, '_, '_, '_, '_>, &mut Endpoint<'_, '_, '_, '_, '_, '_>),
) {
    let harness = async_initial_pair::Harness::new();
    let limits = Limits {
        max_data: 2048,
        max_streams_bidi: 1,
        max_streams_uni: 0,
        stream_data_bidi_local: 1024,
        stream_data_bidi_remote: 1024,
        stream_data_uni: 1024,
    };
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let client_tls = RustlsProvider::client(
        roots,
        ServerName::try_from("localhost").unwrap(),
        parameters(b"client01", None, limits),
    )
    .unwrap();
    let server_tls = RustlsProvider::server(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        parameters(b"server01", Some(b"original"), limits),
    )
    .unwrap();
    let p0 = service_program::<INGRESS>();
    let p1 = service_program::<PACKET>();
    let p2 = service_program::<APPLICATION>();
    let p3 = service_program::<RECOVERY>();
    let p4 = service_program::<ADAPTER>();
    let p5 = service_program::<TIMER>();
    let client_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let server_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let mut client_slab = [0; 32768];
    let mut server_slab = [0; 32768];
    let mut client_kit = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let mut server_kit = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let crv = client_kit
        .init()
        .rendezvous(
            &mut client_slab,
            client_queue.bind(SessionId::new(1)).unwrap(),
        )
        .unwrap();
    let srv = server_kit
        .init()
        .rendezvous(
            &mut server_slab,
            server_queue.bind(SessionId::new(2)).unwrap(),
        )
        .unwrap();
    macro_rules! attach {
        ($rv:expr,$sid:expr) => {
            Driver::new(
                $sid,
                Roles {
                    ingress: $rv.enter(SessionId::new($sid as u32), &p0).unwrap(),
                    packet: $rv.enter(SessionId::new($sid as u32), &p1).unwrap(),
                    application: $rv.enter(SessionId::new($sid as u32), &p2).unwrap(),
                    recovery: $rv.enter(SessionId::new($sid as u32), &p3).unwrap(),
                    adapter: $rv.enter(SessionId::new($sid as u32), &p4).unwrap(),
                    timer: $rv.enter(SessionId::new($sid as u32), &p5).unwrap(),
                },
            )
        };
    }
    let mut cb0 = [0; 8192];
    let mut cb1 = [0; 8192];
    let mut cb2 = [0; 8192];
    let mut cm0 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut cm1 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut cm2 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut sb0 = [0; 8192];
    let mut sb1 = [0; 8192];
    let mut sb2 = [0; 8192];
    let mut sm0 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut sm1 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut sm2 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let cc = [
        CryptoBuffer::new(&mut cb0, &mut cm0).unwrap(),
        CryptoBuffer::new(&mut cb1, &mut cm1).unwrap(),
        CryptoBuffer::new(&mut cb2, &mut cm2).unwrap(),
    ];
    let sc = [
        CryptoBuffer::new(&mut sb0, &mut sm0).unwrap(),
        CryptoBuffer::new(&mut sb1, &mut sm1).unwrap(),
        CryptoBuffer::new(&mut sb2, &mut sm2).unwrap(),
    ];
    let mut execution = pin!(async_initial_pair::with_pair(
        client_tls,
        server_tls,
        async |client_initial, server_initial, client_tls, server_tls| {
            let client = HandshakeEndpoint::new(
                Config {
                    side: Side::Client,
                    local_id: b"client01",
                    original_destination_id: b"original",
                    generation: 1,
                },
                client_tls,
                attach!(crv, 1),
                cc,
                client_initial,
            )
            .unwrap();
            let server = HandshakeEndpoint::new(
                Config {
                    side: Side::Server,
                    local_id: b"server01",
                    original_destination_id: b"original",
                    generation: 2,
                },
                server_tls,
                attach!(srv, 2),
                sc,
                server_initial,
            )
            .unwrap();
            let mut client_streams = [const { StreamSlot::<1024>::EMPTY }; 2];
            let mut server_streams = [const { StreamSlot::<1024>::EMPTY }; 2];
            let mut client_chunks = [const { SendChunk::<1024>::EMPTY }; 4];
            let mut server_chunks = [const { SendChunk::<1024>::EMPTY }; 4];
            let mut client_refs = [PacketReference::EMPTY; 16];
            let mut server_refs = [PacketReference::EMPTY; 16];
            let mut client = TransportEndpoint::new(
                client,
                limits,
                &mut client_streams,
                &mut client_chunks,
                &mut client_refs,
                1,
            )
            .unwrap();
            let mut server = TransportEndpoint::new(
                server,
                limits,
                &mut server_streams,
                &mut server_chunks,
                &mut server_refs,
                2,
            )
            .unwrap();
            f(&mut client, &mut server).await;
            assert!(!client.is_retired() && !server.is_retired());
            client.retire_owned().await.unwrap();
            server.retire_owned().await.unwrap();
            assert!(client.is_retired() && server.is_retired());
            async_initial_pair::Completion::Retired
        }
    ));
    eprintln!(
        "host composed stream-fixture future bytes: {}",
        core::mem::size_of_val(execution.as_ref().get_ref())
    );
    harness.drive(execution.as_mut());
}
async fn transfer(
    from: &mut Endpoint<'_, '_, '_, '_, '_, '_>,
    to: &mut Endpoint<'_, '_, '_, '_, '_, '_>,
    now: u64,
) -> usize {
    let mut out = [0; 1500];
    let mut scratch = [0; 1500];
    for n in 0..64 {
        let Some(tx) = from.transmit(&mut out).await.unwrap() else {
            return n;
        };
        from.adapter_result(tx, true, now).await.unwrap();
        to.receive(&out[..tx.len], &mut scratch).await.unwrap();
    }
    panic!("bounded transfer failed to yield")
}
async fn pump(
    client: &mut Endpoint<'_, '_, '_, '_, '_, '_>,
    server: &mut Endpoint<'_, '_, '_, '_, '_, '_>,
    now: u64,
) {
    for _ in 0..32 {
        let a = transfer(client, server, now).await;
        let b = transfer(server, client, now).await;
        if a + b == 0 {
            return;
        }
    }
    panic!("wire did not become idle")
}
async fn handshake(
    client: &mut Endpoint<'_, '_, '_, '_, '_, '_>,
    server: &mut Endpoint<'_, '_, '_, '_, '_, '_>,
) {
    pump(client, server, 0).await;
    assert!(client.handshake_complete());
    assert!(server.handshake_complete());
}

#[test]
fn hq_style_request_and_five_mebibyte_encrypted_response() {
    with_pair(async |client, server| {
        handshake(client, server).await;
        let request = client.open(true).unwrap();
        client.send(request, b"GET /five-mib\r\n", true).unwrap();
        pump(client, server, 1).await;
        let response = server.streams().lookup(request.id()).unwrap();
        let read = server.read(response).unwrap();
        assert_eq!(read.first, b"GET /five-mib\r\n");
        assert!(read.fin);
        server.consume(response, 15).unwrap();
        pump(client, server, 2).await;
        const BLOCKS: usize = 5 * 1024;
        for i in 0..BLOCKS {
            let block = [(i % 251) as u8; 1024];
            server.send(response, &block, i + 1 == BLOCKS).unwrap();
            pump(client, server, (i + 3) as u64).await;
            let view = client.read(request).unwrap();
            assert_eq!(view.first, &block);
            assert!(view.second.is_empty());
            assert_eq!(view.fin, i + 1 == BLOCKS);
            client.consume(request, 1024).unwrap();
            pump(client, server, (i + 3) as u64).await;
        }
        assert_eq!(client.streams().receive_charged(), 5 * 1024 * 1024);
        client.retire_stream(request).unwrap();
        server.retire_stream(response).unwrap();
        pump(client, server, 6000).await;
        assert_eq!(
            client.streams().lookup(request.id()),
            Err(streams::Error::Retired)
        );
        assert_eq!(
            server.streams().lookup(request.id()),
            Err(streams::Error::Retired)
        );
    });
}

#[test]
fn rejected_application_output_uses_fresh_packet_number_and_keeps_bytes() {
    with_pair(async |client, server| {
        handshake(client, server).await;
        let h = client.open(true).unwrap();
        client.send(h, b"request", true).unwrap();
        let mut out = [0; 1500];
        let first = client.transmit(&mut out).await.unwrap().unwrap();
        assert!(matches!(
            client.receive(&[], &mut [0; 1500]).await,
            Err(transport::Error::Busy)
        ));
        client.adapter_result(first, false, 1).await.unwrap();
        let second = client.transmit(&mut out).await.unwrap().unwrap();
        assert!(second.packet_number.value > first.packet_number.value);
        client.adapter_result(second, true, 2).await.unwrap();
        server
            .receive(&out[..second.len], &mut [0; 1500])
            .await
            .unwrap();
        let peer = server.streams().lookup(h.id()).unwrap();
        assert_eq!(server.read(peer).unwrap().first, b"request");
        assert_eq!(server.streams().receive_charged(), 7);
    });
}

#[test]
fn lost_stream_packet_retransmits_on_pto_and_duplicates_do_not_redeliver() {
    with_pair(async |client, server| {
        handshake(client, server).await;
        let h = client.open(true).unwrap();
        client.send(h, b"request", true).unwrap();
        let mut original = [0; 1500];
        let first = client.transmit(&mut original).await.unwrap().unwrap();
        client.adapter_result(first, true, 1).await.unwrap();
        let deadline = client.next_deadline().expect("application PTO");
        client.timer(deadline).await.unwrap();
        server.timer(deadline).await.unwrap();
        let mut out = [0; 1500];
        let probe = client
            .transmit(&mut out)
            .await
            .unwrap()
            .expect("STREAM probe");
        assert!(probe.packet_number.value > first.packet_number.value);
        client.adapter_result(probe, true, deadline).await.unwrap();
        server
            .receive(&out[..probe.len], &mut [0; 1500])
            .await
            .unwrap();
        let peer = server.streams().lookup(h.id()).unwrap();
        assert_eq!(server.read(peer).unwrap().first, b"request");
        server.consume(peer, 7).unwrap();
        assert_eq!(
            server
                .receive(&out[..probe.len], &mut [0; 1500])
                .await
                .unwrap()
                .discarded,
            1
        );
        assert!(server.read(peer).unwrap().first.is_empty());
        assert_eq!(server.streams().receive_charged(), 7);
        pump(client, server, deadline + 1).await;
    });
}

#[test]
fn corrupted_one_rtt_never_reaches_stream_owner() {
    with_pair(async |client, server| {
        handshake(client, server).await;
        let h = client.open(true).unwrap();
        client.send(h, b"request", true).unwrap();
        let mut out = [0; 1500];
        let tx = client.transmit(&mut out).await.unwrap().unwrap();
        client.adapter_result(tx, true, 1).await.unwrap();
        let mut corrupt = out;
        corrupt[tx.len - 1] ^= 1;
        assert_eq!(
            server
                .receive(&corrupt[..tx.len], &mut [0; 1500])
                .await
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(
            server.streams().lookup(h.id()),
            Err(streams::Error::NotOpened)
        );
        assert!(!server.is_retired());
        server
            .receive(&out[..tx.len], &mut [0; 1500])
            .await
            .unwrap();
        let peer = server.streams().lookup(h.id()).unwrap();
        assert_eq!(server.read(peer).unwrap().first, b"request");
    });
}

#[test]
fn stop_sending_resets_only_target_direction_and_reliably_reports_final_size() {
    with_pair(async |client, server| {
        handshake(client, server).await;
        let request = client.open(true).unwrap();
        client.send(request, b"GET /slow\r\n", true).unwrap();
        pump(client, server, 1).await;
        let response = server.streams().lookup(request.id()).unwrap();
        server.consume(response, 11).unwrap();
        server.send(response, b"partial", false).unwrap();
        pump(client, server, 2).await;
        assert_eq!(client.read(request).unwrap().first, b"partial");
        client.stop(request, 42).unwrap();
        pump(client, server, 3).await;
        assert_eq!(client.read(request).unwrap().reset, Some(42));
        assert!(client.read(request).unwrap().first.is_empty());
        assert_eq!(client.streams().receive_charged(), 7);
        assert_eq!(client.acknowledge_reset(request).unwrap(), 42);
        pump(client, server, 4).await;
        client.retire_stream(request).unwrap();
        server.retire_stream(response).unwrap();
        pump(client, server, 5).await;
    });
}

#[test]
fn nineteen_ninety_nine_encrypted_streams_recycle_live_slots() {
    with_pair(async |client, server| {
        handshake(client, server).await;
        for index in 0..1999u64 {
            let request = client.open(true).unwrap();
            assert_eq!(request.id(), index * 4);
            client.send(request, b"x", true).unwrap();
            pump(client, server, index * 4 + 1).await;
            let response = server.streams().lookup(request.id()).unwrap();
            assert_eq!(server.read(response).unwrap().first, b"x");
            server.consume(response, 1).unwrap();
            server.send(response, b"y", true).unwrap();
            pump(client, server, index * 4 + 2).await;
            assert_eq!(client.read(request).unwrap().first, b"y");
            client.consume(request, 1).unwrap();
            pump(client, server, index * 4 + 3).await;
            client.retire_stream(request).unwrap();
            server.retire_stream(response).unwrap();
            pump(client, server, index * 4 + 4).await;
            assert_eq!(client.streams().live_count(), 0);
            assert_eq!(server.streams().live_count(), 0);
        }
        assert_eq!(client.streams().cumulative_opened(0), Ok(1999));
        assert_eq!(server.streams().cumulative_opened(0), Ok(1999));
    });
}

#[test]
fn lost_max_stream_data_is_reliably_repeated_by_application_pto() {
    with_pair(async |client, server| {
        handshake(client, server).await;
        let request = client.open(true).unwrap();
        client.send(request, b"x", true).unwrap();
        pump(client, server, 1).await;
        let response = server.streams().lookup(request.id()).unwrap();
        server.consume(response, 1).unwrap();
        pump(client, server, 2).await;
        server.send(response, &[7; 1024], false).unwrap();
        pump(client, server, 3).await;
        client.consume(request, 1024).unwrap();
        let mut out = [0; 1500];
        let max_data = client.transmit(&mut out).await.unwrap().unwrap();
        client.adapter_result(max_data, true, 4).await.unwrap();
        server
            .receive(&out[..max_data.len], &mut [0; 1500])
            .await
            .unwrap();
        let max_stream_data = client.transmit(&mut out).await.unwrap().unwrap();
        client
            .adapter_result(max_stream_data, true, 4)
            .await
            .unwrap();
        // The adapter accepted the stream-credit packet, but the network lost it.
        transfer(server, client, 5).await;
        assert!(matches!(
            server.send(response, b"next", true),
            Err(transport::Error::Streams(streams::Error::FlowControl))
        ));
        let deadline = client.next_deadline().expect("credit PTO is armed");
        client.timer(deadline).await.unwrap();
        server.timer(deadline).await.unwrap();
        let probe = client
            .transmit(&mut out)
            .await
            .unwrap()
            .expect("credit retransmission");
        assert!(probe.packet_number.value > max_stream_data.packet_number.value);
        client.adapter_result(probe, true, deadline).await.unwrap();
        server
            .receive(&out[..probe.len], &mut [0; 1500])
            .await
            .unwrap();
        server.send(response, b"next", true).unwrap();
        pump(client, server, deadline + 1).await;
        assert_eq!(client.read(request).unwrap().first, b"next");
        assert!(client.read(request).unwrap().fin);
    });
}

fn threshold_loss_with_credit_pending(packet_threshold: bool) {
    with_pair(async |client, server| {
        handshake(client, server).await;
        let request = client.open(true).unwrap();
        let count = if packet_threshold { 4 } else { 2 };
        for index in 0..count {
            client
                .send(request, &[b'a' + index as u8], index + 1 == count)
                .unwrap();
        }
        let mut out = [0; 1500];
        for index in 0..count {
            let tx = client.transmit(&mut out).await.unwrap().unwrap();
            client.adapter_result(tx, true, 10).await.unwrap();
            if index != 0 {
                server
                    .receive(&out[..tx.len], &mut [0; 1500])
                    .await
                    .unwrap();
            }
        }
        let response = server.streams().lookup(request.id()).unwrap();
        assert!(server.read(response).unwrap().first.is_empty());
        // A response is legal before the complete request is available. Its
        // consumption queues credit controls that must not steal the loss event.
        server.send(response, b"x", false).unwrap();
        transfer(server, client, 11).await;
        assert_eq!(client.read(request).unwrap().first, b"x");
        client.consume(request, 1).unwrap();
        let now = if packet_threshold {
            12
        } else {
            let deadline = client
                .next_deadline()
                .expect("time-threshold loss deadline");
            client.timer(deadline).await.unwrap();
            server.timer(deadline).await.unwrap();
            deadline
        };
        pump(client, server, now).await;
        let read = server.read(response).unwrap();
        assert_eq!(
            read.first,
            if packet_threshold {
                &b"abcd"[..]
            } else {
                &b"ab"[..]
            }
        );
        assert!(read.fin);
    });
}
#[test]
fn packet_threshold_requeues_exact_lost_chunk_despite_other_pending_controls() {
    threshold_loss_with_credit_pending(true);
}
#[test]
fn time_threshold_requeues_exact_lost_chunk_despite_other_pending_controls() {
    threshold_loss_with_credit_pending(false);
}
