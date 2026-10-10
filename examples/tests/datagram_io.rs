//! Actual kernel datagrams through the common QUIC I/O boundary.

use hibana_quic::{
    io::{Address, Codepoint},
    io::{DatagramRx, DatagramTx, IoError},
};
const DATAGRAM: usize = hibana_quic::quic::application::storage::DATAGRAM;

use core::cell::Cell;
use core::time::Duration;
use hibana_quic::io::Clock as ClockCapability;
use hibana_quic::quic::datagram::{Receive, Statistics, Transmit};
use hibana_quic_pal::unix::{
    Instant,
    clock::{Clock, before_deadline},
    reactor::Reactor,
};
use std::net::UdpSocket;
#[test]
fn accepted_send_has_real_bytes_address_and_monotonic_receipt() {
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .unwrap();
    let socket = reactor
        .register_udp(
            hibana_quic_pal::unix::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
        )
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let clock = Clock::new(&reactor, Instant::now());
    let statistics = Statistics::default();
    let address = Address {
        local: socket.local_addr().unwrap(),
        remote: peer.local_addr().unwrap(),
    };
    let mut tx = Transmit {
        alternate: None,
        socket: &socket,
        address,
        clock: &clock,
        statistics: &statistics,
    };
    let accepted = reactor
        .block_on(tx.send(b"direct role output", Codepoint::NotEct))
        .unwrap()
        .unwrap();
    let mut bytes = [0; 32];
    let (len, source) = peer.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..len], b"direct role output");
    assert_eq!(source, address.local);
    assert_eq!(statistics.last_accepted.get(), Some(accepted));
    assert!(accepted <= clock.now());
}
#[test]
fn actual_transmit_marks_each_datagram_and_rejects_ce_before_send() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let reactor = {
            static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
                hibana_quic_pal::unix::reactor::WakeStorage::new();
            Reactor::<4, 8>::new(&WAKE)
        }
        .unwrap();
        let socket = reactor
            .register_udp(hibana_quic_pal::unix::UdpSocket::bind(bind.parse().unwrap()).unwrap())
            .unwrap();
        let raw = hibana_quic_pal::unix::UdpSocket::bind(bind.parse().unwrap()).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let remote = raw.local_addr().unwrap();
        let mut peer = hibana_quic_pal::unix::udp::UdpMetadataSocket::new(raw).unwrap();
        let clock = Clock::new(&reactor, Instant::now());
        let statistics = Statistics::default();
        let address = Address {
            local: socket.local_addr().unwrap(),
            remote,
        };
        let mut tx = Transmit {
            alternate: None,
            socket: &socket,
            address,
            clock: &clock,
            statistics: &statistics,
        };
        for mark in [
            Codepoint::Ect0,
            Codepoint::NotEct,
            Codepoint::Ect1,
            Codepoint::NotEct,
        ] {
            let at = reactor
                .block_on(tx.send(b"real marked send", mark))
                .unwrap()
                .unwrap();
            let mut bytes = [0; 32];
            let got = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..got.len], b"real marked send");
            assert_eq!(got.ecn, Some(mark));
            assert_eq!(got.source, address.local);
            assert!(at <= clock.now());
        }
        assert_eq!(statistics.sent.get(), 4);
        let previous = statistics.last_accepted.get();
        assert_eq!(
            reactor
                .block_on(tx.send(b"forbidden CE", Codepoint::Ce))
                .unwrap(),
            Err(IoError::Rejected)
        );
        assert_eq!(statistics.sent.get(), 4);
        assert_eq!(statistics.last_accepted.get(), previous);
    }
}
#[test]
fn actual_native_receive_preserves_ecn_with_its_datagram() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let reactor = {
            static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
                hibana_quic_pal::unix::reactor::WakeStorage::new();
            Reactor::<4, 8>::new(&WAKE)
        }
        .unwrap();
        let socket = reactor
            .register_udp(hibana_quic_pal::unix::UdpSocket::bind(bind.parse().unwrap()).unwrap())
            .unwrap();
        let raw = hibana_quic_pal::unix::UdpSocket::bind(bind.parse().unwrap()).unwrap();
        let remote = raw.local_addr().unwrap();
        let peer = hibana_quic_pal::unix::udp::UdpMetadataSocket::new(raw).unwrap();
        let clock = Clock::new(&reactor, Instant::now());
        let statistics = Statistics::default();
        let address = Address {
            local: socket.local_addr().unwrap(),
            remote,
        };
        let mut rx = Receive::<_, { DATAGRAM }> {
            alternate: None,
            socket: &socket,
            address,
            first: None,
            routed: None,
            statistics: &statistics,
        };
        for mark in [
            Codepoint::NotEct,
            Codepoint::Ect0,
            Codepoint::Ect1,
            Codepoint::Ce,
        ] {
            // CE is injected by this explicit metadata fixture only.
            peer.send_to(b"measured metadata", address.local, mark)
                .unwrap();
            let mut bytes = [0; 32];
            let observed = reactor
                .block_on(before_deadline(
                    &clock,
                    Instant::now() + Duration::from_secs(1),
                    async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
                ))
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..observed.len], b"measured metadata");
            assert_eq!(observed.ecn, Some(mark));
        }
        assert_eq!(statistics.received.get(), 4);
    }
}

#[test]
fn receive_preserves_each_physical_path_for_core_admission() {
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .unwrap();
    let socket = reactor
        .register_udp(
            hibana_quic_pal::unix::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
        )
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let foreign = UdpSocket::bind("127.0.0.1:0").unwrap();
    let clock = Clock::new(&reactor, Instant::now());
    let statistics = Statistics::default();
    let address = Address {
        local: socket.local_addr().unwrap(),
        remote: peer.local_addr().unwrap(),
    };
    foreign.send_to(b"foreign", address.local).unwrap();
    peer.send_to(b"admitted", address.local).unwrap();
    let mut rx = Receive::<_, { DATAGRAM }> {
        alternate: None,
        socket: &socket,
        address,
        first: None,
        routed: None,
        statistics: &statistics,
    };
    let mut bytes = [0; 32];
    let len = reactor
        .block_on(before_deadline(
            &clock,
            clock.start + Duration::from_secs(1),
            async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..len.len], b"foreign");
    assert_eq!(
        len.path,
        Some(Address {
            local: address.local,
            remote: foreign.local_addr().unwrap()
        })
    );
    assert_eq!(len.ecn, Some(Codepoint::NotEct));
    let admitted = reactor
        .block_on(before_deadline(
            &clock,
            clock.start + Duration::from_secs(1),
            async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..admitted.len], b"admitted");
    assert_eq!(admitted.path, Some(address));
    // These are physical observations, not amplification or authentication credit.
    // The handshake prefix filters the initial address before credit; the
    // application path owner only sees observations after AEAD admission.
    assert_eq!(statistics.received.get(), 2);
    assert_eq!(statistics.foreign.get(), 1);
}
#[test]
fn expired_hard_deadline_never_polls_ready_submission() {
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .unwrap();
    let clock = Clock::new(&reactor, Instant::now());
    let attempted = Cell::new(false);
    let result = reactor
        .block_on(before_deadline(&clock, clock.start, async {
            attempted.set(true);
            Ok::<_, core::convert::Infallible>(())
        }))
        .unwrap();
    assert!(result.is_err());
    assert!(!attempted.get());
}
#[test]
fn idle_timeout_parks_and_cancels_the_registered_receive() {
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .unwrap();
    let socket = reactor
        .register_udp(
            hibana_quic_pal::unix::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
        )
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let clock = Clock::new(&reactor, Instant::now());
    let statistics = Statistics::default();
    let address = Address {
        local: socket.local_addr().unwrap(),
        remote: peer.local_addr().unwrap(),
    };
    let mut rx = Receive::<_, { DATAGRAM }> {
        alternate: None,
        socket: &socket,
        address,
        first: None,
        routed: None,
        statistics: &statistics,
    };
    let mut bytes = [0; 32];
    let result = reactor
        .block_on(before_deadline(
            &clock,
            clock.start + Duration::from_millis(10),
            async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
        ))
        .unwrap();
    assert!(result.is_err());
    assert!(
        reactor.statistics().polls <= 3,
        "idle socket must sleep in epoll"
    );
    assert!(reactor.statistics().timer_events > 0);
    peer.send_to(b"after cancellation", address.local).unwrap();
    let len = reactor
        .block_on(before_deadline(
            &clock,
            Instant::now() + Duration::from_secs(1),
            async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..len.len], b"after cancellation");
    assert_eq!(len.ecn, Some(Codepoint::NotEct));
}
#[test]
fn rejected_send_never_records_acceptance() {
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .unwrap();
    let socket = reactor
        .register_udp(
            hibana_quic_pal::unix::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
        )
        .unwrap();
    let clock = Clock::new(&reactor, Instant::now());
    let statistics = Statistics::default();
    let address = Address {
        local: socket.local_addr().unwrap(),
        remote: "[::1]:4433".parse().unwrap(),
    };
    let mut tx = Transmit {
        alternate: None,
        socket: &socket,
        address,
        clock: &clock,
        statistics: &statistics,
    };
    assert_eq!(
        reactor
            .block_on(tx.send(b"invalid family", Codepoint::NotEct))
            .unwrap(),
        Err(IoError::Rejected)
    );
    assert_eq!(statistics.sent.get(), 0);
    assert_eq!(statistics.last_accepted.get(), None);
}
