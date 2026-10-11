//! Deliberately invented serializer test inputs, never endpoint/interop evidence.
use crate::trace::{
    Direction, DropReason, Ecn, Error, Event, KeyUpdateTrigger, LossTrigger, PacketHeader,
    PacketType, QlogWriter, VantagePoint,
};

pub fn events() -> [Event; 7] {
    [
        Event::Packet {
            direction: Direction::Sent,
            header: PacketHeader {
                packet_type: PacketType::Initial,
                packet_number: Some(0),
                key_phase: None,
            },
            datagram_id: Some(7),
        },
        Event::Packet {
            direction: Direction::Received,
            header: PacketHeader {
                packet_type: PacketType::OneRtt,
                packet_number: Some((1 << 62) - 1),
                key_phase: Some(u64::MAX),
            },
            datagram_id: None,
        },
        Event::Datagram {
            direction: Direction::Sent,
            payload_len: 1200,
            datagram_id: 7,
            ecn: Ecn::NotEct,
        },
        Event::Datagram {
            direction: Direction::Received,
            payload_len: u16::MAX,
            datagram_id: u32::MAX,
            ecn: Ecn::Ce,
        },
        Event::PacketDropped {
            packet_type: PacketType::Unknown,
            datagram_id: Some(u32::MAX),
            reason: DropReason::DecryptionFailure,
        },
        Event::PacketLost {
            header: PacketHeader {
                packet_type: PacketType::Handshake,
                packet_number: Some(27),
                key_phase: None,
            },
            trigger: Some(LossTrigger::ReorderingThreshold),
        },
        Event::ApplicationKeyUpdated {
            owner: VantagePoint::Server,
            generation: u64::MAX,
            trigger: KeyUpdateTrigger::RemoteUpdate,
        },
    ]
}

/// Shared exercised code for the allocation counter and allocator-free target
/// link. There is no network/TLS activity and no key material in these inputs.
pub fn exercise() {
    let mut too_small = [0xa5; 1];
    assert!(matches!(
        QlogWriter::new(&mut too_small, VantagePoint::Client),
        Err(Error::Capacity { .. })
    ));
    assert_eq!(too_small, [0xa5]);
    let mut buffer = [0xa5; 512];
    let mut writer = QlogWriter::new(&mut buffer, VantagePoint::Client).unwrap();
    assert_eq!(writer.consume(usize::MAX), Err(Error::InvalidConsume));
    assert_eq!(
        writer.push(
            0,
            Event::Packet {
                direction: Direction::Received,
                header: PacketHeader {
                    packet_type: PacketType::Initial,
                    packet_number: Some(1 << 62),
                    key_phase: None,
                },
                datagram_id: None,
            }
        ),
        Err(Error::InvalidPacketNumber)
    );
    for (time, event) in events().into_iter().enumerate() {
        loop {
            match writer.push(time as u64, core::hint::black_box(event)) {
                Ok(()) => break,
                Err(Error::Capacity {
                    required,
                    available,
                }) => {
                    assert!(required > available);
                    let length = writer.pending().len();
                    assert!(length > 0);
                    core::hint::black_box(writer.pending());
                    writer.consume(length.min(31)).unwrap();
                }
                Err(error) => panic!("unexpected trace error: {error:?}"),
            }
        }
    }
    assert_eq!(writer.push(0, events()[0]), Err(Error::TimeWentBackwards));
    let count = writer.pending().len();
    core::hint::black_box(writer.pending());
    writer.consume(count).unwrap();
    assert_eq!(writer.available(), writer.capacity());
    writer.push(u64::MAX, events()[6]).unwrap();
    let count = writer.pending().len();
    core::hint::black_box(writer.pending());
    writer.consume(count).unwrap();
    assert!(writer.pending().is_empty());
}
