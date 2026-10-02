//! Serializer fixtures only: this program never runs a network connection.
#![allow(dead_code)]
#[path = "../../src/trace.rs"]
mod trace;
mod trace_cases;
use std::io::Write;
use trace::*;

fn emit(writer: &mut QlogWriter<'_>, at: u64, event: Event) {
    writer.push(at, event).unwrap();
    std::io::stdout().write_all(writer.pending()).unwrap();
    writer.consume(writer.pending().len()).unwrap();
}

fn main() {
    let mut buffer = [0; 1024];
    let mut writer = QlogWriter::new(&mut buffer, VantagePoint::Client).unwrap();
    for event in trace_cases::events() {
        emit(&mut writer, 1, event);
    }
    for packet_type in [
        PacketType::Initial,
        PacketType::Handshake,
        PacketType::ZeroRtt,
        PacketType::OneRtt,
        PacketType::Retry,
        PacketType::VersionNegotiation,
        PacketType::StatelessReset,
        PacketType::Unknown,
    ] {
        emit(
            &mut writer,
            1001,
            Event::Packet {
                direction: Direction::Received,
                header: PacketHeader {
                    packet_type,
                    packet_number: None,
                    key_phase: None,
                },
                datagram_id: None,
            },
        );
    }
    for reason in [
        DropReason::InternalError,
        DropReason::Rejected,
        DropReason::Unsupported,
        DropReason::Invalid,
        DropReason::Duplicate,
        DropReason::ConnectionUnknown,
        DropReason::DecryptionFailure,
        DropReason::KeyUnavailable,
        DropReason::General,
    ] {
        emit(
            &mut writer,
            1001,
            Event::PacketDropped {
                packet_type: PacketType::Unknown,
                datagram_id: None,
                reason,
            },
        );
    }
    for ecn in [Ecn::NotEct, Ecn::Ect0, Ecn::Ect1, Ecn::Ce] {
        emit(
            &mut writer,
            1001,
            Event::Datagram {
                direction: Direction::Sent,
                payload_len: 0,
                datagram_id: 0,
                ecn,
            },
        );
    }
    for trigger in [LossTrigger::TimeThreshold, LossTrigger::ReorderingThreshold] {
        emit(
            &mut writer,
            1001,
            Event::PacketLost {
                header: PacketHeader {
                    packet_type: PacketType::OneRtt,
                    packet_number: Some(1),
                    key_phase: Some(3),
                },
                trigger: Some(trigger),
            },
        );
    }
    for owner in [VantagePoint::Client, VantagePoint::Server] {
        for trigger in [
            KeyUpdateTrigger::Tls,
            KeyUpdateTrigger::LocalUpdate,
            KeyUpdateTrigger::RemoteUpdate,
        ] {
            emit(
                &mut writer,
                u64::MAX,
                Event::ApplicationKeyUpdated {
                    owner,
                    generation: u64::MAX,
                    trigger,
                },
            );
        }
    }
}
