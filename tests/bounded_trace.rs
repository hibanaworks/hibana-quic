//! Writer-component tests. These events are fixtures, not network observations.
use hibana_quic::trace::{self, *};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[path = "support/trace_cases.rs"]
mod trace_cases;

struct Counting;
thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}
fn count() {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = ALLOCS.try_with(|count| count.set(count.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn record(at_micros: u64, event: Event) -> Vec<u8> {
    let mut buffer = [0; 2048];
    let mut writer = QlogWriter::new(&mut buffer, VantagePoint::Client).unwrap();
    writer.consume(writer.pending().len()).unwrap();
    writer.push(at_micros, event).unwrap();
    writer.pending().to_vec()
}

fn schema_header(vantage: VantagePoint) -> Vec<u8> {
    let mut buffer = [0; 2048];
    QlogWriter::new(&mut buffer, vantage)
        .unwrap()
        .pending()
        .to_vec()
}

#[test]
fn construction_only_writes_schema_metadata() {
    for vantage in [VantagePoint::Client, VantagePoint::Server] {
        let bytes = schema_header(vantage);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(bytes[0], 0x1e);
        assert!(text.ends_with("}}}}\n"));
        assert_eq!(text.bytes().filter(|&byte| byte == 0x1e).count(), 1);
        assert!(!text.contains("\"name\""));
        assert!(!text.contains("\"events\""));
        assert!(text.contains(EVENT_SCHEMA));
        assert!(text[..256].contains(FILE_SCHEMA));
        assert!(text[..256].contains(MEDIA_TYPE));
        assert!(text.contains("\"clock_type\":\"monotonic\",\"epoch\":\"unknown\""));
    }
}

#[test]
fn every_short_header_capacity_is_rejected_without_any_write() {
    let required = schema_header(VantagePoint::Client).len();
    for capacity in 0..required {
        let mut buffer = [0xa5; 1024];
        assert!(matches!(
            QlogWriter::new(&mut buffer[..capacity], VantagePoint::Client),
            Err(Error::Capacity { required: actual, available })
                if actual == required && available == capacity
        ));
        assert_eq!(buffer, [0xa5; 1024]);
    }
    let mut exact = vec![0; required];
    assert_eq!(
        QlogWriter::new(&mut exact, VantagePoint::Client)
            .unwrap()
            .pending()
            .len(),
        required
    );
}

#[test]
fn all_event_capacity_boundaries_are_transactional_and_retryable() {
    let header = schema_header(VantagePoint::Client);
    for event in trace_cases::events() {
        let encoded = record(999_999, event);
        for capacity in header.len()..header.len() + encoded.len() {
            let mut buffer = vec![0xa5; capacity + 1];
            {
                let mut writer =
                    QlogWriter::new(&mut buffer[..capacity], VantagePoint::Client).unwrap();
                assert_eq!(
                    writer.push(999_999, event),
                    Err(Error::Capacity {
                        required: encoded.len(),
                        available: capacity - header.len(),
                    })
                );
                assert_eq!(writer.pending(), header);
                writer.consume(header.len()).unwrap();
                // The rejected later event did not advance the clock.
                writer.push(1, event).unwrap();
                assert_eq!(writer.pending(), record(1, event));
            }
            assert_eq!(buffer[capacity], 0xa5);
        }
        let mut exact = vec![0; header.len() + encoded.len()];
        let mut writer = QlogWriter::new(&mut exact, VantagePoint::Client).unwrap();
        writer.push(999_999, event).unwrap();
        assert_eq!(writer.available(), 0);
        assert_eq!(&writer.pending()[header.len()..], encoded);
    }
}

#[test]
fn rejected_record_preserves_the_entire_backing_buffer() {
    let header = schema_header(VantagePoint::Client);
    for event in trace_cases::events() {
        let encoded = record(0, event);
        for available in 0..encoded.len() {
            let mut buffer = vec![0xa5; header.len() + available];
            let mut expected = buffer.clone();
            expected[..header.len()].copy_from_slice(&header);
            {
                let mut writer = QlogWriter::new(&mut buffer, VantagePoint::Client).unwrap();
                assert!(matches!(writer.push(0, event), Err(Error::Capacity { .. })));
            }
            assert_eq!(buffer, expected);
        }
    }
}

#[test]
fn partial_sink_writes_compact_without_duplication_or_missing_bytes() {
    let mut expected = schema_header(VantagePoint::Server);
    let mut buffer = [0; 512];
    let mut writer = QlogWriter::new(&mut buffer, VantagePoint::Server).unwrap();
    let mut actual = Vec::new();
    for time in 0..300 {
        let event = trace_cases::events()[time % 7];
        expected.extend(record(time as u64, event));
        loop {
            match writer.push(time as u64, event) {
                Ok(()) => break,
                Err(Error::Capacity {
                    required,
                    available,
                }) => {
                    assert!(required > available);
                    assert!(required <= writer.capacity());
                    let accepted = (time % 17 + 1).min(writer.pending().len());
                    assert!(accepted > 0);
                    actual.extend_from_slice(&writer.pending()[..accepted]);
                    writer.consume(accepted).unwrap();
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    actual.extend_from_slice(writer.pending());
    writer.consume(writer.pending().len()).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(writer.available(), writer.capacity());
    assert!(writer.pending().is_empty());
}

#[test]
fn overconsume_and_time_regression_leave_pending_bytes_unchanged() {
    let mut buffer = [0; 2048];
    let mut writer = QlogWriter::new(&mut buffer, VantagePoint::Client).unwrap();
    writer.push(100, trace_cases::events()[0]).unwrap();
    let before = writer.pending().to_vec();
    for count in [writer.pending().len() + 1, usize::MAX] {
        assert_eq!(writer.consume(count), Err(Error::InvalidConsume));
        assert_eq!(writer.pending(), before);
    }
    assert_eq!(
        writer.push(99, trace_cases::events()[0]),
        Err(Error::TimeWentBackwards)
    );
    assert_eq!(writer.pending(), before);
    writer.consume(writer.pending().len()).unwrap();
    assert_eq!(
        writer.push(99, trace_cases::events()[0]),
        Err(Error::TimeWentBackwards)
    );
    writer.push(100, trace_cases::events()[0]).unwrap();
}

#[test]
fn integer_and_submillisecond_encoding_preserve_decimal_values() {
    for (micros, time) in [
        (0, "0.000"),
        (1, "0.001"),
        (999, "0.999"),
        (1000, "1.000"),
        (u64::MAX, "18446744073709551.615"),
    ] {
        let bytes = record(micros, trace_cases::events()[1]);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with(&format!("\x1e{{\"time\":{time},")));
        assert!(text.contains("\"packet_number\":\"4611686018427387903\""));
        assert!(text.contains("\"key_phase\":\"18446744073709551615\""));
        assert!(!text.contains("datagram_id"));
    }
}

#[test]
fn invalid_packet_headers_and_loss_claims_are_rejected() {
    let mut buffer = [0; 2048];
    let mut writer = QlogWriter::new(&mut buffer, VantagePoint::Client).unwrap();
    let before = writer.pending().to_vec();
    for packet_type in [
        PacketType::Retry,
        PacketType::VersionNegotiation,
        PacketType::StatelessReset,
        PacketType::Unknown,
    ] {
        let event = Event::Packet {
            direction: Direction::Sent,
            datagram_id: None,
            header: PacketHeader {
                packet_type,
                packet_number: Some(1),
                key_phase: None,
            },
        };
        assert_eq!(writer.push(99, event), Err(Error::InvalidHeader));
    }
    for packet_number in [1 << 62, u64::MAX] {
        assert_eq!(
            writer.push(
                99,
                Event::Packet {
                    direction: Direction::Sent,
                    datagram_id: None,
                    header: PacketHeader {
                        packet_type: PacketType::OneRtt,
                        packet_number: Some(packet_number),
                        key_phase: None
                    }
                }
            ),
            Err(Error::InvalidPacketNumber)
        );
    }
    for packet_type in [
        PacketType::Initial,
        PacketType::Handshake,
        PacketType::ZeroRtt,
        PacketType::Retry,
    ] {
        assert_eq!(
            writer.push(
                99,
                Event::Packet {
                    direction: Direction::Received,
                    datagram_id: None,
                    header: PacketHeader {
                        packet_type,
                        packet_number: None,
                        key_phase: Some(1)
                    }
                }
            ),
            Err(Error::InvalidHeader)
        );
    }
    assert_eq!(
        writer.push(
            99,
            Event::PacketLost {
                header: PacketHeader {
                    packet_type: PacketType::Initial,
                    packet_number: None,
                    key_phase: None
                },
                trigger: Some(LossTrigger::TimeThreshold)
            }
        ),
        Err(Error::InvalidHeader)
    );
    assert_eq!(writer.pending(), before);
    writer.push(0, trace_cases::events()[0]).unwrap();
}

#[test]
fn unknown_drop_never_fabricates_authenticated_fields() {
    let bytes = record(0, trace_cases::events()[4]);
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        "\x1e{\"time\":0.000,\"name\":\"quic:packet_dropped\",\"data\":{\"header\":{\"packet_type\":\"unknown\"},\"datagram_id\":4294967295,\"trigger\":\"decryption_failure\"}}\n"
    );
}

#[test]
fn application_key_events_contain_only_owner_generation_trigger() {
    let bytes = record(0, trace_cases::events()[6]);
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        "\x1e{\"time\":0.000,\"name\":\"quic:key_updated\",\"data\":{\"key_type\":\"server_1rtt_secret\",\"key_phase\":\"18446744073709551615\",\"trigger\":\"remote_update\"}}\n"
    );
}

#[test]
fn key_phase_is_a_full_generation_in_headers_and_key_updates() {
    for generation in [2, 3, 4, u64::MAX] {
        let events = [
            Event::Packet {
                direction: Direction::Received,
                header: PacketHeader {
                    packet_type: PacketType::OneRtt,
                    packet_number: Some(1),
                    key_phase: Some(generation),
                },
                datagram_id: None,
            },
            Event::ApplicationKeyUpdated {
                owner: VantagePoint::Client,
                generation,
                trigger: KeyUpdateTrigger::LocalUpdate,
            },
        ];
        for event in events {
            let bytes = record(0, event);
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(text.contains(&format!("\"key_phase\":\"{generation}\"")));
            assert!(!text.contains("key_phase_bit"));
        }
    }
}

#[test]
fn writer_paths_including_capacity_failure_and_compaction_allocate_nothing() {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(false));
        }
    }
    ALLOCS.with(|count| count.set(0));
    ACTIVE.with(|active| active.set(true));
    let guard = Guard;
    trace_cases::exercise();
    drop(guard);
    assert_eq!(ALLOCS.with(Cell::get), 0);
}

#[test]
fn unknown_loss_cause_is_omitted_not_guessed() {
    let mut bytes = [0; 1024];
    let mut writer = QlogWriter::new(&mut bytes, VantagePoint::Client).unwrap();
    writer
        .push(
            0,
            Event::PacketLost {
                header: PacketHeader {
                    packet_type: PacketType::ZeroRtt,
                    packet_number: Some(5),
                    key_phase: None,
                },
                trigger: None,
            },
        )
        .unwrap();
    let json = core::str::from_utf8(writer.pending()).unwrap();
    assert!(json.contains("quic:packet_lost"));
    assert!(json.contains("0RTT"));
    assert!(!json.contains("trigger"));
}
