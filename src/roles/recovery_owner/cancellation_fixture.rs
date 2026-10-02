//! Test-only numerical reservations; every cancellation is minted by the real
//! datagram prepublication boundary, never by a test grant constructor.
use super::*;
pub(crate) fn with_reserved_stream(
    generation: u64,
    path: PathIdentity,
    cancel: impl FnOnce(
        SendTicket,
    ) -> (
        super::super::datagram::RecoveryCancellation,
        super::super::datagram::StreamCancellation,
    ),
) -> super::super::datagram::StreamCancellation {
    let mut owner = RecoveryOwner::<2, 1, 32, 2>::new(Config {
        generation,
        initial_rtt_us: recovery::INITIAL_RTT_US,
        max_datagram_size: 1200,
        active_path: Some(path),
        ecn: None,
        max_ack_delay_us: 0,
    })
    .unwrap();
    let arena = Arena::<1, 2>::new(generation);
    let Outcome::Reserved(ticket) = owner
        .apply(
            &arena,
            Descriptor {
                generation,
                sequence: 1,
            },
            Command::Reserve(SendPlan {
                kind: PacketKind::OneRtt,
                bytes: 64,
                in_flight: true,
                ack_eliciting: true,
                pto_probe: false,
                flight: None,
            }),
        )
        .unwrap()
    else {
        panic!("actual Recovery reservation");
    };
    let (recovery, stream) = cancel(ticket);
    assert!(
        matches!(owner.apply(&arena, Descriptor { generation, sequence: 2 }, Command::Cancel(recovery)).unwrap(), Outcome::AdapterRejected(packet) if packet == ticket.packet())
    );
    assert_eq!(owner.sent.reserved_in_flight(), 0);
    assert_eq!(owner.sent.bytes_in_flight(), 0);
    stream
}
