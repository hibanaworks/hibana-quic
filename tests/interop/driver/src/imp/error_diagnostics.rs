//! Fixed diagnostic metadata only. No Debug/Display rendering or private fields.
use hibana_quic::quic::{accounting, application, recovery};
fn application_kind(error: &application::Error) -> &'static str {
    use application::Error as E;
    match error {
        E::Entropy => "Entropy",
        E::Transport(_) => "Transport",
        E::Attach(_) => "Attach",
        E::Attachment(_) => "Attachment",
        E::Connection(_) => "Connection",
        E::Endpoint(_) => "Endpoint",
        E::Recovery(_) => "Recovery",
        E::Streams(_) => "Streams",
        E::Crypto(_) => "Crypto",
        E::Packet(_) => "Packet",
        E::Parameters(_) => "Parameters",
        E::Binding => "Binding",
        E::Capacity => "Capacity",
        E::Application => "Application",
        E::Incomplete => "Incomplete",
        E::KeyControlBinding => "KeyControlBinding",
        E::KeyControlRetired => "KeyControlRetired",
        E::Early(_) => "Early",
        E::UnexpectedLabel(_) => "UnexpectedLabel",
    }
}
fn connection_kind(error: &hibana_quic::quic::Error) -> &'static str {
    use hibana_quic::quic::Error as E;
    match error {
        E::Endpoint(_) => "Endpoint",
        E::Transcript(_) => "Transcript",
        E::Resolver(_) => "Resolver",
        E::Crypto(_) => "Crypto",
        E::EndpointAt { .. } => "EndpointAt",
        E::Tls(_) => "Tls",
        E::Packet(_) => "Packet",
        E::Reassembly(_) => "Reassembly",
        E::Recovery(_) => "Recovery",
        E::Gate(_) => "Gate",
        E::Slot(_) => "Slot",
        E::Io(_) => "Io",
        E::Binding => "Binding",
        E::Capacity => "Capacity",
        E::UnsupportedFrame => "UnsupportedFrame",
        E::UnsupportedLevel => "UnsupportedLevel",
        E::UnexpectedLabel(_) => "UnexpectedLabel",
    }
}
fn recovery_kind(error: &recovery::Error) -> &'static str {
    use recovery::Error as E;
    match error {
        E::Accounting(_) => "Accounting",
        E::Recovery(_) => "Recovery",
        E::Packet(_) => "Packet",
        E::Flight(_) => "Flight",
        E::Ecn(_) => "Ecn",
        E::Binding => "Binding",
        E::Capacity => "Capacity",
        E::UnsupportedLevel => "UnsupportedLevel",
        E::UnsupportedFrame => "UnsupportedFrame",
        E::CongestionLimited => "CongestionLimited",
        E::StaleDeadline => "StaleDeadline",
        E::PendingInitialPublication => "PendingInitialPublication",
    }
}
fn accounting_kind(error: &accounting::AccountingError) -> &'static str {
    use accounting::AccountingError as E;
    match error {
        E::PacketNumberExhausted => "PacketNumberExhausted",
        E::Full => "Full",
        E::Overflow => "Overflow",
        E::InvalidReservation => "InvalidReservation",
        E::InvalidState => "InvalidState",
        E::InvalidClassification => "InvalidClassification",
        E::UnsentPacket => "UnsentPacket",
        E::InvalidAckRange => "InvalidAckRange",
        E::TooManyAckRanges => "TooManyAckRanges",
        E::HistoryUnavailable => "HistoryUnavailable",
        E::OutstandingPackets => "OutstandingPackets",
        E::AmplificationLimited => "AmplificationLimited",
        E::ReservationIdExhausted => "ReservationIdExhausted",
        E::Retired => "Retired",
    }
}

pub(super) fn application_record(error: &application::Error) -> String {
    let connection = match error {
        application::Error::Connection(error) => Some(error),
        _ => None,
    };
    let recovery = match error {
        application::Error::Recovery(error) => Some(error),
        application::Error::Connection(hibana_quic::quic::Error::Recovery(error)) => Some(error),
        _ => None,
    };
    let accounting = match recovery {
        Some(recovery::Error::Accounting(error)) => Some(error),
        _ => None,
    };
    format!(
        "{{\"status\":\"failure\",\"error_scope\":\"application\",\"application_error\":\"{}\",\"connection_error\":\"{}\",\"recovery_error\":\"{}\",\"accounting_error\":\"{}\"}}",
        application_kind(error),
        connection.map_or("none", connection_kind),
        recovery.map_or("none", recovery_kind),
        accounting.map_or("none", accounting_kind),
    )
}

pub(super) const DRIVER_FAILURE: &str = "{\"status\":\"failure\",\"error_scope\":\"driver\"}";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_accounting_variants_are_fixed_and_complete() {
        use accounting::AccountingError as A;
        let cases = [
            (A::PacketNumberExhausted, "PacketNumberExhausted"),
            (A::Full, "Full"),
            (A::Overflow, "Overflow"),
            (A::InvalidReservation, "InvalidReservation"),
            (A::InvalidState, "InvalidState"),
            (A::InvalidClassification, "InvalidClassification"),
            (A::UnsentPacket, "UnsentPacket"),
            (A::InvalidAckRange, "InvalidAckRange"),
            (A::TooManyAckRanges, "TooManyAckRanges"),
            (A::HistoryUnavailable, "HistoryUnavailable"),
            (A::OutstandingPackets, "OutstandingPackets"),
            (A::AmplificationLimited, "AmplificationLimited"),
            (A::ReservationIdExhausted, "ReservationIdExhausted"),
            (A::Retired, "Retired"),
        ];
        for (error, label) in cases {
            let direct = application::Error::Recovery(recovery::Error::Accounting(error));
            let nested = application::Error::Connection(hibana_quic::quic::Error::Recovery(
                recovery::Error::Accounting(error),
            ));
            for error in [direct, nested] {
                let record = application_record(&error);
                assert!(record.contains(&format!("\"accounting_error\":\"{label}\"")));
                assert!(record.contains("\"recovery_error\":\"Accounting\""));
                assert!(!record.contains("role"));
            }
        }
    }
    #[test]
    fn numeric_private_variant_fields_are_not_rendered() {
        for label in 0..=255 {
            let record = application_record(&application::Error::UnexpectedLabel(label));
            assert_eq!(
                record,
                "{\"status\":\"failure\",\"error_scope\":\"application\",\"application_error\":\"UnexpectedLabel\",\"connection_error\":\"none\",\"recovery_error\":\"none\",\"accounting_error\":\"none\"}"
            );
        }
    }
    #[test]
    fn top_level_failure_has_no_input_and_fixed_content() {
        assert_eq!(
            DRIVER_FAILURE,
            "{\"status\":\"failure\",\"error_scope\":\"driver\"}"
        );
    }
}
