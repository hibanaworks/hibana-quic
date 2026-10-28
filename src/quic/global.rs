//! Finite handshake graph: direct TLS message order, independent TX publication,
//! timer ownership and affine Initial-key retirement compose in parallel.
//!
//! Role identifiers below index the role projections. Their attached affine
//! endpoints are defined and created in [`crate::quic::localside::Endpoints`].
//! [`crate::quic::localside::run`] shows which actual futures own or borrow each endpoint
//! and how those futures are polled together.
use hibana::g;
use hibana::runtime::program::Projectable;
pub const RX: u8 = 0;
pub const TLS_RX: u8 = 1;
pub const TX: u8 = 2;
pub const TLS_TX: u8 = 3;
pub type TranscriptComplete = g::Msg<227, ()>;
pub const UDP: u8 = 4;
pub const TIMER: u8 = 5;
pub const TIMER_TX: u8 = 6;
pub const TX_WIRE: u8 = 7;
pub const WRITE_KEYS: u8 = hibana_tls::handshake::global::owned::WRITE_KEYS;
pub type PacketKeys<'r> = g::Msg<94, hibana::Endpoint<'r, WRITE_KEYS>>;
pub type ApplicationInputEnd = g::Msg<95, ()>;
pub const ADAPTER_RESULT: u16 = 1001;
pub type ReceiveComplete = g::Msg<20, ()>;
pub type ReceiveContinuation = g::Msg<21, ()>;
pub trait Publication {
    type Datagram: g::Message<Payload = ()>;
    type Accepted: g::Message<Payload = ()>;
    type Rejected: g::Message<Payload = ()>;
    type Settled: g::Message<Payload = ()>;
}
pub struct Emission<const D: u8, const A: u8, const R: u8, const S: u8>;
impl<const D: u8, const A: u8, const R: u8, const S: u8> Publication for Emission<D, A, R, S> {
    type Datagram = g::Msg<D, ()>;
    type Accepted = g::Msg<A, ()>;
    type Rejected = g::Msg<R, ()>;
    type Settled = g::Msg<S, ()>;
}
pub trait TransmitPhase {
    type Flight: g::Message<Payload = ()>;
    type Idle: g::Message<Payload = u64>;
    type Boundary: g::Message<Payload = ()>;
    type Taken: g::Message<Payload = ()>;
    type PhaseSettled: g::Message<Payload = ()>;
    type Ack: Publication;
    type Probe: Publication;
    type Data: Publication;
    type BatchAck: Publication;
    type BatchProbe: Publication;
    type BatchEnd: g::Message<Payload = ()>;
    type BatchSettled: g::Message<Payload = ()>;
    type WireBoundary: g::Message<Payload = ()>;
    type WireBoundarySeen: g::Message<Payload = ()>;
}
macro_rules! tx_phase {
    ($name:ident,$b:literal) => {
        pub struct $name;
        impl TransmitPhase for $name {
            type Flight = g::Msg<{ $b + 1 }, ()>;
            type Idle = g::Msg<{ $b + 2 }, u64>;
            type Boundary = g::Msg<{ $b + 3 }, ()>;
            type Taken = g::Msg<{ $b + 4 }, ()>;
            type PhaseSettled = g::Msg<{ $b + 30 }, ()>;
            type Ack = Emission<{ $b + 5 }, { $b + 6 }, { $b + 7 }, { $b + 8 }>;
            type Probe = Emission<{ $b + 9 }, { $b + 10 }, { $b + 11 }, { $b + 12 }>;
            type Data = Emission<{ $b + 13 }, { $b + 14 }, { $b + 15 }, { $b + 16 }>;
            type BatchAck = Emission<{ $b + 17 }, { $b + 18 }, { $b + 19 }, { $b + 20 }>;
            type BatchProbe = Emission<{ $b + 21 }, { $b + 22 }, { $b + 23 }, { $b + 24 }>;
            type BatchEnd = g::Msg<{ $b + 25 }, ()>;
            type BatchSettled = g::Msg<{ $b + 26 }, ()>;
            type WireBoundary = g::Msg<{ $b + 27 }, ()>;
            type WireBoundarySeen = g::Msg<{ $b + 28 }, ()>;
        }
    };
}
tx_phase!(InitialTransmit, 32);
tx_phase!(HandshakeTransmit, 64);
tx_phase!(ApplicationTransmit, 96);
pub type WriteApplication<'r> =
    g::Msg<93, hibana::Endpoint<'r, { hibana_tls::handshake::global::owned::MATERIAL }>>;
pub type DrainAck = Emission<128, 129, 130, 131>;
pub type DrainProbe = Emission<132, 133, 134, 135>;
// Concrete message names keep each written local continuation directly readable.
pub type InitialAckDatagram = <<InitialTransmit as TransmitPhase>::Ack as Publication>::Datagram;
pub type InitialAckAccepted = <<InitialTransmit as TransmitPhase>::Ack as Publication>::Accepted;
pub type InitialAckRejected = <<InitialTransmit as TransmitPhase>::Ack as Publication>::Rejected;
pub type InitialAckSettled = <<InitialTransmit as TransmitPhase>::Ack as Publication>::Settled;
pub type InitialProbeDatagram =
    <<InitialTransmit as TransmitPhase>::Probe as Publication>::Datagram;
pub type InitialProbeAccepted =
    <<InitialTransmit as TransmitPhase>::Probe as Publication>::Accepted;
pub type InitialProbeRejected =
    <<InitialTransmit as TransmitPhase>::Probe as Publication>::Rejected;
pub type InitialProbeSettled = <<InitialTransmit as TransmitPhase>::Probe as Publication>::Settled;
pub type InitialDataDatagram = <<InitialTransmit as TransmitPhase>::Data as Publication>::Datagram;
pub type InitialDataAccepted = <<InitialTransmit as TransmitPhase>::Data as Publication>::Accepted;
pub type InitialDataRejected = <<InitialTransmit as TransmitPhase>::Data as Publication>::Rejected;
pub type InitialDataSettled = <<InitialTransmit as TransmitPhase>::Data as Publication>::Settled;
pub type InitialFlight = <InitialTransmit as TransmitPhase>::Flight;
pub type InitialBoundary = <InitialTransmit as TransmitPhase>::Boundary;
pub type InitialTaken = <InitialTransmit as TransmitPhase>::Taken;
pub type InitialPhaseSettled = <InitialTransmit as TransmitPhase>::PhaseSettled;
pub type InitialWireBoundary = <InitialTransmit as TransmitPhase>::WireBoundary;
pub type HandshakeAckDatagram =
    <<HandshakeTransmit as TransmitPhase>::Ack as Publication>::Datagram;
pub type HandshakeAckAccepted =
    <<HandshakeTransmit as TransmitPhase>::Ack as Publication>::Accepted;
pub type HandshakeAckRejected =
    <<HandshakeTransmit as TransmitPhase>::Ack as Publication>::Rejected;
pub type HandshakeAckSettled = <<HandshakeTransmit as TransmitPhase>::Ack as Publication>::Settled;
pub type HandshakeProbeDatagram =
    <<HandshakeTransmit as TransmitPhase>::Probe as Publication>::Datagram;
pub type HandshakeProbeAccepted =
    <<HandshakeTransmit as TransmitPhase>::Probe as Publication>::Accepted;
pub type HandshakeProbeRejected =
    <<HandshakeTransmit as TransmitPhase>::Probe as Publication>::Rejected;
pub type HandshakeProbeSettled =
    <<HandshakeTransmit as TransmitPhase>::Probe as Publication>::Settled;
pub type HandshakeDataDatagram =
    <<HandshakeTransmit as TransmitPhase>::Data as Publication>::Datagram;
pub type HandshakeDataAccepted =
    <<HandshakeTransmit as TransmitPhase>::Data as Publication>::Accepted;
pub type HandshakeDataRejected =
    <<HandshakeTransmit as TransmitPhase>::Data as Publication>::Rejected;
pub type HandshakeDataSettled =
    <<HandshakeTransmit as TransmitPhase>::Data as Publication>::Settled;
pub type HandshakeFlight = <HandshakeTransmit as TransmitPhase>::Flight;
pub type HandshakeIdle = <HandshakeTransmit as TransmitPhase>::Idle;
pub type HandshakeBoundary = <HandshakeTransmit as TransmitPhase>::Boundary;
pub type HandshakeTaken = <HandshakeTransmit as TransmitPhase>::Taken;
pub type HandshakePhaseSettled = <HandshakeTransmit as TransmitPhase>::PhaseSettled;
pub type HandshakeWireBoundary = <HandshakeTransmit as TransmitPhase>::WireBoundary;
pub type ApplicationAckDatagram =
    <<ApplicationTransmit as TransmitPhase>::Ack as Publication>::Datagram;
pub type ApplicationAckAccepted =
    <<ApplicationTransmit as TransmitPhase>::Ack as Publication>::Accepted;
pub type ApplicationAckRejected =
    <<ApplicationTransmit as TransmitPhase>::Ack as Publication>::Rejected;
pub type ApplicationAckSettled =
    <<ApplicationTransmit as TransmitPhase>::Ack as Publication>::Settled;
pub type ApplicationProbeDatagram =
    <<ApplicationTransmit as TransmitPhase>::Probe as Publication>::Datagram;
pub type ApplicationProbeAccepted =
    <<ApplicationTransmit as TransmitPhase>::Probe as Publication>::Accepted;
pub type ApplicationProbeRejected =
    <<ApplicationTransmit as TransmitPhase>::Probe as Publication>::Rejected;
pub type ApplicationProbeSettled =
    <<ApplicationTransmit as TransmitPhase>::Probe as Publication>::Settled;
pub type ApplicationDataDatagram =
    <<ApplicationTransmit as TransmitPhase>::Data as Publication>::Datagram;
pub type ApplicationDataAccepted =
    <<ApplicationTransmit as TransmitPhase>::Data as Publication>::Accepted;
pub type ApplicationDataRejected =
    <<ApplicationTransmit as TransmitPhase>::Data as Publication>::Rejected;
pub type ApplicationDataSettled =
    <<ApplicationTransmit as TransmitPhase>::Data as Publication>::Settled;
pub type ApplicationFlight = <ApplicationTransmit as TransmitPhase>::Flight;
pub type ApplicationIdle = <ApplicationTransmit as TransmitPhase>::Idle;
pub type ApplicationBoundary = <ApplicationTransmit as TransmitPhase>::Boundary;
pub type ApplicationTaken = <ApplicationTransmit as TransmitPhase>::Taken;
pub type ApplicationPhaseSettled = <ApplicationTransmit as TransmitPhase>::PhaseSettled;
pub type ApplicationWireBoundary = <ApplicationTransmit as TransmitPhase>::WireBoundary;
pub type DrainAckDatagram = <DrainAck as Publication>::Datagram;
pub type DrainAckAccepted = <DrainAck as Publication>::Accepted;
pub type DrainAckRejected = <DrainAck as Publication>::Rejected;
pub type DrainAckSettled = <DrainAck as Publication>::Settled;
pub type DrainProbeDatagram = <DrainProbe as Publication>::Datagram;
pub type DrainProbeAccepted = <DrainProbe as Publication>::Accepted;
pub type DrainProbeRejected = <DrainProbe as Publication>::Rejected;
pub type DrainProbeSettled = <DrainProbe as Publication>::Settled;
pub type InitialWireBoundarySeen = <InitialTransmit as TransmitPhase>::WireBoundarySeen;
pub type HandshakeWireBoundarySeen = <HandshakeTransmit as TransmitPhase>::WireBoundarySeen;
pub type ApplicationWireBoundarySeen = <ApplicationTransmit as TransmitPhase>::WireBoundarySeen;
pub type HandshakeRecoveryTransferred = g::Msg<136, ()>;
pub type TransmitComplete = g::Msg<137, ()>;
pub type TransmitContinuation = g::Msg<138, ()>;
pub type AdapterComplete = g::Msg<139, ()>;
pub type AdapterRetired = g::Msg<140, ()>;
// These edges carry only progress. The projected continuation supplies order;
// no mirrored expiry counter or echo check is protocol authority.
pub type TimerExpired = g::Msg<141, ()>;
pub type TimerTaken = g::Msg<142, ()>;
pub type TimerRetired = g::Msg<143, ()>;
pub type TimerAcknowledged = g::Msg<144, ()>;
fn publication<const FROM: u8, P: Publication>() -> impl Projectable {
    g::seq(
        g::send::<FROM, UDP, P::Datagram>(),
        g::seq(
            g::route(
                g::send::<UDP, FROM, P::Accepted>(),
                g::send::<UDP, FROM, P::Rejected>(),
            )
            .resolve::<ADAPTER_RESULT>(),
            g::send::<FROM, UDP, P::Settled>(),
        ),
    )
}
fn tx_wire<P: TransmitPhase>() -> impl Projectable {
    g::route(
        publication::<WRITE_KEYS, P::Data>(),
        g::route(
            publication::<WRITE_KEYS, P::Ack>(),
            g::route(
                publication::<WRITE_KEYS, P::Probe>(),
                g::seq(
                    g::send::<WRITE_KEYS, UDP, P::WireBoundary>(),
                    g::send::<UDP, WRITE_KEYS, P::WireBoundarySeen>(),
                ),
            ),
        ),
    )
    .roll()
}
fn tx_work<P: TransmitPhase>(source: impl Projectable) -> impl Projectable {
    g::seq(
        g::par(source, tx_wire::<P>()),
        g::send::<WRITE_KEYS, TLS_TX, P::PhaseSettled>(),
    )
}

fn flight<P: TransmitPhase>() -> impl Projectable {
    g::send::<TLS_TX, WRITE_KEYS, P::Flight>()
}
fn idle<P: TransmitPhase>() -> impl Projectable {
    g::send::<TLS_TX, WRITE_KEYS, P::Idle>()
}

/// Actual key-space retirement is independent of TLS flight transport. The
/// configured producer can only obtain its affine event from accepted Handshake
/// publication (client) or authenticated Handshake receipt (server).
pub const INITIAL_EVENT: u8 = 18;
pub const INITIAL_OWNER: u8 = 19;
pub type ClientInitialRetire = g::Msg<145, ()>;
pub type ServerInitialRetire = g::Msg<146, ()>;
pub type InitialRetired = g::Msg<147, ()>;
pub const TIMER_STOP: u8 = 20;
pub const RECEIVE_STOP: u8 = 21;
pub type StopTimer = g::Msg<222, ()>;
pub type TimerStopped = g::Msg<223, ()>;
pub type StopReceive = g::Msg<225, ()>;
pub type ReceiveStopped = g::Msg<226, ()>;
pub type EarlyStart = g::Msg<148, ()>;
pub type EarlySkip = g::Msg<149, ()>;
pub type EarlyEnd = g::Msg<150, ()>;
pub type EarlyDone = g::Msg<151, ()>;
pub type EarlyContinue = g::Msg<160, ()>;
pub type EarlySettled = g::Msg<161, ()>;
pub type EarlyInitial = Emission<152, 153, 154, 155>;
pub type EarlyPacket = Emission<156, 157, 158, 159>;
pub type EarlyInitialDatagram = <EarlyInitial as Publication>::Datagram;
pub type EarlyInitialAccepted = <EarlyInitial as Publication>::Accepted;
pub type EarlyInitialRejected = <EarlyInitial as Publication>::Rejected;
pub type EarlyInitialSettled = <EarlyInitial as Publication>::Settled;
pub type EarlyPacketDatagram = <EarlyPacket as Publication>::Datagram;
pub type EarlyPacketAccepted = <EarlyPacket as Publication>::Accepted;
pub type EarlyPacketRejected = <EarlyPacket as Publication>::Rejected;
pub type EarlyPacketSettled = <EarlyPacket as Publication>::Settled;
pub fn early_prefix() -> impl Projectable {
    g::seq(
        g::route(
            g::seq(
                g::send::<TLS_TX, TX_WIRE, EarlyStart>(),
                g::seq(
                    g::send::<TX_WIRE, UDP, EarlyStart>(),
                    g::seq(
                        publication::<TX_WIRE, EarlyInitial>(),
                        g::route(
                            publication::<TX_WIRE, EarlyPacket>(),
                            g::send::<TX_WIRE, UDP, EarlyEnd>(),
                        )
                        .roll(),
                    ),
                ),
            ),
            g::seq(
                g::send::<TLS_TX, TX_WIRE, EarlySkip>(),
                g::send::<TX_WIRE, UDP, EarlySkip>(),
            ),
        ),
        g::seq(
            g::send::<UDP, TX_WIRE, EarlySettled>(),
            g::send::<TX_WIRE, TLS_TX, EarlyDone>(),
        ),
    )
}

fn handshake() -> impl Projectable {
    use hibana_tls::handshake::global::owned as tls;
    let drain = g::route(
        publication::<WRITE_KEYS, DrainAck>(),
        g::route(
            publication::<WRITE_KEYS, DrainProbe>(),
            g::send::<WRITE_KEYS, UDP, HandshakeRecoveryTransferred>(),
        ),
    )
    .roll();
    let complete = g::seq(
        g::send::<WRITE_KEYS, RECEIVE_STOP, StopReceive>(),
        g::seq(
            g::send::<RECEIVE_STOP, WRITE_KEYS, ReceiveStopped>(),
            g::seq(
                g::send::<WRITE_KEYS, TIMER_STOP, StopTimer>(),
                g::seq(
                    g::send::<TIMER_STOP, WRITE_KEYS, TimerStopped>(),
                    g::seq(
                        g::send::<WRITE_KEYS, TLS_TX, TransmitComplete>(),
                        g::seq(
                            g::send::<TLS_TX, WRITE_KEYS, TransmitContinuation>(),
                            g::seq(
                                g::send::<WRITE_KEYS, UDP, AdapterComplete>(),
                                g::send::<UDP, WRITE_KEYS, AdapterRetired>(),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    let hello = g::seq(
        tls::hello(),
        g::seq(
            g::send::<TLS_RX, TX, tls::Keys<'_>>(),
            g::seq(
                g::send::<{ tls::MATERIAL }, TLS_RX, tls::Install>(),
                g::seq(
                    g::send::<TLS_RX, { tls::MATERIAL }, tls::Installed>(),
                    g::seq(
                        g::send::<TX, TLS_TX, tls::Keys<'_>>(),
                        g::send::<TLS_TX, TLS_RX, tls::Keys<'_>>(),
                    ),
                ),
            ),
        ),
    );
    let initial_output = tx_work::<InitialTransmit>(g::seq(
        hello,
        g::seq(
            g::send::<WRITE_KEYS, TLS_TX, InitialTaken>(),
            g::route(
                flight::<InitialTransmit>(),
                g::send::<TLS_TX, WRITE_KEYS, InitialBoundary>(),
            ),
        )
        .roll(),
    ));
    let handshake_output = tx_work::<HandshakeTransmit>(
        g::seq(
            g::send::<WRITE_KEYS, TLS_TX, HandshakeTaken>(),
            g::route(
                flight::<HandshakeTransmit>(),
                g::route(
                    idle::<HandshakeTransmit>(),
                    g::send::<TLS_TX, WRITE_KEYS, HandshakeBoundary>(),
                ),
            ),
        )
        .roll(),
    );
    let application_output = tx_work::<ApplicationTransmit>(g::seq(
        g::par(
            g::seq(
                g::send::<TX_WIRE, TLS_RX, tls::Keys<'_>>(),
                g::seq(
                    tls::complete(),
                    g::send::<TLS_RX, TLS_TX, TranscriptComplete>(),
                ),
            ),
            g::seq(
                g::send::<WRITE_KEYS, TLS_TX, ApplicationTaken>(),
                g::route(
                    flight::<ApplicationTransmit>(),
                    g::route(
                        idle::<ApplicationTransmit>(),
                        g::send::<TLS_TX, WRITE_KEYS, ApplicationInputEnd>(),
                    ),
                ),
            )
            .roll(),
        ),
        g::send::<TLS_TX, WRITE_KEYS, ApplicationBoundary>(),
    ));
    g::seq(
        g::send::<TX, TX_WIRE, PacketKeys<'_>>(),
        g::seq(
            initial_output,
            g::seq(
                g::par(
                    g::seq(
                        g::route(tls::client_messages(), tls::server_messages()),
                        tls::installation(),
                    ),
                    handshake_output,
                ),
                g::seq(
                    g::send::<TLS_TX, TX_WIRE, WriteApplication<'_>>(),
                    g::seq(
                        application_output,
                        g::par(
                            g::seq(
                                g::send::<RX, TLS_RX, ReceiveComplete>(),
                                g::send::<TLS_RX, RX, ReceiveContinuation>(),
                            ),
                            g::seq(
                                g::seq(drain, complete),
                                g::send::<TX_WIRE, TX, PacketKeys<'_>>(),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}
pub fn choreography() -> impl Projectable {
    let timer = g::route(
        g::seq(
            g::send::<TIMER, TIMER_TX, TimerExpired>(),
            g::send::<TIMER_TX, TIMER, TimerTaken>(),
        ),
        g::seq(
            g::send::<TIMER, TIMER_TX, TimerRetired>(),
            g::send::<TIMER_TX, TIMER, TimerAcknowledged>(),
        ),
    )
    .roll();
    let initial = g::seq(
        g::route(
            g::send::<INITIAL_EVENT, INITIAL_OWNER, ClientInitialRetire>(),
            g::send::<INITIAL_EVENT, INITIAL_OWNER, ServerInitialRetire>(),
        ),
        g::send::<INITIAL_OWNER, INITIAL_EVENT, InitialRetired>(),
    );
    g::seq(
        crate::quic::retry::global::client::prefix(),
        g::seq(
            early_prefix(),
            g::seq(
                g::send::<TLS_TX, TLS_RX, EarlyContinue>(),
                g::par(handshake(), g::par(timer, initial)),
            ),
        ),
    )
}
