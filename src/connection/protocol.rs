//! Finite handshake graph: direct TLS message order, independent TX publication,
//! timer ownership and affine Initial-key retirement compose in parallel.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};
pub const RX: u8 = 0;
pub const TLS_RX: u8 = 1;
pub const TX: u8 = 2;
pub const TLS_TX: u8 = 3;
pub const UDP: u8 = 4;
pub const TIMER: u8 = 5;
pub const TIMER_TX: u8 = 6;
pub const TX_WIRE: u8 = 7;
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
    type Request: g::Message<Payload = ()>;
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
            type Request = g::Msg<{ $b }, ()>;
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
pub type WriteHandshake = g::Msg<61, ()>;
pub type WriteApplication = g::Msg<93, ()>;
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
pub type InitialRequest = <InitialTransmit as TransmitPhase>::Request;
pub type InitialFlight = <InitialTransmit as TransmitPhase>::Flight;
pub type InitialIdle = <InitialTransmit as TransmitPhase>::Idle;
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
pub type HandshakeRequest = <HandshakeTransmit as TransmitPhase>::Request;
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
pub type ApplicationRequest = <ApplicationTransmit as TransmitPhase>::Request;
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
type Publish<P> = g::Seq<
    g::Send<TX_WIRE, UDP, <P as Publication>::Datagram>,
    g::Seq<
        g::Resolve<
            g::Route<
                g::Send<UDP, TX_WIRE, <P as Publication>::Accepted>,
                g::Send<UDP, TX_WIRE, <P as Publication>::Rejected>,
            >,
            ADAPTER_RESULT,
        >,
        g::Send<TX_WIRE, UDP, <P as Publication>::Settled>,
    >,
>;
fn publication<P: Publication>() -> g::Program<Publish<P>> {
    g::seq(
        g::send::<TX_WIRE, UDP, P::Datagram>(),
        g::seq(
            g::route(
                g::send::<UDP, TX_WIRE, P::Accepted>(),
                g::send::<UDP, TX_WIRE, P::Rejected>(),
            )
            .resolve::<ADAPTER_RESULT>(),
            g::send::<TX_WIRE, UDP, P::Settled>(),
        ),
    )
}
type TxResponse<P> = g::Route<
    g::Seq<
        g::Send<TLS_TX, TX, <P as TransmitPhase>::Flight>,
        g::Send<TX, TLS_TX, <P as TransmitPhase>::Taken>,
    >,
    g::Route<
        g::Seq<
            g::Send<TLS_TX, TX, <P as TransmitPhase>::Idle>,
            g::Send<TX, TLS_TX, <P as TransmitPhase>::Taken>,
        >,
        g::Send<TLS_TX, TX, <P as TransmitPhase>::Boundary>,
    >,
>;
type SourceWork<P> =
    g::Roll<g::Seq<g::Send<TX, TLS_TX, <P as TransmitPhase>::Request>, TxResponse<P>>>;
type WireWork<P> = g::Roll<
    g::Route<
        Publish<<P as TransmitPhase>::Data>,
        g::Route<
            Publish<<P as TransmitPhase>::Ack>,
            g::Route<
                Publish<<P as TransmitPhase>::Probe>,
                g::Seq<
                    g::Send<TX_WIRE, UDP, <P as TransmitPhase>::WireBoundary>,
                    g::Send<UDP, TX_WIRE, <P as TransmitPhase>::WireBoundarySeen>,
                >,
            >,
        >,
    >,
>;
type TxWork<P> = g::Seq<
    g::Par<SourceWork<P>, WireWork<P>>,
    g::Send<TX, TLS_TX, <P as TransmitPhase>::PhaseSettled>,
>;
fn tx_work<P: TransmitPhase>() -> g::Program<TxWork<P>> {
    let source = g::seq(
        g::send::<TX, TLS_TX, P::Request>(),
        g::route(
            g::seq(
                g::send::<TLS_TX, TX, P::Flight>(),
                g::send::<TX, TLS_TX, P::Taken>(),
            ),
            g::route(
                g::seq(
                    g::send::<TLS_TX, TX, P::Idle>(),
                    g::send::<TX, TLS_TX, P::Taken>(),
                ),
                g::send::<TLS_TX, TX, P::Boundary>(),
            ),
        ),
    )
    .roll();
    let wire = g::route(
        publication::<P::Data>(),
        g::route(
            publication::<P::Ack>(),
            g::route(
                publication::<P::Probe>(),
                g::seq(
                    g::send::<TX_WIRE, UDP, P::WireBoundary>(),
                    g::send::<UDP, TX_WIRE, P::WireBoundarySeen>(),
                ),
            ),
        ),
    )
    .roll();
    g::seq(
        g::par(source, wire),
        g::send::<TX, TLS_TX, P::PhaseSettled>(),
    )
}

/// Actual key-space retirement is independent of TLS flight transport. The
/// configured producer can only obtain its affine event from accepted Handshake
/// publication (client) or authenticated Handshake receipt (server).
pub const INITIAL_EVENT: u8 = 18;
pub const INITIAL_OWNER: u8 = 19;
pub type ClientInitialRetire = g::Msg<145, ()>;
pub type ServerInitialRetire = g::Msg<146, ()>;
pub type InitialRetired = g::Msg<147, ()>;
pub type InitialRetirementFlow = g::Seq<
    g::Route<
        g::Send<INITIAL_EVENT, INITIAL_OWNER, ClientInitialRetire>,
        g::Send<INITIAL_EVENT, INITIAL_OWNER, ServerInitialRetire>,
    >,
    g::Send<INITIAL_OWNER, INITIAL_EVENT, InitialRetired>,
>;
pub type ReceiveFlow = g::Seq<
    crate::bounded_tls::protocol::Flow,
    g::Seq<g::Send<RX, TLS_RX, ReceiveComplete>, g::Send<TLS_RX, RX, ReceiveContinuation>>,
>;
pub type DrainFlow = g::Roll<
    g::Route<
        Publish<DrainAck>,
        g::Route<Publish<DrainProbe>, g::Send<TX_WIRE, UDP, HandshakeRecoveryTransferred>>,
    >,
>;
pub const TIMER_STOP: u8 = 20;
pub const RECEIVE_STOP: u8 = 21;
pub type StopTimer = g::Msg<222, ()>;
pub type TimerStopped = g::Msg<223, ()>;
pub type StopReceive = g::Msg<225, ()>;
pub type ReceiveStopped = g::Msg<226, ()>;
pub type CompleteFlow = g::Seq<
    g::Send<TX_WIRE, RECEIVE_STOP, StopReceive>,
    g::Seq<
        g::Send<RECEIVE_STOP, TX_WIRE, ReceiveStopped>,
        g::Seq<
            g::Send<TX_WIRE, TIMER_STOP, StopTimer>,
            g::Seq<
                g::Send<TIMER_STOP, TX_WIRE, TimerStopped>,
                g::Seq<
                    g::Send<TX, TLS_TX, TransmitComplete>,
                    g::Seq<
                        g::Send<TLS_TX, TX, TransmitContinuation>,
                        g::Seq<
                            g::Send<TX_WIRE, UDP, AdapterComplete>,
                            g::Send<UDP, TX_WIRE, AdapterRetired>,
                        >,
                    >,
                >,
            >,
        >,
    >,
>;
pub type TransmitFlow = g::Seq<
    TxWork<InitialTransmit>,
    g::Seq<
        g::Send<TLS_TX, TX, WriteHandshake>,
        g::Seq<
            TxWork<HandshakeTransmit>,
            g::Seq<
                g::Send<TLS_TX, TX, WriteApplication>,
                g::Seq<TxWork<ApplicationTransmit>, g::Seq<DrainFlow, CompleteFlow>>,
            >,
        >,
    >,
>;
pub type TimerFlow = g::Roll<
    g::Route<
        g::Seq<g::Send<TIMER, TIMER_TX, TimerExpired>, g::Send<TIMER_TX, TIMER, TimerTaken>>,
        g::Seq<g::Send<TIMER, TIMER_TX, TimerRetired>, g::Send<TIMER_TX, TIMER, TimerAcknowledged>>,
    >,
>;
pub type EarlyStart = g::Msg<148, ()>;
pub type EarlySkip = g::Msg<149, ()>;
pub type EarlyEnd = g::Msg<150, ()>;
pub type EarlyDone = g::Msg<151, ()>;
pub type EarlyContinue = g::Msg<160, ()>;
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
pub type EarlyFlow = g::Route<
    g::Seq<
        g::Send<TLS_TX, TX_WIRE, EarlyStart>,
        g::Seq<
            g::Send<TX_WIRE, UDP, EarlyStart>,
            g::Seq<
                Publish<EarlyInitial>,
                g::Seq<
                    g::Roll<g::Route<Publish<EarlyPacket>, g::Send<TX_WIRE, UDP, EarlyEnd>>>,
                    g::Send<TX_WIRE, TLS_TX, EarlyDone>,
                >,
            >,
        >,
    >,
    g::Seq<g::Send<TLS_TX, TX_WIRE, EarlySkip>, g::Send<TX_WIRE, UDP, EarlySkip>>,
>;
pub fn early_prefix() -> g::Program<EarlyFlow> {
    g::route(
        g::seq(
            g::send::<TLS_TX, TX_WIRE, EarlyStart>(),
            g::seq(
                g::send::<TX_WIRE, UDP, EarlyStart>(),
                g::seq(
                    publication::<EarlyInitial>(),
                    g::seq(
                        g::route(
                            publication::<EarlyPacket>(),
                            g::send::<TX_WIRE, UDP, EarlyEnd>(),
                        )
                        .roll(),
                        g::send::<TX_WIRE, TLS_TX, EarlyDone>(),
                    ),
                ),
            ),
        ),
        g::seq(
            g::send::<TLS_TX, TX_WIRE, EarlySkip>(),
            g::send::<TX_WIRE, UDP, EarlySkip>(),
        ),
    )
}
pub type MainFlow =
    g::Par<ReceiveFlow, g::Par<TransmitFlow, g::Par<TimerFlow, InitialRetirementFlow>>>;
pub type Flow = g::Seq<
    crate::retry::client_protocol::Prefix,
    g::Seq<EarlyFlow, g::Seq<g::Send<TLS_TX, TX, EarlyContinue>, MainFlow>>,
>;

pub fn choreography() -> g::Program<Flow> {
    let receive = g::seq(
        crate::bounded_tls::protocol::choreography(),
        g::seq(
            g::send::<RX, TLS_RX, ReceiveComplete>(),
            g::send::<TLS_RX, RX, ReceiveContinuation>(),
        ),
    );
    let drain = g::route(
        publication::<DrainAck>(),
        g::route(
            publication::<DrainProbe>(),
            g::send::<TX_WIRE, UDP, HandshakeRecoveryTransferred>(),
        ),
    )
    .roll();
    let complete = g::seq(
        g::send::<TX_WIRE, RECEIVE_STOP, StopReceive>(),
        g::seq(
            g::send::<RECEIVE_STOP, TX_WIRE, ReceiveStopped>(),
            g::seq(
                g::send::<TX_WIRE, TIMER_STOP, StopTimer>(),
                g::seq(
                    g::send::<TIMER_STOP, TX_WIRE, TimerStopped>(),
                    g::seq(
                        g::send::<TX, TLS_TX, TransmitComplete>(),
                        g::seq(
                            g::send::<TLS_TX, TX, TransmitContinuation>(),
                            g::seq(
                                g::send::<TX_WIRE, UDP, AdapterComplete>(),
                                g::send::<UDP, TX_WIRE, AdapterRetired>(),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    let transmit = g::seq(
        tx_work::<InitialTransmit>(),
        g::seq(
            g::send::<TLS_TX, TX, WriteHandshake>(),
            g::seq(
                tx_work::<HandshakeTransmit>(),
                g::seq(
                    g::send::<TLS_TX, TX, WriteApplication>(),
                    g::seq(tx_work::<ApplicationTransmit>(), g::seq(drain, complete)),
                ),
            ),
        ),
    );
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
        crate::retry::client_protocol::prefix(),
        g::seq(
            early_prefix(),
            g::seq(
                g::send::<TLS_TX, TX, EarlyContinue>(),
                g::par(receive, g::par(transmit, g::par(timer, initial))),
            ),
        ),
    )
}
pub struct Programs {
    pub rx: RoleProgram<RX>,
    pub tls_rx: RoleProgram<TLS_RX>,
    pub tx: RoleProgram<TX>,
    pub tls_tx: RoleProgram<TLS_TX>,
    pub udp: RoleProgram<UDP>,
    pub timer: RoleProgram<TIMER>,
    pub timer_tx: RoleProgram<TIMER_TX>,
    pub tx_wire: RoleProgram<TX_WIRE>,
    pub initial_event: RoleProgram<INITIAL_EVENT>,
    pub initial_owner: RoleProgram<INITIAL_OWNER>,
    pub timer_stop: RoleProgram<TIMER_STOP>,
    pub receive_stop: RoleProgram<RECEIVE_STOP>,
}
pub fn programs() -> Programs {
    let global = choreography();
    Programs {
        rx: project(&global),
        tls_rx: project(&global),
        tx: project(&global),
        tls_tx: project(&global),
        udp: project(&global),
        timer: project(&global),
        timer_tx: project(&global),
        tx_wire: project(&global),
        initial_event: project(&global),
        initial_owner: project(&global),
        timer_stop: project(&global),
        receive_stop: project(&global),
    }
}
