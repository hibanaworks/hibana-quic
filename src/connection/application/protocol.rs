//! Approximate recovery of the unfinished application choreography.
//! NOT executed or globally validated after recovery.
//! IMPORTANT: the historical PublicationFlow still contains closing inside
//! the active parallel phase. The required split into all-ordinary-retired
//! followed by closing/draining was identified but not implemented before loss.
use hibana::{g, runtime::program::RoleProgram};

pub const SOURCE: u8 = 8;
pub const INGRESS: u8 = 9;
pub const RECEIVE: u8 = 10;
pub const SINK: u8 = 11;
pub const RX_KEYS: u8 = 12;
pub const TX_KEYS: u8 = 13;
pub const CLOCK: u8 = 14;
pub const TX_CLOCK: u8 = 15;
pub const TRANSMIT: u8 = 16;
pub const ADAPTER: u8 = 17;
pub const PEER_EVENT: u8 = 18;
pub const PEER_CLOSE: u8 = 19;
pub const FILES_EVENT: u8 = 20;
pub const FILES_CLOSE: u8 = 21;
pub const SUBMISSION_RESULT: u16 = 1100;

pub type SourceData = g::Msg<0, u64>;
pub type SourceAccepted = g::Msg<1, u64>;
pub type SourceRejected = g::Msg<2, u64>;
pub type SourceTaken = g::Msg<3, u64>;
pub type SourceDone = g::Msg<4, u64>;
pub type SourceRetired = g::Msg<5, u64>;
pub type ReceivedData = g::Msg<6, u64>;
pub type ReceivedMore = g::Msg<7, u64>;
pub type ReceivedFin = g::Msg<8, u64>;
pub type ReceiveRetire = g::Msg<9, u64>;
pub type ReceiveRetired = g::Msg<10, u64>;
pub type PeerUpdate = g::Msg<11, u64>;
pub type WriteInstalled = g::Msg<12, u64>;
pub type UpdateFailed = g::Msg<13, u64>;
pub type KeyAck = g::Msg<14, u64>;
pub type KeyAckApplied = g::Msg<15, u64>;
pub type KeyAckFailed = g::Msg<16, u64>;
pub type Confirmed = g::Msg<17, u64>;
pub type ConfirmationApplied = g::Msg<18, u64>;
pub type ConfirmationFailed = g::Msg<19, u64>;
pub type KeysRetire = g::Msg<20, u64>;
pub type KeysRetired = g::Msg<21, u64>;
pub type Expired = g::Msg<22, u64>;
pub type TimerTaken = g::Msg<23, u64>;
pub type ClockRetired = g::Msg<24, u64>;
pub type ClockAcknowledged = g::Msg<25, u64>;
pub type Datagram = g::Msg<26, u64>;
pub type Accepted = g::Msg<27, u64>;
pub type Rejected = g::Msg<28, u64>;
pub type Settled = g::Msg<29, u64>;
pub type StopPublication = g::Msg<30, u64>;
pub type PublicationStopped = g::Msg<31, u64>;
pub type CloseDatagram = g::Msg<32, u64>;
pub type CloseAccepted = g::Msg<33, u64>;
pub type CloseRejected = g::Msg<34, u64>;
pub type CloseSettled = g::Msg<35, u64>;
pub type CloseFlightDone = g::Msg<36, u64>;
pub type CloseFlightSettled = g::Msg<37, u64>;
pub type Drain = g::Msg<38, u64>;
pub type Drained = g::Msg<39, u64>;
pub type Retire = g::Msg<40, u64>;
pub type Retired = g::Msg<41, u64>;
// These declarations reconstruct the planned terminal lane dependencies. They
// had not yet been incorporated into a validated combined graph before loss.
pub type Quiesce = g::Msg<42, u64>;
pub type Quiesced = g::Msg<43, u64>;
pub type PeerClose = g::Msg<44, u64>;
pub type PeerFailed = g::Msg<45, u64>;
pub type PeerCancelled = g::Msg<46, u64>;
pub type PeerSeen = g::Msg<47, u64>;
pub type FilesComplete = g::Msg<48, u64>;
pub type ApplicationFailed = g::Msg<49, u64>;
pub type CompletionCancelled = g::Msg<50, u64>;
pub type CompletionSeen = g::Msg<51, u64>;

pub type SourceFlow = g::Seq<g::Roll<g::Route<
    g::Seq<g::Send<SOURCE, INGRESS, SourceData>, g::Seq<g::Route<g::Send<INGRESS, SOURCE, SourceAccepted>, g::Send<INGRESS, SOURCE, SourceRejected>>, g::Send<SOURCE, INGRESS, SourceTaken>>>,
    g::Send<SOURCE, INGRESS, SourceDone>>>, g::Send<INGRESS, SOURCE, SourceRetired>>;
pub type ReceiveFlow = g::Seq<g::Roll<g::Route<
    g::Seq<g::Send<RECEIVE, SINK, ReceivedData>, g::Route<g::Send<SINK, RECEIVE, ReceivedMore>, g::Send<SINK, RECEIVE, ReceivedFin>>>,
    g::Send<RECEIVE, SINK, ReceiveRetire>>>, g::Send<SINK, RECEIVE, ReceiveRetired>>;
pub type KeyFlow = g::Seq<g::Roll<g::Route<
    g::Seq<g::Send<RX_KEYS, TX_KEYS, PeerUpdate>, g::Route<g::Send<TX_KEYS, RX_KEYS, WriteInstalled>, g::Send<TX_KEYS, RX_KEYS, UpdateFailed>>>,
    g::Route<g::Seq<g::Send<RX_KEYS, TX_KEYS, KeyAck>, g::Route<g::Send<TX_KEYS, RX_KEYS, KeyAckApplied>, g::Send<TX_KEYS, RX_KEYS, KeyAckFailed>>>,
    g::Route<g::Seq<g::Send<RX_KEYS, TX_KEYS, Confirmed>, g::Route<g::Send<TX_KEYS, RX_KEYS, ConfirmationApplied>, g::Send<TX_KEYS, RX_KEYS, ConfirmationFailed>>>,
    g::Send<RX_KEYS, TX_KEYS, KeysRetire>>>>>, g::Send<TX_KEYS, RX_KEYS, KeysRetired>>;
pub type TimerFlow = g::Roll<g::Route<
    g::Seq<g::Send<CLOCK, TX_CLOCK, Expired>, g::Send<TX_CLOCK, CLOCK, TimerTaken>>,
    g::Seq<g::Send<CLOCK, TX_CLOCK, ClockRetired>, g::Send<TX_CLOCK, CLOCK, ClockAcknowledged>>>>;
pub type Publish = g::Seq<g::Send<TRANSMIT, ADAPTER, Datagram>, g::Seq<g::Resolve<g::Route<g::Send<ADAPTER, TRANSMIT, Accepted>, g::Send<ADAPTER, TRANSMIT, Rejected>>, SUBMISSION_RESULT>, g::Send<TRANSMIT, ADAPTER, Settled>>>;
pub type ClosePublish = g::Seq<g::Send<TRANSMIT, ADAPTER, CloseDatagram>, g::Seq<g::Resolve<g::Route<g::Send<ADAPTER, TRANSMIT, CloseAccepted>, g::Send<ADAPTER, TRANSMIT, CloseRejected>>, SUBMISSION_RESULT>, g::Send<TRANSMIT, ADAPTER, CloseSettled>>>;
pub type Closing = g::Seq<g::Roll<g::Route<ClosePublish, g::Send<TRANSMIT, ADAPTER, CloseFlightDone>>>, g::Send<ADAPTER, TRANSMIT, CloseFlightSettled>>;
pub type Draining = g::Seq<g::Send<TRANSMIT, ADAPTER, Drain>, g::Send<ADAPTER, TRANSMIT, Drained>>;
pub type PublicationFlow = g::Seq<g::Roll<g::Route<Publish, g::Send<TRANSMIT, ADAPTER, StopPublication>>>,
    g::Seq<g::Send<ADAPTER, TRANSMIT, PublicationStopped>,
    g::Seq<g::Route<Closing, Draining>, g::Seq<g::Send<TRANSMIT, ADAPTER, Retire>, g::Send<ADAPTER, TRANSMIT, Retired>>>>>;
pub type Flow = g::Par<SourceFlow, g::Par<ReceiveFlow, g::Par<KeyFlow, g::Par<TimerFlow, PublicationFlow>>>>;

pub fn choreography() -> g::Program<Flow> {
    let source = g::seq(g::route(g::seq(g::send::<SOURCE, INGRESS, SourceData>(), g::seq(g::route(g::send::<INGRESS, SOURCE, SourceAccepted>(), g::send::<INGRESS, SOURCE, SourceRejected>()), g::send::<SOURCE, INGRESS, SourceTaken>())), g::send::<SOURCE, INGRESS, SourceDone>()).roll(), g::send::<INGRESS, SOURCE, SourceRetired>());
    let receive = g::seq(g::route(g::seq(g::send::<RECEIVE, SINK, ReceivedData>(), g::route(g::send::<SINK, RECEIVE, ReceivedMore>(), g::send::<SINK, RECEIVE, ReceivedFin>())), g::send::<RECEIVE, SINK, ReceiveRetire>()).roll(), g::send::<SINK, RECEIVE, ReceiveRetired>());
    let keys = g::seq(g::route(g::seq(g::send::<RX_KEYS, TX_KEYS, PeerUpdate>(), g::route(g::send::<TX_KEYS, RX_KEYS, WriteInstalled>(), g::send::<TX_KEYS, RX_KEYS, UpdateFailed>())), g::route(g::seq(g::send::<RX_KEYS, TX_KEYS, KeyAck>(), g::route(g::send::<TX_KEYS, RX_KEYS, KeyAckApplied>(), g::send::<TX_KEYS, RX_KEYS, KeyAckFailed>())), g::route(g::seq(g::send::<RX_KEYS, TX_KEYS, Confirmed>(), g::route(g::send::<TX_KEYS, RX_KEYS, ConfirmationApplied>(), g::send::<TX_KEYS, RX_KEYS, ConfirmationFailed>())), g::send::<RX_KEYS, TX_KEYS, KeysRetire>()))).roll(), g::send::<TX_KEYS, RX_KEYS, KeysRetired>());
    let timer = g::route(g::seq(g::send::<CLOCK, TX_CLOCK, Expired>(), g::send::<TX_CLOCK, CLOCK, TimerTaken>()), g::seq(g::send::<CLOCK, TX_CLOCK, ClockRetired>(), g::send::<TX_CLOCK, CLOCK, ClockAcknowledged>())).roll();
    let publish = g::seq(g::send::<TRANSMIT, ADAPTER, Datagram>(), g::seq(g::route(g::send::<ADAPTER, TRANSMIT, Accepted>(), g::send::<ADAPTER, TRANSMIT, Rejected>()).resolve::<SUBMISSION_RESULT>(), g::send::<TRANSMIT, ADAPTER, Settled>()));
    let close_publish = g::seq(g::send::<TRANSMIT, ADAPTER, CloseDatagram>(), g::seq(g::route(g::send::<ADAPTER, TRANSMIT, CloseAccepted>(), g::send::<ADAPTER, TRANSMIT, CloseRejected>()).resolve::<SUBMISSION_RESULT>(), g::send::<TRANSMIT, ADAPTER, CloseSettled>()));
    let closing = g::seq(g::route(close_publish, g::send::<TRANSMIT, ADAPTER, CloseFlightDone>()).roll(), g::send::<ADAPTER, TRANSMIT, CloseFlightSettled>());
    let draining = g::seq(g::send::<TRANSMIT, ADAPTER, Drain>(), g::send::<ADAPTER, TRANSMIT, Drained>());
    let publication = g::seq(g::route(publish, g::send::<TRANSMIT, ADAPTER, StopPublication>()).roll(), g::seq(g::send::<ADAPTER, TRANSMIT, PublicationStopped>(), g::seq(g::route(closing, draining), g::seq(g::send::<TRANSMIT, ADAPTER, Retire>(), g::send::<ADAPTER, TRANSMIT, Retired>()))));
    g::par(source, g::par(receive, g::par(keys, g::par(timer, publication))))
}

pub struct Programs {
    pub source: RoleProgram<SOURCE>, pub ingress: RoleProgram<INGRESS>,
    pub receive: RoleProgram<RECEIVE>, pub sink: RoleProgram<SINK>,
    pub rx_keys: RoleProgram<RX_KEYS>, pub tx_keys: RoleProgram<TX_KEYS>,
    pub clock: RoleProgram<CLOCK>, pub tx_clock: RoleProgram<TX_CLOCK>,
    pub transmit: RoleProgram<TRANSMIT>, pub adapter: RoleProgram<ADAPTER>,
}
// No public programs() or connect_client/server runner existed before loss.
// Prefix→application must be one global with actual affine startup handoffs;
// the host must not select an independent application FSM after handshake.
