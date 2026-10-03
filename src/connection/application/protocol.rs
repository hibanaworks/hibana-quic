//! The connected global: actual affine startup, concurrent ordinary roles,
//! complete ordinary retirement, then closing or draining.
//! Source implementation is awaiting fresh compiler/global validation.
use hibana::{g, runtime::program::{RoleProgram, project}};

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
pub const PEER_EVENT: u8 = 22;
pub const PEER_CLOSE: u8 = 23;
pub const FILES_EVENT: u8 = 24;
pub const FILES_CLOSE: u8 = 25;
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
pub type PublicationFlow = g::Seq<g::Roll<g::Route<Publish, g::Send<TRANSMIT, ADAPTER, StopPublication>>>, g::Send<ADAPTER, TRANSMIT, PublicationStopped>>;
pub type FilesOutcome = g::Msg<52, u64>;
pub type KeyRetirement = g::Msg<53, u64>;
pub type CloseAuthority = g::Msg<54, u64>;
pub type ReceiveStart = g::Msg<160, u64>;
pub type TranscriptStart = g::Msg<161, u64>;
pub type WriteStart = g::Msg<162, u64>;
pub type StreamAdmission = g::Msg<163, u64>;
pub type WriteAdmission = g::Msg<164, u64>;

pub type PeerTerminal = g::Seq<g::Route<g::Send<PEER_EVENT, PEER_CLOSE, PeerClose>, g::Route<g::Send<PEER_EVENT, PEER_CLOSE, PeerFailed>, g::Send<PEER_EVENT, PEER_CLOSE, PeerCancelled>>>, g::Send<PEER_CLOSE, PEER_EVENT, PeerSeen>>;
pub type FilesTerminal = g::Seq<g::Route<g::Send<FILES_EVENT, FILES_CLOSE, FilesComplete>, g::Route<g::Send<FILES_EVENT, FILES_CLOSE, ApplicationFailed>, g::Send<FILES_EVENT, FILES_CLOSE, CompletionCancelled>>>, g::Send<FILES_CLOSE, FILES_EVENT, CompletionSeen>>;
pub type Terminal = g::Seq<g::Par<PeerTerminal, FilesTerminal>, g::Send<FILES_CLOSE, PEER_CLOSE, FilesOutcome>>;
pub type Active = g::Par<SourceFlow, g::Par<ReceiveFlow, g::Par<KeyFlow, g::Par<TimerFlow, g::Par<PublicationFlow, Terminal>>>>>;
pub type Retirement = g::Seq<g::Send<RX_KEYS, TRANSMIT, KeyRetirement>, g::Send<PEER_CLOSE, TRANSMIT, CloseAuthority>>;
pub type ClosingDraining = g::Seq<g::Route<Closing, Draining>, g::Seq<g::Send<TRANSMIT, ADAPTER, Retire>, g::Send<ADAPTER, TRANSMIT, Retired>>>;
pub type Flow = g::Seq<Active, g::Seq<Retirement, ClosingDraining>>;
pub type Startup = g::Seq<g::Send<0, RECEIVE, ReceiveStart>, g::Seq<g::Send<1, RECEIVE, TranscriptStart>, g::Seq<g::Send<2, TX_KEYS, WriteStart>, g::Seq<g::Send<RECEIVE, SOURCE, StreamAdmission>, g::Send<TX_KEYS, TRANSMIT, WriteAdmission>>>>>;

fn startup() -> g::Program<Startup> {
    g::seq(g::send::<0, RECEIVE, ReceiveStart>(), g::seq(g::send::<1, RECEIVE, TranscriptStart>(), g::seq(g::send::<2, TX_KEYS, WriteStart>(), g::seq(g::send::<RECEIVE, SOURCE, StreamAdmission>(), g::send::<TX_KEYS, TRANSMIT, WriteAdmission>()))))
}

pub fn choreography() -> g::Program<Flow> {
    let source = g::seq(g::route(g::seq(g::send::<SOURCE, INGRESS, SourceData>(), g::seq(g::route(g::send::<INGRESS, SOURCE, SourceAccepted>(), g::send::<INGRESS, SOURCE, SourceRejected>()), g::send::<SOURCE, INGRESS, SourceTaken>())), g::send::<SOURCE, INGRESS, SourceDone>()).roll(), g::send::<INGRESS, SOURCE, SourceRetired>());
    let receive = g::seq(g::route(g::seq(g::send::<RECEIVE, SINK, ReceivedData>(), g::route(g::send::<SINK, RECEIVE, ReceivedMore>(), g::send::<SINK, RECEIVE, ReceivedFin>())), g::send::<RECEIVE, SINK, ReceiveRetire>()).roll(), g::send::<SINK, RECEIVE, ReceiveRetired>());
    let keys = g::seq(g::route(g::seq(g::send::<RX_KEYS, TX_KEYS, PeerUpdate>(), g::route(g::send::<TX_KEYS, RX_KEYS, WriteInstalled>(), g::send::<TX_KEYS, RX_KEYS, UpdateFailed>())), g::route(g::seq(g::send::<RX_KEYS, TX_KEYS, KeyAck>(), g::route(g::send::<TX_KEYS, RX_KEYS, KeyAckApplied>(), g::send::<TX_KEYS, RX_KEYS, KeyAckFailed>())), g::route(g::seq(g::send::<RX_KEYS, TX_KEYS, Confirmed>(), g::route(g::send::<TX_KEYS, RX_KEYS, ConfirmationApplied>(), g::send::<TX_KEYS, RX_KEYS, ConfirmationFailed>())), g::send::<RX_KEYS, TX_KEYS, KeysRetire>()))).roll(), g::send::<TX_KEYS, RX_KEYS, KeysRetired>());
    let timer = g::route(g::seq(g::send::<CLOCK, TX_CLOCK, Expired>(), g::send::<TX_CLOCK, CLOCK, TimerTaken>()), g::seq(g::send::<CLOCK, TX_CLOCK, ClockRetired>(), g::send::<TX_CLOCK, CLOCK, ClockAcknowledged>())).roll();
    let publish = g::seq(g::send::<TRANSMIT, ADAPTER, Datagram>(), g::seq(g::route(g::send::<ADAPTER, TRANSMIT, Accepted>(), g::send::<ADAPTER, TRANSMIT, Rejected>()).resolve::<SUBMISSION_RESULT>(), g::send::<TRANSMIT, ADAPTER, Settled>()));
    let publication = g::seq(g::route(publish, g::send::<TRANSMIT, ADAPTER, StopPublication>()).roll(), g::send::<ADAPTER, TRANSMIT, PublicationStopped>());
    let peer = g::seq(g::route(g::send::<PEER_EVENT, PEER_CLOSE, PeerClose>(), g::route(g::send::<PEER_EVENT, PEER_CLOSE, PeerFailed>(), g::send::<PEER_EVENT, PEER_CLOSE, PeerCancelled>())), g::send::<PEER_CLOSE, PEER_EVENT, PeerSeen>());
    let files = g::seq(g::route(g::send::<FILES_EVENT, FILES_CLOSE, FilesComplete>(), g::route(g::send::<FILES_EVENT, FILES_CLOSE, ApplicationFailed>(), g::send::<FILES_EVENT, FILES_CLOSE, CompletionCancelled>())), g::send::<FILES_CLOSE, FILES_EVENT, CompletionSeen>());
    let terminal = g::seq(g::par(peer, files), g::send::<FILES_CLOSE, PEER_CLOSE, FilesOutcome>());
    let active = g::par(source, g::par(receive, g::par(keys, g::par(timer, g::par(publication, terminal)))));
    let retirement = g::seq(g::send::<RX_KEYS, TRANSMIT, KeyRetirement>(), g::send::<PEER_CLOSE, TRANSMIT, CloseAuthority>());
    let close_publish = g::seq(g::send::<TRANSMIT, ADAPTER, CloseDatagram>(), g::seq(g::route(g::send::<ADAPTER, TRANSMIT, CloseAccepted>(), g::send::<ADAPTER, TRANSMIT, CloseRejected>()).resolve::<SUBMISSION_RESULT>(), g::send::<TRANSMIT, ADAPTER, CloseSettled>()));
    let closing = g::seq(g::route(close_publish, g::send::<TRANSMIT, ADAPTER, CloseFlightDone>()).roll(), g::send::<ADAPTER, TRANSMIT, CloseFlightSettled>());
    let draining = g::seq(g::send::<TRANSMIT, ADAPTER, Drain>(), g::send::<ADAPTER, TRANSMIT, Drained>());
    let final_phase = g::seq(g::route(closing, draining), g::seq(g::send::<TRANSMIT, ADAPTER, Retire>(), g::send::<ADAPTER, TRANSMIT, Retired>()));
    g::seq(active, g::seq(retirement, final_phase))
}

pub struct Programs {
    pub handshake: crate::connection::protocol::Programs,
    pub source: RoleProgram<SOURCE>, pub ingress: RoleProgram<INGRESS>,
    pub receive: RoleProgram<RECEIVE>, pub sink: RoleProgram<SINK>,
    pub rx_keys: RoleProgram<RX_KEYS>, pub tx_keys: RoleProgram<TX_KEYS>,
    pub clock: RoleProgram<CLOCK>, pub tx_clock: RoleProgram<TX_CLOCK>,
    pub transmit: RoleProgram<TRANSMIT>, pub adapter: RoleProgram<ADAPTER>,
    pub peer_event: RoleProgram<PEER_EVENT>, pub peer_close: RoleProgram<PEER_CLOSE>,
    pub files_event: RoleProgram<FILES_EVENT>, pub files_close: RoleProgram<FILES_CLOSE>,
}

/// One projected session includes the actual TLS prefix and every subsequent
/// local continuation. The host creates endpoints once and never selects phases.
pub fn programs() -> Programs {
    let global = g::seq(crate::connection::protocol::choreography(), g::seq(startup(), choreography()));
    Programs {
        handshake: crate::connection::protocol::Programs {
            rx: project(&global), tls_rx: project(&global), tx: project(&global), tls_tx: project(&global),
            udp: project(&global), timer: project(&global), timer_tx: project(&global), tx_wire: project(&global),
            initial_event: project(&global), initial_owner: project(&global),
        },
        source: project(&global), ingress: project(&global), receive: project(&global), sink: project(&global),
        rx_keys: project(&global), tx_keys: project(&global), clock: project(&global), tx_clock: project(&global),
        transmit: project(&global), adapter: project(&global), peer_event: project(&global), peer_close: project(&global),
        files_event: project(&global), files_close: project(&global),
    }
}
