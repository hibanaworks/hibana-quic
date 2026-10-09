//! The connected global: actual affine startup, concurrent ordinary roles,
//! complete ordinary retirement, then closing or draining.
use crate::quic::ecn::global as e;
use crate::quic::global::{RX as PREFIX_RX, TLS_RX as PREFIX_TLS_RX, TX as PREFIX_TX};
use hibana::runtime::program::Projectable;
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};

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
/// Finite owner of the joined publication, key and terminal retirement grants.
pub const CLOSE_JOIN: u8 = 26;
pub const SOURCE_COLLECTOR: u8 = 27;
pub const INPUT_COLLECTOR: u8 = 28;
pub const DELIVERY_COLLECTOR: u8 = 29;
pub const SOURCE_JOIN: u8 = 30;
pub type SourceJoined = g::Msg<213, ()>;
pub type SourceFailed = g::Msg<214, ()>;
pub type SourceDataFailed = g::Msg<215, ()>;
pub type SourceEndFailed = g::Msg<216, u64>;
pub type ReceivedFailed = g::Msg<217, u64>;
pub type ReceivedInterrupted = g::Msg<219, u64>;
pub type PeerApplicationFailed = g::Msg<218, ()>;
pub const SUBMISSION_RESULT: u16 = 1100;
pub const STOP_RESULT: u16 = 1101;

pub type SourceData = g::Msg<0, ()>;
pub type SourceAccepted = g::Msg<1, ()>;
pub type SourceRejected = g::Msg<2, ()>;
pub type SourceTaken = g::Msg<3, ()>;
pub type SourceDone = g::Msg<4, ()>;
pub type SourceRetired = g::Msg<5, ()>;
pub type ReceivedData = g::Msg<6, u64>;
pub type ReceivedMore = g::Msg<7, u64>;
pub type ReceivedFin = g::Msg<8, u64>;
pub type ReceiveRetire = g::Msg<9, ()>;
pub type ReceiveRetired = g::Msg<10, ()>;
pub type PeerUpdate = g::Msg<11, ()>;
pub type WriteInstalled = g::Msg<12, ()>;
pub type UpdateFailed = g::Msg<13, ()>;
pub type KeyAck = g::Msg<14, ()>;
pub type KeyAckApplied = g::Msg<15, ()>;
pub type KeyAckFailed = g::Msg<16, ()>;
pub type Confirmed = g::Msg<17, ()>;
pub type ConfirmationApplied = g::Msg<18, ()>;
pub type ConfirmationFailed = g::Msg<19, ()>;
pub type KeysRetire = g::Msg<20, ()>;
pub type KeysRetired = g::Msg<21, ()>;
pub type Expired = g::Msg<22, ()>;
pub type TimerTaken = g::Msg<23, ()>;
pub type ClockRetired = g::Msg<24, ()>;
pub type ClockAcknowledged = g::Msg<25, ()>;
pub type Datagram = g::Msg<26, ()>;
pub type Accepted = g::Msg<27, ()>;
pub type Rejected = g::Msg<28, ()>;
pub type Settled = g::Msg<29, ()>;
pub type StopPublication = g::Msg<30, ()>;
pub type PublicationStopped = g::Msg<31, ()>;
pub type CloseDatagram = g::Msg<32, ()>;
pub type CloseAccepted = g::Msg<33, ()>;
pub type CloseRejected = g::Msg<34, ()>;
pub type CloseSettled = g::Msg<35, ()>;
pub type CloseFlightDone = g::Msg<36, ()>;
pub type CloseFlightSettled = g::Msg<37, ()>;
pub type Drain = g::Msg<38, ()>;
pub type Drained = g::Msg<39, ()>;
pub type Retire = g::Msg<40, ()>;
pub type Retired = g::Msg<41, ()>;
// Parallel terminal observations join before connection retirement.
pub type PeerClose = g::Msg<44, ()>;
pub type PeerFailed = g::Msg<45, ()>;
pub type PeerCancelled = g::Msg<46, ()>;
pub type PeerSeen = g::Msg<47, ()>;
pub type FilesComplete = g::Msg<48, ()>;
/// The client consumed every authenticated response FIN. This is application
/// completion, not a fabricated ACK of its outbound request packets.
pub type ResponsesComplete = g::Msg<220, ()>;
pub type ApplicationFailed = g::Msg<49, ()>;
pub type CompletionCancelled = g::Msg<50, ()>;
pub type CompletionSeen = g::Msg<51, ()>;
pub type IdleExpired = g::Msg<52, ()>;

// Stream production has a finite terminal outside the rolled data fragment.
// FIN is a choreography message, never a boolean hidden in a data slot.
pub type SourceOpen = g::Msg<168, u64>;
pub type SourceFin = g::Msg<169, u64>;
pub type SourceAbandon = g::Msg<170, u64>;
pub type SourceEnded = g::Msg<171, u64>;
pub type SourceEndRejected = g::Msg<172, u64>;
pub type SourceDataFinished = g::Msg<173, u64>;
pub type SourceStopped = g::Msg<187, ()>;
pub type SourceEndStopped = g::Msg<188, u64>;
pub type ProductionReclaim = g::Msg<189, u64>;
pub type ProductionStored = g::Msg<190, u64>;
pub type ProductionReclaimsDone = g::Msg<191, ()>;
pub type ProductionReclaimsClosed = g::Msg<192, ()>;
pub type InputReclaim = g::Msg<193, u64>;
pub type InputStored = g::Msg<194, u64>;
pub type NoInputReclaim = g::Msg<195, u64>;
pub type InputReclaimsDone = g::Msg<196, ()>;
pub type InputReclaimsClosed = g::Msg<197, ()>;
pub type DeliveryReclaim = g::Msg<198, u64>;
pub type DeliveryStored = g::Msg<199, u64>;
pub type DeliveryReclaimsDone = g::Msg<200, ()>;
pub type DeliveryReclaimsClosed = g::Msg<201, ()>;
pub type ReclaimStream = g::Msg<202, u64>;
pub type StreamReclaimed = g::Msg<203, u64>;
pub type ReclaimSettled = g::Msg<204, u64>;
pub type LocalUpdate = g::Msg<205, ()>;
pub type LocalInstalled = g::Msg<206, ()>;
pub type LocalRejected = g::Msg<207, ()>;
pub type LocalSettled = g::Msg<208, ()>;
pub type ApplyStop = g::Msg<174, u64>;
pub type StopApplied = g::Msg<175, u64>;
pub type StopFailed = g::Msg<176, u64>;
pub type StopSettled = g::Msg<177, u64>;
pub type ApplyAcknowledgments = g::Msg<178, ()>;
pub type AcknowledgmentsApplied = g::Msg<179, ()>;
pub type AcknowledgmentsSettled = g::Msg<180, ()>;
pub type StreamDelivered = g::Msg<181, u64>;
pub type StreamDeliverySeen = g::Msg<182, u64>;
pub type DeliveriesDone = g::Msg<183, ()>;
pub type ApplyLoss = g::Msg<184, u64>;
pub type LossApplied = g::Msg<185, u64>;
pub type LossSettled = g::Msg<186, u64>;
// Applying a stop is an exclusive alternative to the complete publication
// fragment. The actual adapter owner settles its send before offering again.
pub type FilesOutcome = g::Msg<52, ()>;
pub type KeyRetirement = g::Msg<53, ()>;
pub type CloseAuthority = g::Msg<54, ()>;
pub type PublicationRetired = g::Msg<55, ()>;
pub type PeerOutcome = g::Msg<56, ()>;
pub type KeyRetirementGrant = g::Msg<57, ()>;
pub type PeerRetirementGrant = g::Msg<58, ()>;
pub type FilesRetirementGrant = g::Msg<59, ()>;
pub type FinishedValidated = g::Msg<160, ()>;
pub type TranscriptStart = g::Msg<161, ()>;
pub type WriteStart = g::Msg<162, ()>;
pub type StreamAdmission = g::Msg<163, ()>;
pub type WriteAdmission = g::Msg<164, ()>;
pub type ReadAdmission = g::Msg<165, ()>;
pub type KeyControlAdmission = g::Msg<166, ()>;
pub type WriteForAdmission = g::Msg<167, ()>;

fn startup() -> impl Projectable {
    // The write continuation visits RX for the actual Finished/parameter/scope
    // check. Its owned bundle then returns through the transcript/read path.
    // RX cannot publish FinishedValidated before receiving WriteForAdmission,
    // so a capacity-one carrier has no unordered arrivals at TX_KEYS.
    let authenticated_read = g::seq(
        g::send::<PREFIX_RX, PREFIX_TLS_RX, FinishedValidated>(),
        g::seq(
            g::send::<PREFIX_TLS_RX, RECEIVE, TranscriptStart>(),
            g::send::<RECEIVE, TX_KEYS, ReadAdmission>(),
        ),
    );
    let settled_write = g::seq(
        g::send::<PREFIX_TX, TX_KEYS, WriteStart>(),
        g::send::<TX_KEYS, PREFIX_RX, WriteForAdmission>(),
    );
    g::seq(
        g::par(authenticated_read, settled_write),
        g::seq(
            g::send::<TX_KEYS, RX_KEYS, KeyControlAdmission>(),
            g::seq(
                g::send::<TX_KEYS, TRANSMIT, WriteAdmission>(),
                g::send::<TRANSMIT, SOURCE, StreamAdmission>(),
            ),
        ),
    )
}

fn source_base() -> impl Projectable {
    let chunks = g::route(
        g::seq(
            g::send::<SOURCE, INGRESS, SourceData>(),
            g::seq(
                g::route(
                    g::send::<INGRESS, SOURCE, SourceAccepted>(),
                    g::route(
                        g::send::<INGRESS, SOURCE, SourceStopped>(),
                        g::route(
                            g::send::<INGRESS, SOURCE, SourceRejected>(),
                            g::send::<INGRESS, SOURCE, SourceDataFailed>(),
                        ),
                    ),
                ),
                g::send::<SOURCE, INGRESS, SourceTaken>(),
            ),
        ),
        g::send::<SOURCE, INGRESS, SourceDataFinished>(),
    )
    .roll();
    let stream = g::seq(
        g::send::<SOURCE, INGRESS, SourceOpen>(),
        g::seq(
            chunks,
            g::seq(
                g::route(
                    g::send::<SOURCE, INGRESS, SourceFin>(),
                    g::send::<SOURCE, INGRESS, SourceAbandon>(),
                ),
                g::route(
                    g::send::<INGRESS, SOURCE, SourceEnded>(),
                    g::route(
                        g::send::<INGRESS, SOURCE, SourceEndStopped>(),
                        g::route(
                            g::send::<INGRESS, SOURCE, SourceEndRejected>(),
                            g::send::<INGRESS, SOURCE, SourceEndFailed>(),
                        ),
                    ),
                ),
            ),
        ),
    );
    g::seq(
        g::route(stream, g::send::<SOURCE, INGRESS, SourceDone>()).roll(),
        g::seq(
            g::send::<INGRESS, SOURCE, SourceRetired>(),
            g::route(
                g::send::<SOURCE, SOURCE_JOIN, SourceJoined>(),
                g::send::<SOURCE, SOURCE_JOIN, SourceFailed>(),
            ),
        ),
    )
}

pub fn source_choreography() -> impl Projectable {
    let receipts = g::route(
        g::seq(
            g::send::<INGRESS, SOURCE_COLLECTOR, ProductionReclaim>(),
            g::send::<SOURCE_COLLECTOR, INGRESS, ProductionStored>(),
        ),
        g::seq(
            g::send::<INGRESS, SOURCE_COLLECTOR, ProductionReclaimsDone>(),
            g::send::<SOURCE_COLLECTOR, INGRESS, ProductionReclaimsClosed>(),
        ),
    )
    .roll();
    g::par(source_base(), receipts)
}
pub fn receive_choreography() -> impl Projectable {
    let packets = g::seq(
        g::route(
            g::seq(
                g::send::<RECEIVE, SINK, ReceivedData>(),
                g::route(
                    g::send::<SINK, RECEIVE, ReceivedMore>(),
                    g::route(
                        g::send::<SINK, RECEIVE, ReceivedFin>(),
                        g::route(
                            g::send::<SINK, RECEIVE, ReceivedFailed>(),
                            g::send::<SINK, RECEIVE, ReceivedInterrupted>(),
                        ),
                    ),
                ),
            ),
            g::send::<RECEIVE, SINK, ReceiveRetire>(),
        )
        .roll(),
        g::send::<SINK, RECEIVE, ReceiveRetired>(),
    );
    let receipts = g::route(
        g::seq(
            g::route(
                g::send::<SINK, INPUT_COLLECTOR, InputReclaim>(),
                g::send::<SINK, INPUT_COLLECTOR, NoInputReclaim>(),
            ),
            g::send::<INPUT_COLLECTOR, SINK, InputStored>(),
        ),
        g::seq(
            g::send::<SINK, INPUT_COLLECTOR, InputReclaimsDone>(),
            g::send::<INPUT_COLLECTOR, SINK, InputReclaimsClosed>(),
        ),
    )
    .roll();
    g::par(packets, receipts)
}
pub fn publication_choreography() -> impl Projectable {
    let publish = g::seq(
        g::send::<TRANSMIT, ADAPTER, Datagram>(),
        g::seq(
            g::route(
                g::send::<ADAPTER, TRANSMIT, Accepted>(),
                g::send::<ADAPTER, TRANSMIT, Rejected>(),
            ),
            g::send::<TRANSMIT, ADAPTER, Settled>(),
        ),
    );
    let reset = g::seq(
        g::send::<TRANSMIT, ADAPTER, ApplyStop>(),
        g::seq(
            g::route(
                g::send::<ADAPTER, TRANSMIT, StopApplied>(),
                g::send::<ADAPTER, TRANSMIT, StopFailed>(),
            )
            .resolve::<STOP_RESULT>(),
            g::send::<TRANSMIT, ADAPTER, StopSettled>(),
        ),
    );
    let base = g::seq(
        g::route(
            publish,
            g::route(
                reset,
                g::route(
                    g::seq(
                        g::send::<TRANSMIT, ADAPTER, ApplyAcknowledgments>(),
                        g::seq(
                            g::send::<ADAPTER, TRANSMIT, AcknowledgmentsApplied>(),
                            g::seq(
                                g::route(
                                    g::seq(
                                        g::send::<ADAPTER, TRANSMIT, StreamDelivered>(),
                                        g::send::<TRANSMIT, ADAPTER, StreamDeliverySeen>(),
                                    ),
                                    g::send::<ADAPTER, TRANSMIT, DeliveriesDone>(),
                                )
                                .roll(),
                                g::send::<TRANSMIT, ADAPTER, AcknowledgmentsSettled>(),
                            ),
                        ),
                    ),
                    g::route(
                        g::seq(
                            g::send::<TRANSMIT, ADAPTER, ApplyLoss>(),
                            g::seq(
                                g::send::<ADAPTER, TRANSMIT, LossApplied>(),
                                g::send::<TRANSMIT, ADAPTER, LossSettled>(),
                            ),
                        ),
                        g::route(
                            g::seq(
                                g::send::<TRANSMIT, ADAPTER, ReclaimStream>(),
                                g::seq(
                                    g::send::<ADAPTER, TRANSMIT, StreamReclaimed>(),
                                    g::send::<TRANSMIT, ADAPTER, ReclaimSettled>(),
                                ),
                            ),
                            g::send::<TRANSMIT, ADAPTER, StopPublication>(),
                        ),
                    ),
                ),
            ),
        )
        .roll(),
        g::send::<ADAPTER, TRANSMIT, PublicationStopped>(),
    );
    let receipt = g::route(
        g::seq(
            g::send::<TRANSMIT, DELIVERY_COLLECTOR, DeliveryReclaim>(),
            g::send::<DELIVERY_COLLECTOR, TRANSMIT, DeliveryStored>(),
        ),
        g::seq(
            g::send::<TRANSMIT, DELIVERY_COLLECTOR, DeliveryReclaimsDone>(),
            g::send::<DELIVERY_COLLECTOR, TRANSMIT, DeliveryReclaimsClosed>(),
        ),
    )
    .roll();
    g::par(base, receipt)
}

pub fn key_choreography() -> impl Projectable {
    let peer_update = g::seq(
        g::send::<RX_KEYS, TX_KEYS, PeerUpdate>(),
        g::route(
            g::send::<TX_KEYS, RX_KEYS, WriteInstalled>(),
            g::send::<TX_KEYS, RX_KEYS, UpdateFailed>(),
        ),
    );
    let key_ack = g::seq(
        g::send::<RX_KEYS, TX_KEYS, KeyAck>(),
        g::route(
            g::send::<TX_KEYS, RX_KEYS, KeyAckApplied>(),
            g::send::<TX_KEYS, RX_KEYS, KeyAckFailed>(),
        ),
    );
    let confirmation = g::seq(
        g::send::<RX_KEYS, TX_KEYS, Confirmed>(),
        g::route(
            g::send::<TX_KEYS, RX_KEYS, ConfirmationApplied>(),
            g::send::<TX_KEYS, RX_KEYS, ConfirmationFailed>(),
        ),
    );
    let key_work = g::route(
        peer_update,
        g::route(
            key_ack,
            g::route(
                confirmation,
                g::route(
                    g::seq(
                        g::send::<RX_KEYS, TX_KEYS, LocalUpdate>(),
                        g::seq(
                            g::route(
                                g::send::<TX_KEYS, RX_KEYS, LocalInstalled>(),
                                g::send::<TX_KEYS, RX_KEYS, LocalRejected>(),
                            ),
                            g::send::<RX_KEYS, TX_KEYS, LocalSettled>(),
                        ),
                    ),
                    g::send::<RX_KEYS, TX_KEYS, KeysRetire>(),
                ),
            ),
        ),
    )
    .roll();
    g::seq(key_work, g::send::<TX_KEYS, RX_KEYS, KeysRetired>())
}

pub fn choreography() -> impl Projectable {
    let source = source_choreography();
    let receive = receive_choreography();

    let keys = key_choreography();

    let timer = g::route(
        g::seq(
            g::send::<CLOCK, TX_CLOCK, Expired>(),
            g::send::<TX_CLOCK, CLOCK, TimerTaken>(),
        ),
        g::seq(
            g::send::<CLOCK, TX_CLOCK, ClockRetired>(),
            g::send::<TX_CLOCK, CLOCK, ClockAcknowledged>(),
        ),
    )
    .roll();
    let publication = publication_choreography();

    let peer = g::seq(
        g::route(
            g::send::<PEER_EVENT, PEER_CLOSE, PeerClose>(),
            g::route(
                g::send::<PEER_EVENT, PEER_CLOSE, PeerFailed>(),
                g::route(
                    g::send::<PEER_EVENT, PEER_CLOSE, PeerApplicationFailed>(),
                    g::send::<PEER_EVENT, PEER_CLOSE, PeerCancelled>(),
                ),
            ),
        ),
        g::send::<PEER_CLOSE, PEER_EVENT, PeerSeen>(),
    );
    let files = g::seq(
        g::route(
            g::route(
                g::send::<FILES_EVENT, FILES_CLOSE, FilesComplete>(),
                g::send::<FILES_EVENT, FILES_CLOSE, ResponsesComplete>(),
            ),
            g::route(
                g::send::<FILES_EVENT, FILES_CLOSE, ApplicationFailed>(),
                g::route(
                    g::send::<FILES_EVENT, FILES_CLOSE, IdleExpired>(),
                    g::send::<FILES_EVENT, FILES_CLOSE, CompletionCancelled>(),
                ),
            ),
        ),
        g::send::<FILES_CLOSE, FILES_EVENT, CompletionSeen>(),
    );
    let terminal = g::par(peer, files);

    // Each lane is an actual bounded IO/key/clock continuation. They all finish
    // before the closing capability and sole write key can be transferred.
    let ordinary_base = g::par(
        source,
        g::par(
            receive,
            g::par(keys, g::par(timer, g::par(publication, terminal))),
        ),
    );
    let ordinary = g::par(
        g::par(
            g::par(ordinary_base, e::choreography()),
            crate::quic::path::global::choreography(),
        ),
        crate::http3::global::choreography(),
    );
    // The fresh close owner passes the actual accumulated grant to one
    // retired owner at a time. Each response requires consuming that grant;
    // no unsolicited input can occupy a capacity-one carrier ahead of it.
    let retired_keys = g::seq(
        g::send::<CLOSE_JOIN, RX_KEYS, KeyRetirementGrant>(),
        g::send::<RX_KEYS, CLOSE_JOIN, KeyRetirement>(),
    );
    let retired_peer = g::seq(
        g::send::<CLOSE_JOIN, PEER_CLOSE, PeerRetirementGrant>(),
        g::send::<PEER_CLOSE, CLOSE_JOIN, PeerOutcome>(),
    );
    let retired_files = g::seq(
        g::send::<CLOSE_JOIN, FILES_CLOSE, FilesRetirementGrant>(),
        g::send::<FILES_CLOSE, CLOSE_JOIN, FilesOutcome>(),
    );
    let retirement = g::seq(
        g::par(
            g::send::<TRANSMIT, CLOSE_JOIN, PublicationRetired>(),
            g::par(retired_keys, g::par(retired_peer, retired_files)),
        ),
        g::send::<CLOSE_JOIN, TRANSMIT, CloseAuthority>(),
    );

    let close_packet = g::seq(
        g::send::<TRANSMIT, ADAPTER, CloseDatagram>(),
        g::seq(
            g::route(
                g::send::<ADAPTER, TRANSMIT, CloseAccepted>(),
                g::send::<ADAPTER, TRANSMIT, CloseRejected>(),
            )
            .resolve::<SUBMISSION_RESULT>(),
            g::send::<TRANSMIT, ADAPTER, CloseSettled>(),
        ),
    );
    let closing = g::seq(
        g::route(
            close_packet,
            g::send::<TRANSMIT, ADAPTER, CloseFlightDone>(),
        )
        .roll(),
        g::send::<ADAPTER, TRANSMIT, CloseFlightSettled>(),
    );
    let draining = g::seq(
        g::send::<TRANSMIT, ADAPTER, Drain>(),
        g::send::<ADAPTER, TRANSMIT, Drained>(),
    );
    let final_phase = g::seq(
        g::route(closing, draining),
        g::seq(
            g::send::<TRANSMIT, ADAPTER, Retire>(),
            g::send::<ADAPTER, TRANSMIT, Retired>(),
        ),
    );
    g::seq(ordinary, g::seq(retirement, final_phase))
}

pub type EarlyRequest = g::Msg<209, u64>;
pub type EarlyStored = g::Msg<210, u64>;
pub type EarlyRequestsDone = g::Msg<211, u64>;
pub type EarlyReceiptsDone = g::Msg<212, u64>;
fn early_admission() -> impl Projectable {
    g::route(
        g::seq(
            g::send::<SOURCE, INGRESS, EarlyRequest>(),
            g::seq(
                g::seq(
                    g::send::<INGRESS, SOURCE_COLLECTOR, ProductionReclaim>(),
                    g::send::<SOURCE_COLLECTOR, INGRESS, ProductionStored>(),
                ),
                g::send::<INGRESS, SOURCE, EarlyStored>(),
            ),
        ),
        g::seq(
            g::send::<SOURCE, INGRESS, EarlyRequestsDone>(),
            g::send::<INGRESS, SOURCE_COLLECTOR, EarlyReceiptsDone>(),
        ),
    )
    .roll()
}

pub struct Programs {
    pub ecn_owner: RoleProgram<{ e::OWNER }>,
    pub handshake: crate::quic::global::Programs,
    pub source: RoleProgram<SOURCE>,
    pub source_join: RoleProgram<SOURCE_JOIN>,
    pub ingress: RoleProgram<INGRESS>,
    pub receive: RoleProgram<RECEIVE>,
    pub sink: RoleProgram<SINK>,
    pub rx_keys: RoleProgram<RX_KEYS>,
    pub tx_keys: RoleProgram<TX_KEYS>,
    pub clock: RoleProgram<CLOCK>,
    pub tx_clock: RoleProgram<TX_CLOCK>,
    pub transmit: RoleProgram<TRANSMIT>,
    pub adapter: RoleProgram<ADAPTER>,
    pub peer_event: RoleProgram<PEER_EVENT>,
    pub peer_close: RoleProgram<PEER_CLOSE>,
    pub files_event: RoleProgram<FILES_EVENT>,
    pub files_close: RoleProgram<FILES_CLOSE>,
    pub close_join: RoleProgram<CLOSE_JOIN>,
    pub source_collector: RoleProgram<SOURCE_COLLECTOR>,
    pub input_collector: RoleProgram<INPUT_COLLECTOR>,
    pub delivery_collector: RoleProgram<DELIVERY_COLLECTOR>,
}

/// One projected session includes the actual TLS prefix and every subsequent
/// local continuation. The host creates endpoints once and never selects phases.
pub fn programs() -> Programs {
    let global = g::seq(
        crate::quic::global::choreography(),
        g::seq(
            startup(),
            g::seq(
                crate::quic::early_data::global::bridge(),
                g::seq(early_admission(), choreography()),
            ),
        ),
    );
    Programs {
        ecn_owner: project(&global),
        handshake: crate::quic::global::Programs {
            rx: project(&global),
            tls_rx: project(&global),
            tx: project(&global),
            tls_tx: project(&global),
            tls_complete: project(&global),
            tls_handoff: project(&global),
            udp: project(&global),
            timer: project(&global),
            timer_tx: project(&global),
            tx_wire: project(&global),
            initial_event: project(&global),
            initial_owner: project(&global),
            timer_stop: project(&global),
            receive_stop: project(&global),
        },
        source: project(&global),
        source_join: project(&global),
        ingress: project(&global),
        receive: project(&global),
        sink: project(&global),
        rx_keys: project(&global),
        tx_keys: project(&global),
        clock: project(&global),
        tx_clock: project(&global),
        transmit: project(&global),
        adapter: project(&global),
        peer_event: project(&global),
        peer_close: project(&global),
        files_event: project(&global),
        files_close: project(&global),
        close_join: project(&global),
        source_collector: project(&global),
        input_collector: project(&global),
        delivery_collector: project(&global),
    }
}
