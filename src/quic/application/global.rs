//! The connected global: actual affine startup, concurrent ordinary endpoints,
//! complete ordinary retirement, then closing or draining.
//!
//! [`crate::quic::application::localside::Endpoints`] attaches the participants.
//! The TLS installation and packet-write endpoints continue from the handshake.
//! [`crate::quic::application::localside::run`] shows which actual futures own or borrow each endpoint
//! and how those futures are polled together.
use crate::quic::ecn::global as e;
use crate::quic::global::{RX as PREFIX_RX, TLS_RX as PREFIX_TLS_RX, TX as PREFIX_TX};
use hibana::Endpoint;
use hibana::g;
use hibana::runtime::program::Projectable;

pub const SOURCE: u8 = 8;
pub const INGRESS: u8 = 9;
pub const RECEIVE: u8 = 10;
pub const SINK: u8 = 11;
/// The TLS installation endpoint continues as the client's key-control endpoint.
pub const RX_KEYS: u8 = hibana_tls::handshake::global::owned::MATERIAL;
/// The packet-write endpoint returned by the handshake continues into key
/// updates, packet preparation, and connection closing.
pub const WRITE_KEYS: u8 = hibana_tls::handshake::global::owned::WRITE_KEYS;
pub const CLOCK: u8 = 14;
pub const TX_CLOCK: u8 = 15;
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
/// Permission to produce the current stream's data and return it at its end.
pub const PRODUCTION: u8 = hibana_tls::handshake::global::owned::PRODUCTION;
pub type StreamLoan<'r> = g::Msg<221, Endpoint<'r, PRODUCTION>>;
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
pub type StopClock = g::Msg<223, ()>;
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
pub type CloseFlightDone = g::Msg<213, ()>;
pub type CloseFlightSettled = g::Msg<37, ()>;
pub type Drain = g::Msg<38, ()>;
pub type Drained = g::Msg<39, ()>;
pub type Retire = g::Msg<40, ()>;
pub type Retired = g::Msg<41, ()>;
// Parallel terminal observations join before connection retirement.
pub type PeerClose = g::Msg<44, u64>;
pub type PeerApplicationClose = g::Msg<224, u64>;
pub type PeerFailed = g::Msg<45, u64>;
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

pub type SourceOpen = g::Msg<168, u64>;
/// Finish the stream and return its production endpoint to ingress.
pub type SourceFin<'r> = g::Msg<169, Endpoint<'r, PRODUCTION>>;
/// Stop producing data and return its endpoint without sending FIN.
pub type SourceAbandon<'r> = g::Msg<170, Endpoint<'r, PRODUCTION>>;
pub type SourceEnded = g::Msg<171, u64>;
pub type SourceEndRejected = g::Msg<172, u64>;
/// Wait for ingress to finish consuming the current stream's input.
pub type SourceFlush = g::Msg<173, u64>;
pub type SourceFlushed = g::Msg<222, u64>;
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
/// Verified TLS startup lets the source begin opening application streams.
pub type StreamAdmission = g::Msg<163, ()>;
pub type ReadAdmission = g::Msg<165, ()>;
pub type KeyControlAdmission<'r> = g::Msg<166, Endpoint<'r, RX_KEYS>>;
pub type WriteForAdmission = g::Msg<167, ()>;

fn startup() -> impl Projectable {
    // RX validates Finished and transport parameters after write startup.
    // TLS_RX and RECEIVE acknowledge that validation before traffic starts.
    let authenticated_read = g::seq(
        g::send::<PREFIX_RX, PREFIX_TLS_RX, FinishedValidated>(),
        g::seq(
            g::send::<PREFIX_TLS_RX, RECEIVE, TranscriptStart>(),
            g::send::<RECEIVE, PREFIX_TX, ReadAdmission>(),
        ),
    );
    let settled_write = g::send::<PREFIX_TX, PREFIX_RX, WriteForAdmission>();
    g::seq(
        g::seq(settled_write, authenticated_read),
        g::par(
            g::send::<PREFIX_TLS_RX, RECEIVE, KeyControlAdmission<'_>>(),
            g::send::<PREFIX_TX, SOURCE, StreamAdmission>(),
        ),
    )
}

pub fn source_choreography() -> impl Projectable {
    let chunks = g::route(
        g::seq(
            g::send::<PRODUCTION, INGRESS, SourceData>(),
            g::seq(
                g::route(
                    g::send::<INGRESS, PRODUCTION, SourceAccepted>(),
                    g::route(
                        g::send::<INGRESS, PRODUCTION, SourceStopped>(),
                        g::route(
                            g::send::<INGRESS, PRODUCTION, SourceRejected>(),
                            g::send::<INGRESS, PRODUCTION, SourceDataFailed>(),
                        ),
                    ),
                ),
                g::send::<PRODUCTION, INGRESS, SourceTaken>(),
            ),
        ),
        g::seq(
            g::send::<PRODUCTION, INGRESS, SourceFlush>(),
            g::send::<INGRESS, PRODUCTION, SourceFlushed>(),
        ),
    )
    .roll();
    let stream = g::seq(
        g::send::<SOURCE, INGRESS, SourceOpen>(),
        g::seq(
            g::send::<INGRESS, SOURCE, StreamLoan<'_>>(),
            g::seq(
                chunks,
                g::seq(
                    g::route(
                        g::send::<SOURCE, INGRESS, SourceFin<'_>>(),
                        g::send::<SOURCE, INGRESS, SourceAbandon<'_>>(),
                    ),
                    g::seq(
                        g::send::<INGRESS, SOURCE_COLLECTOR, ProductionReclaim>(),
                        g::seq(
                            g::send::<SOURCE_COLLECTOR, INGRESS, ProductionStored>(),
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
                ),
            ),
        ),
    );
    let stopped = g::seq(
        g::send::<SOURCE, INGRESS, SourceDone>(),
        g::seq(
            g::send::<INGRESS, SOURCE_COLLECTOR, ProductionReclaimsDone>(),
            g::send::<SOURCE_COLLECTOR, INGRESS, ProductionReclaimsClosed>(),
        ),
    );
    g::seq(
        g::route(stream, stopped).roll(),
        g::seq(
            g::send::<INGRESS, SOURCE, SourceRetired>(),
            g::route(
                g::send::<SOURCE, SOURCE_JOIN, SourceJoined>(),
                g::send::<SOURCE, SOURCE_JOIN, SourceFailed>(),
            ),
        ),
    )
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
    g::par(
        g::seq(packets, g::send::<RECEIVE, CLOCK, StopClock>()),
        receipts,
    )
}
pub fn publication_choreography() -> impl Projectable {
    let publish = g::seq(
        g::send::<WRITE_KEYS, ADAPTER, Datagram>(),
        g::seq(
            g::route(
                g::send::<ADAPTER, WRITE_KEYS, Accepted>(),
                g::send::<ADAPTER, WRITE_KEYS, Rejected>(),
            ),
            g::send::<WRITE_KEYS, ADAPTER, Settled>(),
        ),
    );
    let reset = g::seq(
        g::send::<WRITE_KEYS, ADAPTER, ApplyStop>(),
        g::seq(
            g::route(
                g::send::<ADAPTER, WRITE_KEYS, StopApplied>(),
                g::send::<ADAPTER, WRITE_KEYS, StopFailed>(),
            )
            .resolve::<STOP_RESULT>(),
            g::send::<WRITE_KEYS, ADAPTER, StopSettled>(),
        ),
    );
    let base = g::seq(
        g::route(
            publish,
            g::route(
                reset,
                g::route(
                    g::seq(
                        g::send::<WRITE_KEYS, ADAPTER, ApplyAcknowledgments>(),
                        g::seq(
                            g::send::<ADAPTER, WRITE_KEYS, AcknowledgmentsApplied>(),
                            g::seq(
                                g::route(
                                    g::seq(
                                        g::send::<ADAPTER, WRITE_KEYS, StreamDelivered>(),
                                        g::send::<WRITE_KEYS, ADAPTER, StreamDeliverySeen>(),
                                    ),
                                    g::send::<ADAPTER, WRITE_KEYS, DeliveriesDone>(),
                                )
                                .roll(),
                                g::send::<WRITE_KEYS, ADAPTER, AcknowledgmentsSettled>(),
                            ),
                        ),
                    ),
                    g::route(
                        g::seq(
                            g::send::<WRITE_KEYS, ADAPTER, ApplyLoss>(),
                            g::seq(
                                g::send::<ADAPTER, WRITE_KEYS, LossApplied>(),
                                g::send::<WRITE_KEYS, ADAPTER, LossSettled>(),
                            ),
                        ),
                        g::route(
                            g::seq(
                                g::send::<WRITE_KEYS, ADAPTER, ReclaimStream>(),
                                g::seq(
                                    g::send::<ADAPTER, WRITE_KEYS, StreamReclaimed>(),
                                    g::send::<WRITE_KEYS, ADAPTER, ReclaimSettled>(),
                                ),
                            ),
                            g::send::<WRITE_KEYS, ADAPTER, StopPublication>(),
                        ),
                    ),
                ),
            ),
        )
        .roll(),
        g::send::<ADAPTER, WRITE_KEYS, PublicationStopped>(),
    );
    let receipt = g::route(
        g::seq(
            g::send::<WRITE_KEYS, DELIVERY_COLLECTOR, DeliveryReclaim>(),
            g::send::<DELIVERY_COLLECTOR, WRITE_KEYS, DeliveryStored>(),
        ),
        g::seq(
            g::send::<WRITE_KEYS, DELIVERY_COLLECTOR, DeliveryReclaimsDone>(),
            g::send::<DELIVERY_COLLECTOR, WRITE_KEYS, DeliveryReclaimsClosed>(),
        ),
    )
    .roll();
    g::par(base, receipt)
}

pub fn key_choreography() -> impl Projectable {
    let peer_update = g::seq(
        g::send::<RX_KEYS, WRITE_KEYS, PeerUpdate>(),
        g::route(
            g::send::<WRITE_KEYS, RX_KEYS, WriteInstalled>(),
            g::send::<WRITE_KEYS, RX_KEYS, UpdateFailed>(),
        ),
    );
    let key_ack = g::seq(
        g::send::<RX_KEYS, WRITE_KEYS, KeyAck>(),
        g::route(
            g::send::<WRITE_KEYS, RX_KEYS, KeyAckApplied>(),
            g::send::<WRITE_KEYS, RX_KEYS, KeyAckFailed>(),
        ),
    );
    let confirmation = g::seq(
        g::send::<RX_KEYS, WRITE_KEYS, Confirmed>(),
        g::route(
            g::send::<WRITE_KEYS, RX_KEYS, ConfirmationApplied>(),
            g::send::<WRITE_KEYS, RX_KEYS, ConfirmationFailed>(),
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
                        g::send::<RX_KEYS, WRITE_KEYS, LocalUpdate>(),
                        g::seq(
                            g::route(
                                g::send::<WRITE_KEYS, RX_KEYS, LocalInstalled>(),
                                g::send::<WRITE_KEYS, RX_KEYS, LocalRejected>(),
                            ),
                            g::send::<RX_KEYS, WRITE_KEYS, LocalSettled>(),
                        ),
                    ),
                    g::send::<RX_KEYS, WRITE_KEYS, KeysRetire>(),
                ),
            ),
        ),
    )
    .roll();
    g::seq(key_work, g::send::<WRITE_KEYS, RX_KEYS, KeysRetired>())
}

fn timer_choreography() -> impl Projectable {
    g::route(
        g::seq(
            g::send::<CLOCK, TX_CLOCK, Expired>(),
            g::send::<TX_CLOCK, CLOCK, TimerTaken>(),
        ),
        g::send::<CLOCK, TX_CLOCK, ClockRetired>(),
    )
    .roll()
}

fn terminal_choreography() -> impl Projectable {
    let peer = g::seq(
        g::route(
            g::route(
                g::send::<PEER_EVENT, PEER_CLOSE, PeerClose>(),
                g::send::<PEER_EVENT, PEER_CLOSE, PeerApplicationClose>(),
            ),
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
    g::par(peer, files)
}

fn ordinary() -> impl Projectable {
    let source = source_choreography();
    let receive = receive_choreography();
    let keys = key_choreography();
    let timer = timer_choreography();
    let publication = publication_choreography();

    let terminal = terminal_choreography();

    // Run the independent protocol fragments before joining their retirement.
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
    // CLOCK joins its timeout loop and receive-side stop notice before
    // consuming the retirement acknowledgment.
    let ordinary = g::seq(ordinary, g::send::<TX_CLOCK, CLOCK, ClockAcknowledged>());
    // Join publication and the independent key, peer and file acknowledgments
    // before the transmit role begins closing.
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
            g::send::<WRITE_KEYS, CLOSE_JOIN, PublicationRetired>(),
            g::par(retired_keys, g::par(retired_peer, retired_files)),
        ),
        g::send::<CLOSE_JOIN, WRITE_KEYS, CloseAuthority>(),
    );

    let close_packet = g::seq(
        g::send::<WRITE_KEYS, ADAPTER, CloseDatagram>(),
        g::seq(
            g::route(
                g::send::<ADAPTER, WRITE_KEYS, CloseAccepted>(),
                g::send::<ADAPTER, WRITE_KEYS, CloseRejected>(),
            )
            .resolve::<SUBMISSION_RESULT>(),
            g::send::<WRITE_KEYS, ADAPTER, CloseSettled>(),
        ),
    );
    let closing = g::seq(
        g::route(
            close_packet,
            g::send::<WRITE_KEYS, ADAPTER, CloseFlightDone>(),
        )
        .roll(),
        g::send::<ADAPTER, WRITE_KEYS, CloseFlightSettled>(),
    );
    let draining = g::seq(
        g::send::<WRITE_KEYS, ADAPTER, Drain>(),
        g::send::<ADAPTER, WRITE_KEYS, Drained>(),
    );
    let final_phase = g::seq(
        g::route(closing, draining),
        g::seq(
            g::send::<WRITE_KEYS, ADAPTER, Retire>(),
            g::send::<ADAPTER, WRITE_KEYS, Retired>(),
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

/// The complete connected protocol, including its authenticated handshake prefix.
pub fn choreography() -> impl Projectable {
    g::seq(
        crate::quic::global::choreography(),
        g::seq(
            startup(),
            g::seq(
                crate::quic::early_data::global::bridge(),
                g::seq(early_admission(), ordinary()),
            ),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::carrier::CarrierStorage;
    use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn one_returned_stream_can_join_its_source_collector() {
        let scope = crate::crypto::directional::ApplicationKeyScope::new(99);
        let bindings = scope.endpoint_bindings();
        let global = g::seq(early_admission(), source_choreography());
        let source_program = project::<SOURCE>(&global);
        let ingress_program = project::<INGRESS>(&global);
        let production_program = project::<PRODUCTION>(&global);
        let collector_program = project::<SOURCE_COLLECTOR>(&global);
        let joined_program = project::<SOURCE_JOIN>(&global);
        let session = SessionId::new(99);
        let queues = CarrierStorage::<1, 16, 16>::new();
        let carrier = queues.bind(session, &bindings).unwrap();
        let mut slab = [0; 64 * 1024];
        let mut storage = SessionKitStorage::uninit();
        let rv = storage.init().rendezvous(&mut slab, &carrier).unwrap();
        let mut source = rv.enter(session, &source_program).unwrap();
        let mut ingress = rv.enter(session, &ingress_program).unwrap();
        let production = rv.enter(session, &production_program).unwrap();
        let mut collector = rv.enter(session, &collector_program).unwrap();
        let mut joined = rv.enter(session, &joined_program).unwrap();
        tokio::time::timeout(core::time::Duration::from_secs(2), async {
            tokio::try_join!(
                async {
                    source.send::<EarlyRequestsDone>(&0).await?;
                    source.send::<SourceOpen>(&0).await?;
                    let mut production = source.recv::<StreamLoan<'_>>().await?;
                    production.send::<SourceFlush>(&0).await?;
                    assert_eq!(production.recv::<SourceFlushed>().await?, 0);
                    source.send::<SourceFin<'_>>(production).await?;
                    assert_eq!(source.recv::<SourceEnded>().await?, 0);
                    source.send::<SourceDone>(&()).await?;
                    source.recv::<SourceRetired>().await?;
                    source.send::<SourceJoined>(&()).await
                },
                async {
                    assert_eq!(ingress.recv::<EarlyRequestsDone>().await?, 0);
                    ingress.send::<EarlyReceiptsDone>(&0).await?;
                    assert_eq!(ingress.recv::<SourceOpen>().await?, 0);
                    ingress.send::<StreamLoan<'_>>(production).await?;
                    assert_eq!(ingress.recv::<SourceFlush>().await?, 0);
                    ingress.send::<SourceFlushed>(&0).await?;
                    let _production = ingress.recv::<SourceFin<'_>>().await?;
                    ingress.send::<ProductionReclaim>(&0).await?;
                    assert_eq!(ingress.recv::<ProductionStored>().await?, 0);
                    ingress.send::<SourceEnded>(&0).await?;
                    ingress.recv::<SourceDone>().await?;
                    ingress.send::<ProductionReclaimsDone>(&()).await?;
                    ingress.recv::<ProductionReclaimsClosed>().await?;
                    ingress.send::<SourceRetired>(&()).await
                },
                async {
                    assert_eq!(collector.recv::<EarlyReceiptsDone>().await?, 0);
                    let branch = collector.offer().await?;
                    assert_eq!(branch.recv::<ProductionReclaim>().await?, 0);
                    collector.send::<ProductionStored>(&0).await?;
                    let branch = collector.offer().await?;
                    branch.recv::<ProductionReclaimsDone>().await?;
                    collector.send::<ProductionReclaimsClosed>(&()).await
                },
                joined.recv::<SourceJoined>(),
            )
        })
        .await
        .expect("the returned stream did not join its collector")
        .unwrap();
        assert_eq!(queues.queued(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_cannot_open_another_stream_before_returning_the_endpoint() {
        let scope = crate::crypto::directional::ApplicationKeyScope::new(96);
        let bindings = scope.endpoint_bindings();
        let global = source_choreography();
        let source_program = project::<SOURCE>(&global);
        let ingress_program = project::<INGRESS>(&global);
        let production_program = project::<PRODUCTION>(&global);
        let session = SessionId::new(96);
        let queues = CarrierStorage::<1, 16, 8>::new();
        let carrier = queues.bind(session, &bindings).unwrap();
        let mut slab = [0; 32 * 1024];
        let mut storage = SessionKitStorage::uninit();
        let rv = storage.init().rendezvous(&mut slab, &carrier).unwrap();
        let mut source = rv.enter(session, &source_program).unwrap();
        let mut ingress = rv.enter(session, &ingress_program).unwrap();
        let production = rv.enter(session, &production_program).unwrap();
        source.send::<SourceOpen>(&0).await.unwrap();
        assert_eq!(ingress.recv::<SourceOpen>().await.unwrap(), 0);
        ingress.send::<StreamLoan<'_>>(production).await.unwrap();
        let mut production = source.recv::<StreamLoan<'_>>().await.unwrap();
        production.send::<SourceFlush>(&0).await.unwrap();
        assert_eq!(ingress.recv::<SourceFlush>().await.unwrap(), 0);
        ingress.send::<SourceFlushed>(&0).await.unwrap();
        assert_eq!(production.recv::<SourceFlushed>().await.unwrap(), 0);
        assert!(source.send::<SourceOpen>(&4).await.is_err());
        assert_eq!(queues.queued(), 0, "an invalid open reached ingress");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn source_cannot_reclaim_or_retire_while_its_endpoint_is_lent() {
        for retire in [false, true] {
            let scope = crate::crypto::directional::ApplicationKeyScope::new(98);
            let bindings = scope.endpoint_bindings();
            let global = source_choreography();
            let source_program = project::<SOURCE>(&global);
            let ingress_program = project::<INGRESS>(&global);
            let production_program = project::<PRODUCTION>(&global);
            let collector_program = project::<SOURCE_COLLECTOR>(&global);
            let session = SessionId::new(98);
            let queues = CarrierStorage::<1, 16, 8>::new();
            let carrier = queues.bind(session, &bindings).unwrap();
            let mut slab = [0; 32 * 1024];
            let mut storage = SessionKitStorage::uninit();
            let rv = storage.init().rendezvous(&mut slab, &carrier).unwrap();
            let mut source = rv.enter(session, &source_program).unwrap();
            let mut ingress = rv.enter(session, &ingress_program).unwrap();
            let production = rv.enter(session, &production_program).unwrap();
            let _collector = rv.enter(session, &collector_program).unwrap();
            source.send::<SourceOpen>(&0).await.unwrap();
            assert_eq!(ingress.recv::<SourceOpen>().await.unwrap(), 0);
            ingress.send::<StreamLoan<'_>>(production).await.unwrap();
            let _production = source.recv::<StreamLoan<'_>>().await.unwrap();
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                if retire {
                    ingress.send::<ProductionReclaimsDone>(&()).await
                } else {
                    ingress.send::<ProductionReclaim>(&0).await
                }
            })
            .await
            .expect("out-of-order reclamation waited instead of failing");
            assert!(result.is_err());
            assert_eq!(queues.queued(), 0, "an early reclaim reached the collector");
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn terminal_outcomes_travel_in_their_projected_messages() {
        use crate::crypto::directional::ApplicationKeyScope;
        use crate::quic::application::localside::termination;
        use crate::quic::application::{CloseKind, Control, Error};
        use crate::quic::imp::publication_gate::PublicationGate;
        let protocol = crate::http3::Protocol::Http3;
        for peer_branch in 0..5 {
            for files_branch in 0..5 {
                for peer_first in [false, true] {
                    let mut scope = ApplicationKeyScope::new(97);
                    let mut installation = scope.claim().unwrap();
                    let mut gate =
                        PublicationGate::new(installation.take_publication_gate().unwrap());
                    let (_, stop) = gate.split().unwrap();
                    let control = Control::new(stop);
                    let exchange = termination::Exchange::new(&control, protocol);
                    let global = terminal_choreography();
                    let peer_program = project::<PEER_EVENT>(&global);
                    let peer_close_program = project::<PEER_CLOSE>(&global);
                    let files_program = project::<FILES_EVENT>(&global);
                    let files_close_program = project::<FILES_CLOSE>(&global);
                    let session = SessionId::new(97);
                    let queues = CarrierStorage::<1, 16, 8>::new();
                    let carrier = queues.bind(session, &[]).unwrap();
                    let mut slab = [0; 16 * 1024];
                    let mut storage = SessionKitStorage::uninit();
                    let rv = storage.init().rendezvous(&mut slab, &carrier).unwrap();
                    let mut peer = rv.enter(session, &peer_program).unwrap();
                    let mut peer_close = rv.enter(session, &peer_close_program).unwrap();
                    let mut files = rv.enter(session, &files_program).unwrap();
                    let mut files_close = rv.enter(session, &files_close_program).unwrap();
                    let code = 0x103;
                    let sending_peer = async {
                        let expected = match peer_branch {
                            0 => {
                                peer.send::<PeerClose>(&code).await?;
                                Some(CloseKind::Peer { code })
                            }
                            1 => {
                                peer.send::<PeerApplicationClose>(&code).await?;
                                Some(CloseKind::PeerApplication { code })
                            }
                            2 => {
                                peer.send::<PeerFailed>(&code).await?;
                                Some(CloseKind::Local {
                                    application: false,
                                    code,
                                })
                            }
                            3 => {
                                peer.send::<PeerApplicationFailed>(&()).await?;
                                Some(CloseKind::Local {
                                    application: true,
                                    code: protocol.failure_code(),
                                })
                            }
                            4 => {
                                peer.send::<PeerCancelled>(&()).await?;
                                None
                            }
                            _ => unreachable!(),
                        };
                        peer.recv::<PeerSeen>().await?;
                        Ok::<_, Error>(expected)
                    };
                    let sending_files = async {
                        let expected = match files_branch {
                            0 => {
                                files.send::<ResponsesComplete>(&()).await?;
                                Some(CloseKind::Local {
                                    application: true,
                                    code: protocol.success_code(),
                                })
                            }
                            1 => {
                                files.send::<FilesComplete>(&()).await?;
                                Some(CloseKind::Local {
                                    application: true,
                                    code: protocol.success_code(),
                                })
                            }
                            2 => {
                                files.send::<ApplicationFailed>(&()).await?;
                                Some(CloseKind::Local {
                                    application: true,
                                    code: protocol.failure_code(),
                                })
                            }
                            3 => {
                                files.send::<IdleExpired>(&()).await?;
                                Some(CloseKind::IdleExpired)
                            }
                            4 => {
                                files.send::<CompletionCancelled>(&()).await?;
                                None
                            }
                            _ => unreachable!(),
                        };
                        files.recv::<CompletionSeen>().await?;
                        Ok::<_, Error>(expected)
                    };
                    let sending = async {
                        if peer_first {
                            crate::runtime::join::values2(sending_peer, sending_files).await
                        } else {
                            let (files, peer) =
                                crate::runtime::join::values2(sending_files, sending_peer).await?;
                            Ok((peer, files))
                        }
                    };
                    let (expected, actual) =
                        tokio::time::timeout(std::time::Duration::from_secs(5), async {
                            tokio::try_join!(
                                sending,
                                termination::receive(&mut peer_close, &mut files_close, &exchange)
                            )
                        })
                        .await
                        .expect("terminal localsides stalled")
                        .unwrap();
                    assert_eq!(actual, expected);
                    assert_eq!(queues.queued(), 0);
                    assert_eq!(control.stopping(), actual.0.is_some() || actual.1.is_some());
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn validation_cannot_be_reported_before_write_startup_arrives() {
        let global = startup();
        let session = SessionId::new(91);
        let queues = CarrierStorage::<1, 16, 2>::new();
        let carrier = queues.bind(session, &[]).unwrap();
        let mut slab = [0; 16 * 1024];
        let mut storage = SessionKitStorage::uninit();
        let rendezvous = storage.init().rendezvous(&mut slab, &carrier).unwrap();
        let program = project::<PREFIX_RX>(&global);
        let mut receive = rendezvous.enter(session, &program).unwrap();
        assert!(receive.send::<FinishedValidated>(&()).await.is_err());
        assert_eq!(queues.queued(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn validation_can_be_reported_after_write_startup_arrives() {
        let global = startup();
        let session = SessionId::new(92);
        const PORTS: usize = [PREFIX_TX, PREFIX_RX, PREFIX_TLS_RX].len();
        let queues = CarrierStorage::<1, 16, PORTS>::new();
        let carrier = queues.bind(session, &[]).unwrap();
        let mut slab = [0; 16 * 1024];
        let mut storage = SessionKitStorage::uninit();
        let rendezvous = storage.init().rendezvous(&mut slab, &carrier).unwrap();
        let sent = project::<PREFIX_TX>(&global);
        let received = project::<PREFIX_RX>(&global);
        let verified = project::<PREFIX_TLS_RX>(&global);
        let mut sent = rendezvous.enter(session, &sent).unwrap();
        let mut receive = rendezvous.enter(session, &received).unwrap();
        let mut verified = rendezvous.enter(session, &verified).unwrap();
        sent.send::<WriteForAdmission>(&()).await.unwrap();
        receive.recv::<WriteForAdmission>().await.unwrap();
        receive.send::<FinishedValidated>(&()).await.unwrap();
        verified.recv::<FinishedValidated>().await.unwrap();
        assert_eq!(queues.queued(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clock_cannot_finish_before_the_receive_retirement_notice() {
        let global = g::seq(
            g::par(receive_choreography(), timer_choreography()),
            g::send::<TX_CLOCK, CLOCK, ClockAcknowledged>(),
        );
        let session = SessionId::new(93);
        // Packet delivery, input reclamation and timeouts are parallel.
        const PORTS: usize = [CLOCK, TX_CLOCK].len() * 3;
        let queues = CarrierStorage::<1, 16, PORTS>::new();
        let carrier = queues.bind(session, &[]).unwrap();
        let mut slab = [0; 16 * 1024];
        let mut storage = SessionKitStorage::uninit();
        let rendezvous = storage.init().rendezvous(&mut slab, &carrier).unwrap();
        let clock_program = project::<CLOCK>(&global);
        let timer_program = project::<TX_CLOCK>(&global);
        let mut clock = rendezvous.enter(session, &clock_program).unwrap();
        let mut timer = rendezvous.enter(session, &timer_program).unwrap();
        clock.send::<ClockRetired>(&()).await.unwrap();
        timer.recv::<ClockRetired>().await.unwrap();
        timer.send::<ClockAcknowledged>(&()).await.unwrap();
        assert!(clock.recv::<ClockAcknowledged>().await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clock_joins_its_notice_and_acknowledgment_in_both_orders() {
        for notice_first in [false, true] {
            let global = g::seq(
                g::par(receive_choreography(), timer_choreography()),
                g::send::<TX_CLOCK, CLOCK, ClockAcknowledged>(),
            );
            let session = SessionId::new(94 + u32::from(notice_first));
            const PORTS: usize = [CLOCK, TX_CLOCK, RECEIVE, SINK].len() * 3;
            let queues = CarrierStorage::<1, 16, PORTS>::new();
            let carrier = queues.bind(session, &[]).unwrap();
            let mut slab = [0; 16 * 1024];
            let mut storage = SessionKitStorage::uninit();
            let rendezvous = storage.init().rendezvous(&mut slab, &carrier).unwrap();
            let clock_program = project::<CLOCK>(&global);
            let timer_program = project::<TX_CLOCK>(&global);
            let receive_program = project::<RECEIVE>(&global);
            let sink_program = project::<SINK>(&global);
            let mut clock = rendezvous.enter(session, &clock_program).unwrap();
            let mut timer = rendezvous.enter(session, &timer_program).unwrap();
            let mut receive = rendezvous.enter(session, &receive_program).unwrap();
            let mut sink = rendezvous.enter(session, &sink_program).unwrap();
            let finishing = async {
                {
                    let [mut notice, mut timeouts] = clock.par()?;
                    tokio::try_join!(async { notice.recv::<StopClock>().await }, async {
                        timeouts.send::<ClockRetired>(&()).await
                    },)?;
                }
                clock.recv::<ClockAcknowledged>().await
            };
            let peer = async {
                if !notice_first {
                    timer.recv::<ClockRetired>().await?;
                    timer.send::<ClockAcknowledged>(&()).await?;
                }
                receive.send::<ReceiveRetire>(&()).await?;
                sink.recv::<ReceiveRetire>().await?;
                sink.send::<ReceiveRetired>(&()).await?;
                receive.recv::<ReceiveRetired>().await?;
                receive.send::<StopClock>(&()).await?;
                if notice_first {
                    timer.recv::<ClockRetired>().await?;
                    timer.send::<ClockAcknowledged>(&()).await?;
                }
                Ok::<(), hibana::EndpointError>(())
            };
            if notice_first {
                tokio::try_join!(peer, finishing).unwrap();
            } else {
                tokio::try_join!(finishing, peer).unwrap();
            }
            assert_eq!(queues.queued(), 0);
        }
    }
}
