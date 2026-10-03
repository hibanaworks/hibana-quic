//! Reconstructed from the retained author tool calls after executor replacement.
//! This is the last implemented finite handshake choreography; rebuild required.
use hibana::{g,runtime::program::{RoleProgram,project}};
pub const RX:u8=0;pub const TLS_RX:u8=1;pub const TX:u8=2;pub const TLS_TX:u8=3;pub const UDP:u8=4;pub const TIMER:u8=5;pub const TIMER_TX:u8=6;pub const TX_WIRE:u8=7;
pub const CRYPTO_RESULT:u16=1000;pub const ADAPTER_RESULT:u16=1001;
pub trait ReceivePhase{type Need:g::Message<Payload=u64>;type Input:g::Message<Payload=u64>;type Accepted:g::Message<Payload=u64>;type Rejected:g::Message<Payload=u64>;type Taken:g::Message<Payload=u64>;type Boundary:g::Message<Payload=u64>;}
macro_rules! rx_phase{($name:ident,$b:literal)=>{pub struct $name;impl ReceivePhase for $name{type Need=g::Msg<{$b},u64>;type Input=g::Msg<{$b+1},u64>;type Accepted=g::Msg<{$b+2},u64>;type Rejected=g::Msg<{$b+3},u64>;type Taken=g::Msg<{$b+4},u64>;type Boundary=g::Msg<{$b+5},u64>;}};}
rx_phase!(InitialReceive,0);rx_phase!(HandshakeReceive,7);rx_phase!(FinishedReceive,14);
pub type ReadHandshake=g::Msg<6,u64>;pub type ReadApplication=g::Msg<13,u64>;pub type ReceiveComplete=g::Msg<20,u64>;pub type ReceiveContinuation=g::Msg<21,u64>;
pub trait Publication{type Datagram:g::Message<Payload=u64>;type Accepted:g::Message<Payload=u64>;type Rejected:g::Message<Payload=u64>;type Settled:g::Message<Payload=u64>;}
pub struct Emission<const D:u8,const A:u8,const R:u8,const S:u8>;
impl<const D:u8,const A:u8,const R:u8,const S:u8> Publication for Emission<D,A,R,S>{type Datagram=g::Msg<D,u64>;type Accepted=g::Msg<A,u64>;type Rejected=g::Msg<R,u64>;type Settled=g::Msg<S,u64>;}
pub trait TransmitPhase{
 type Request:g::Message<Payload=u64>;type Flight:g::Message<Payload=u64>;type Idle:g::Message<Payload=u64>;type Boundary:g::Message<Payload=u64>;type Taken:g::Message<Payload=u64>;type PhaseSettled:g::Message<Payload=u64>;
 type Ack:Publication;type Probe:Publication;type Data:Publication;type BatchAck:Publication;type BatchProbe:Publication;
 type BatchEnd:g::Message<Payload=u64>;type BatchSettled:g::Message<Payload=u64>;type WireBoundary:g::Message<Payload=u64>;type WireBoundarySeen:g::Message<Payload=u64>;
}
macro_rules! tx_phase{($name:ident,$b:literal)=>{pub struct $name;impl TransmitPhase for $name{
 type Request=g::Msg<{$b},u64>;type Flight=g::Msg<{$b+1},u64>;type Idle=g::Msg<{$b+2},u64>;type Boundary=g::Msg<{$b+3},u64>;type Taken=g::Msg<{$b+4},u64>;type PhaseSettled=g::Msg<{$b+30},u64>;
 type Ack=Emission<{$b+5},{$b+6},{$b+7},{$b+8}>;type Probe=Emission<{$b+9},{$b+10},{$b+11},{$b+12}>;type Data=Emission<{$b+13},{$b+14},{$b+15},{$b+16}>;type BatchAck=Emission<{$b+17},{$b+18},{$b+19},{$b+20}>;type BatchProbe=Emission<{$b+21},{$b+22},{$b+23},{$b+24}>;
 type BatchEnd=g::Msg<{$b+25},u64>;type BatchSettled=g::Msg<{$b+26},u64>;type WireBoundary=g::Msg<{$b+27},u64>;type WireBoundarySeen=g::Msg<{$b+28},u64>;
}};}
tx_phase!(InitialTransmit,32);tx_phase!(HandshakeTransmit,64);tx_phase!(ApplicationTransmit,96);
pub type WriteHandshake=g::Msg<61,u64>;pub type WriteApplication=g::Msg<93,u64>;pub type DrainAck=Emission<128,129,130,131>;pub type DrainProbe=Emission<132,133,134,135>;pub type RecoveryDrained=g::Msg<136,u64>;pub type TransmitComplete=g::Msg<137,u64>;pub type TransmitContinuation=g::Msg<138,u64>;pub type AdapterComplete=g::Msg<139,u64>;pub type AdapterRetired=g::Msg<140,u64>;pub type TimerExpired=g::Msg<141,u64>;pub type TimerTaken=g::Msg<142,u64>;pub type TimerRetired=g::Msg<143,u64>;pub type TimerAcknowledged=g::Msg<144,u64>;
type RxWork<P>=g::Roll<g::Route<g::Seq<g::Send<TLS_RX,RX,<P as ReceivePhase>::Need>,g::Seq<g::Send<RX,TLS_RX,<P as ReceivePhase>::Input>,g::Seq<g::Resolve<g::Route<g::Send<TLS_RX,RX,<P as ReceivePhase>::Accepted>,g::Send<TLS_RX,RX,<P as ReceivePhase>::Rejected>>,CRYPTO_RESULT>,g::Send<RX,TLS_RX,<P as ReceivePhase>::Taken>>>>,g::Send<TLS_RX,RX,<P as ReceivePhase>::Boundary>>>;
fn rx_work<P:ReceivePhase>()->g::Program<RxWork<P>>{g::route(g::seq(g::send::<TLS_RX,RX,P::Need>(),g::seq(g::send::<RX,TLS_RX,P::Input>(),g::seq(g::route(g::send::<TLS_RX,RX,P::Accepted>(),g::send::<TLS_RX,RX,P::Rejected>()).resolve::<CRYPTO_RESULT>(),g::send::<RX,TLS_RX,P::Taken>()))),g::send::<TLS_RX,RX,P::Boundary>()).roll()}
type Publish<P>=g::Seq<g::Send<TX_WIRE,UDP,<P as Publication>::Datagram>,g::Seq<g::Resolve<g::Route<g::Send<UDP,TX_WIRE,<P as Publication>::Accepted>,g::Send<UDP,TX_WIRE,<P as Publication>::Rejected>>,ADAPTER_RESULT>,g::Send<TX_WIRE,UDP,<P as Publication>::Settled>>>;
fn publication<P:Publication>()->g::Program<Publish<P>>{g::seq(g::send::<TX_WIRE,UDP,P::Datagram>(),g::seq(g::route(g::send::<UDP,TX_WIRE,P::Accepted>(),g::send::<UDP,TX_WIRE,P::Rejected>()).resolve::<ADAPTER_RESULT>(),g::send::<TX_WIRE,UDP,P::Settled>()))}
type TxResponse<P>=g::Route<g::Seq<g::Send<TLS_TX,TX,<P as TransmitPhase>::Flight>,g::Send<TX,TLS_TX,<P as TransmitPhase>::Taken>>,g::Route<g::Seq<g::Send<TLS_TX,TX,<P as TransmitPhase>::Idle>,g::Send<TX,TLS_TX,<P as TransmitPhase>::Taken>>,g::Send<TLS_TX,TX,<P as TransmitPhase>::Boundary>>>;
type SourceWork<P>=g::Roll<g::Seq<g::Send<TX,TLS_TX,<P as TransmitPhase>::Request>,TxResponse<P>>>;
type WireWork<P>=g::Roll<g::Route<Publish<<P as TransmitPhase>::Data>,g::Route<Publish<<P as TransmitPhase>::Ack>,g::Route<Publish<<P as TransmitPhase>::Probe>,g::Seq<g::Send<TX_WIRE,UDP,<P as TransmitPhase>::WireBoundary>,g::Send<UDP,TX_WIRE,<P as TransmitPhase>::WireBoundarySeen>>>>>>;
type TxWork<P>=g::Seq<g::Par<SourceWork<P>,WireWork<P>>,g::Send<TX,TLS_TX,<P as TransmitPhase>::PhaseSettled>>;
fn tx_work<P:TransmitPhase>()->g::Program<TxWork<P>>{
 let source=g::seq(g::send::<TX,TLS_TX,P::Request>(),g::route(g::seq(g::send::<TLS_TX,TX,P::Flight>(),g::send::<TX,TLS_TX,P::Taken>()),g::route(g::seq(g::send::<TLS_TX,TX,P::Idle>(),g::send::<TX,TLS_TX,P::Taken>()),g::send::<TLS_TX,TX,P::Boundary>()))).roll();
 let wire=g::route(publication::<P::Data>(),g::route(publication::<P::Ack>(),g::route(publication::<P::Probe>(),g::seq(g::send::<TX_WIRE,UDP,P::WireBoundary>(),g::send::<UDP,TX_WIRE,P::WireBoundarySeen>())))).roll();
 g::seq(g::par(source,wire),g::send::<TX,TLS_TX,P::PhaseSettled>())
}

/// Actual key-space retirement is independent of TLS flight transport. The
/// configured producer can only obtain its affine event from accepted Handshake
/// publication (client) or authenticated Handshake receipt (server).
pub const INITIAL_EVENT: u8 = 18;
pub const INITIAL_OWNER: u8 = 19;
pub type ClientInitialRetire = g::Msg<145, u64>;
pub type ServerInitialRetire = g::Msg<146, u64>;
pub type InitialRetired = g::Msg<147, u64>;
pub type InitialRetirementFlow = g::Seq<
    g::Route<g::Send<INITIAL_EVENT, INITIAL_OWNER, ClientInitialRetire>,
             g::Send<INITIAL_EVENT, INITIAL_OWNER, ServerInitialRetire>>,
    g::Send<INITIAL_OWNER, INITIAL_EVENT, InitialRetired>>;
pub type ReceiveTail = g::Seq<RxWork<FinishedReceive>,
    g::Seq<g::Send<RX, TLS_RX, ReceiveComplete>, g::Send<TLS_RX, RX, ReceiveContinuation>>>;
pub type ReceiveFlow = g::Seq<RxWork<InitialReceive>,
    g::Seq<g::Send<TLS_RX, RX, ReadHandshake>,
    g::Seq<RxWork<HandshakeReceive>,
    g::Seq<g::Send<TLS_RX, RX, ReadApplication>, ReceiveTail>>>>;
pub type DrainFlow = g::Roll<g::Route<Publish<DrainAck>,
    g::Route<Publish<DrainProbe>, g::Send<TX_WIRE, UDP, RecoveryDrained>>>>;
pub type CompleteFlow = g::Seq<g::Send<TX, TLS_TX, TransmitComplete>,
    g::Seq<g::Send<TLS_TX, TX, TransmitContinuation>,
    g::Seq<g::Send<TX_WIRE, UDP, AdapterComplete>, g::Send<UDP, TX_WIRE, AdapterRetired>>>>;
pub type TransmitFlow = g::Seq<TxWork<InitialTransmit>,
    g::Seq<g::Send<TLS_TX, TX, WriteHandshake>,
    g::Seq<TxWork<HandshakeTransmit>,
    g::Seq<g::Send<TLS_TX, TX, WriteApplication>,
    g::Seq<TxWork<ApplicationTransmit>, g::Seq<DrainFlow, CompleteFlow>>>>>>;
pub type TimerFlow = g::Roll<g::Route<
    g::Seq<g::Send<TIMER, TIMER_TX, TimerExpired>, g::Send<TIMER_TX, TIMER, TimerTaken>>,
    g::Seq<g::Send<TIMER, TIMER_TX, TimerRetired>, g::Send<TIMER_TX, TIMER, TimerAcknowledged>>>>;
pub type Flow = g::Par<ReceiveFlow,
    g::Par<TransmitFlow, g::Par<TimerFlow, InitialRetirementFlow>>>;

pub fn choreography() -> g::Program<Flow> {
 let receive=g::seq(rx_work::<InitialReceive>(),g::seq(g::send::<TLS_RX,RX,ReadHandshake>(),g::seq(rx_work::<HandshakeReceive>(),g::seq(g::send::<TLS_RX,RX,ReadApplication>(),g::seq(rx_work::<FinishedReceive>(),g::seq(g::send::<RX,TLS_RX,ReceiveComplete>(),g::send::<TLS_RX,RX,ReceiveContinuation>()))))));
 let drain=g::route(publication::<DrainAck>(),g::route(publication::<DrainProbe>(),g::send::<TX_WIRE,UDP,RecoveryDrained>())).roll();
 let complete=g::seq(g::send::<TX,TLS_TX,TransmitComplete>(),g::seq(g::send::<TLS_TX,TX,TransmitContinuation>(),g::seq(g::send::<TX_WIRE,UDP,AdapterComplete>(),g::send::<UDP,TX_WIRE,AdapterRetired>())));
 let transmit=g::seq(tx_work::<InitialTransmit>(),g::seq(g::send::<TLS_TX,TX,WriteHandshake>(),g::seq(tx_work::<HandshakeTransmit>(),g::seq(g::send::<TLS_TX,TX,WriteApplication>(),g::seq(tx_work::<ApplicationTransmit>(),g::seq(drain,complete))))));
 let timer=g::route(g::seq(g::send::<TIMER,TIMER_TX,TimerExpired>(),g::send::<TIMER_TX,TIMER,TimerTaken>()),g::seq(g::send::<TIMER,TIMER_TX,TimerRetired>(),g::send::<TIMER_TX,TIMER,TimerAcknowledged>())).roll();
 let initial = g::seq(
    g::route(g::send::<INITIAL_EVENT, INITIAL_OWNER, ClientInitialRetire>(),
             g::send::<INITIAL_EVENT, INITIAL_OWNER, ServerInitialRetire>()),
    g::send::<INITIAL_OWNER, INITIAL_EVENT, InitialRetired>());
 g::par(receive, g::par(transmit, g::par(timer, initial)))
}
pub struct Programs {
    pub rx: RoleProgram<RX>, pub tls_rx: RoleProgram<TLS_RX>,
    pub tx: RoleProgram<TX>, pub tls_tx: RoleProgram<TLS_TX>,
    pub udp: RoleProgram<UDP>, pub timer: RoleProgram<TIMER>,
    pub timer_tx: RoleProgram<TIMER_TX>, pub tx_wire: RoleProgram<TX_WIRE>,
    pub initial_event: RoleProgram<INITIAL_EVENT>, pub initial_owner: RoleProgram<INITIAL_OWNER>,
}
pub fn programs() -> Programs {
    let global = choreography();
    Programs { rx: project(&global), tls_rx: project(&global), tx: project(&global),
        tls_tx: project(&global), udp: project(&global), timer: project(&global),
        timer_tx: project(&global), tx_wire: project(&global),
        initial_event: project(&global), initial_owner: project(&global) }
}
