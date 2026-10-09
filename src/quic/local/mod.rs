//! Direct receive, transmit and physical-publication role continuations.
use super::global as p;
use super::wire::{PlainPacket, WriteKeys};
use super::*;
use crate::{
    crypto::directional::ApplicationKeyScope,
    quic::kernel::packet::{self, Frame, FrameIter, Header, LongType, PacketIter, ParseLimits},
    quic::kernel::parameters::{Parameters, Peer},
};
use core::{future::Future, pin::pin};
use hibana::g::Message;

mod publication;
mod receive;
mod sealing;
mod transmit;
pub(super) use publication::publish;
pub(super) use receive::receive;
pub(super) use sealing::prepare;
use sealing::{RecoveryPacket, prepare_recovery_packet};
pub(super) use transmit::transmit;
