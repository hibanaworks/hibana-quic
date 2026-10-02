//! Compiler-known storage of the partial async Initial-role integration.
//!
//! This is a layout probe, never bootable firmware or a peak-stack measurement.
//! Function-item inference measures opaque futures without constructing or
//! polling them. The selected owner profile deliberately reuses the capacities
//! of `thumb_budget`, then accounts for the additional Initial-role session.
//! Actual application owner futures can be substantially larger than these
//! borrowed I/O futures, especially when moved through nested owning joins.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::mem::{align_of, size_of};
use hibana::{
    Endpoint,
    runtime::{SessionKitStorage, program::RoleProgram},
};
use hibana_quic::{
    bounded_tls::BoundedTls,
    carrier::{CarrierStorage, LocalCarrier},
    crypto::PacketKey,
    handshake_endpoint::{HandshakeEndpoint, Transmit},
    mailbox::{Mailbox, Receiver, Sender},
    roles::packet_protection::{self, Command, Exchange, Reply},
    runtime::{self, TaskSet},
    streams::{PacketReference, SendChunk, StreamSlot},
    transport_endpoint::TransportEndpoint,
};

type KeyCommand = Command<1536>;
type KeyReply = Reply<1536>;
type KeyReceiver = Receiver<'static, 'static, KeyCommand, 1>;
type KeySender = Sender<'static, 'static, KeyReply, 1>;
type Engine = HandshakeEndpoint<'static, 'static, BoundedTls<'static, 'static>>;
type Transport = TransportEndpoint<'static, 'static, BoundedTls<'static, 'static>, 1024, 1024>;

// A function item's FnOnce output identifies its opaque future. The function
// and its arguments are never invoked/created, even during const evaluation.
macro_rules! future_size {
    (($($argument:ty),* $(,)?) => $function:expr) => {{
        const fn output_size<F, R>(_: &F) -> usize
        where F: FnOnce($($argument),*) -> R,
        { size_of::<R>() }
        output_size(&$function)
    }};
}

const fn key_future_metrics<F, R, G, S, J, T>(_: &F, _: &G, _: &J) -> [u32; 4]
where
    F: FnOnce(
        &'static mut Endpoint<'static, 16>,
        &'static mut Endpoint<'static, 17>,
        u64,
        PacketKey,
        KeyReceiver,
        KeySender,
        &'static mut Exchange<1536>,
    ) -> R,
    G: FnOnce(
        &'static mut Endpoint<'static, 18>,
        &'static mut Endpoint<'static, 19>,
        u64,
        PacketKey,
        KeyReceiver,
        KeySender,
        &'static mut Exchange<1536>,
    ) -> S,
    J: FnOnce(R, S) -> T,
{
    [
        size_of::<R>() as u32,
        size_of::<S>() as u32,
        align_of::<R>() as u32,
        size_of::<T>() as u32,
    ]
}

const KEY: [u32; 4] = key_future_metrics(
    &packet_protection::run_borrowed::<16, 17, 1536, 1, 1>,
    &packet_protection::run_borrowed::<18, 19, 1536, 1, 1>,
    &runtime::join2::<_, _, packet_protection::Error>,
);

/// Schema 1. Names, selected-capacity assumptions and disjoint subtotal groups
/// are defined in `scripts/read_async_storage_budget.py`.
#[used]
#[unsafe(no_mangle)]
pub static HIBANA_QUIC_ASYNC_STORAGE_BUDGET: [u32; 46] = [
    0x48415331,
    size_of::<Transport>() as u32,
    size_of::<SessionKitStorage<'static, LocalCarrier<'static, 8, 16, 48>>>() as u32,
    size_of::<CarrierStorage<8, 16, 48>>() as u32,
    hibana_quic::protocol::SERVICE_SLAB_BYTES as u32,
    3 * 16384 + 2048,
    2 * 8192 + 16384,
    2 * 1024 + 2048,
    size_of::<[StreamSlot<1024>; 1]>() as u32,
    size_of::<[SendChunk<1024>; 2]>() as u32,
    size_of::<[PacketReference; 16]>() as u32,
    (size_of::<RoleProgram<0>>()
        + size_of::<RoleProgram<1>>()
        + size_of::<RoleProgram<2>>()
        + size_of::<RoleProgram<3>>()
        + size_of::<RoleProgram<4>>()
        + size_of::<RoleProgram<5>>()) as u32,
    3 * 1536,
    1024,
    size_of::<hibana_quic::bounded_tls::SigningKey>() as u32,
    size_of::<[hibana_quic::early_send::RequestSlot<1024>; 1]>() as u32,
    size_of::<[hibana_quic::early_data::QuarantineSlot<1024>; 1]>() as u32,
    size_of::<[hibana_quic::early_control::Slot<128>; 4]>() as u32,
    size_of::<[hibana_quic::path::PathSlot<1, 3>; 2]>() as u32,
    size_of::<[hibana_quic::connection_id::LocalCidSlot; 8]>() as u32,
    size_of::<[hibana_quic::connection_id::PeerCidSlot<2>; 16]>() as u32,
    2048,
    size_of::<SessionKitStorage<'static, LocalCarrier<'static, 1, 16, 32>>>() as u32,
    size_of::<CarrierStorage<1, 16, 32>>() as u32,
    32768,
    (size_of::<Endpoint<'static, 16>>()
        + size_of::<Endpoint<'static, 17>>()
        + size_of::<Endpoint<'static, 18>>()
        + size_of::<Endpoint<'static, 19>>()) as u32,
    (size_of::<RoleProgram<16>>()
        + size_of::<RoleProgram<17>>()
        + size_of::<RoleProgram<18>>()
        + size_of::<RoleProgram<19>>()) as u32,
    (2 * size_of::<Mailbox<'static, KeyCommand, 1>>()
        + 2 * size_of::<Mailbox<'static, KeyReply, 1>>()) as u32,
    (2 * size_of::<[Option<KeyCommand>; 1]>() + 2 * size_of::<[Option<KeyReply>; 1]>()) as u32,
    (2 * size_of::<Exchange<1536>>()) as u32,
    size_of::<TaskSet<'static, packet_protection::Error, 3>>() as u32,
    KEY[0],
    KEY[1],
    KEY[2],
    KEY[3],
    future_size!((&'static mut Engine, &'static [u8], &'static mut [u8])
        => Engine::receive) as u32,
    future_size!((&'static mut Engine, &'static mut [u8]) => Engine::transmit) as u32,
    future_size!((&'static mut Engine, Transmit, bool, u64) => Engine::adapter_result) as u32,
    future_size!((&'static mut Transport, &'static [u8], &'static mut [u8])
        => Transport::receive) as u32,
    future_size!((&'static mut Transport, &'static mut [u8]) => Transport::transmit) as u32,
    future_size!((&'static mut Transport, Transmit, bool, u64)
        => Transport::adapter_result) as u32,
    size_of::<PacketKey>() as u32,
    size_of::<KeyCommand>() as u32,
    size_of::<KeyReply>() as u32,
    size_of::<Engine>() as u32,
    264 * 1024,
];

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::hint::black_box(&HIBANA_QUIC_ASYNC_STORAGE_BUDGET);
    loop {
        core::hint::spin_loop()
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop()
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    println!("{:?}", HIBANA_QUIC_ASYNC_STORAGE_BUDGET);
}
