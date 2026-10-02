//! Target-layout measurement, not bootable firmware or a peak-stack measurement.
#![no_std]
#![no_main]
use core::{mem::size_of,panic::PanicInfo};
use hibana::runtime::{SessionKitStorage,program::RoleProgram};
use hibana_quic::{bounded_tls::BoundedTls,carrier::{CarrierStorage,LocalCarrier},streams::{StreamSlot,SendChunk,PacketReference},transport_endpoint::TransportEndpoint};

#[used]
#[unsafe(no_mangle)]
pub static HIBANA_QUIC_TARGET_BUDGET:[u32;16]=[
    0x48425131,
    size_of::<TransportEndpoint<'static,'static,BoundedTls<'static,'static>,1024,1024>>()as u32,
    size_of::<SessionKitStorage<'static,LocalCarrier<'static,8,16,{hibana_quic::protocol::SERVICE_PORTS}>>>()as u32,
    size_of::<CarrierStorage<8,16,{hibana_quic::protocol::SERVICE_PORTS}>>()as u32,
    32768,
    3*16384+2048,
    2*8192+16384,
    2*1024+2048,
    size_of::<[StreamSlot<1024>;1]>()as u32,
    size_of::<[SendChunk<1024>;2]>()as u32,
    size_of::<[PacketReference;16]>()as u32,
    (size_of::<RoleProgram<0>>()+size_of::<RoleProgram<1>>()+size_of::<RoleProgram<2>>()+size_of::<RoleProgram<3>>()+size_of::<RoleProgram<4>>()+size_of::<RoleProgram<5>>())as u32,
    3*1232,
    1024,
    size_of::<hibana_quic::bounded_tls::SigningKey>()as u32,
    264*1024,
];
#[unsafe(no_mangle)]
pub extern "C" fn _start()->!{core::hint::black_box(&HIBANA_QUIC_TARGET_BUDGET);loop{core::hint::spin_loop()}}
#[panic_handler]
fn panic(_: &PanicInfo<'_>)->!{loop{core::hint::spin_loop()}}
