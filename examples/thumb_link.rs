//! Link smoke for implemented bounded kernels, NOT a bootable Pico QUIC firmware.
#![no_std]
#![no_main]
#[path = "support/component_smoke.rs"]
mod component_smoke;
use core::panic::PanicInfo;
use hibana_quic::{
    flow::{ConnectionReceive, StreamReceive},
    handshake::CryptoBuffer,
    packet::decode_varint,
};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    component_smoke::exercise();
    let mut data = [0_u8; 64];
    let mut bitmap = [0_u8; 64];
    let mut crypto = CryptoBuffer::new(&mut data, &mut bitmap).unwrap();
    let payload = core::hint::black_box(b"\x01\x00\x00\x00");
    core::hint::black_box(crypto.insert(0, payload)).unwrap();
    core::hint::black_box(crypto.ready());
    let mut conn = ConnectionReceive::new(64).unwrap();
    let mut stream = StreamReceive::new(64).unwrap();
    core::hint::black_box(stream.on_data(&mut conn, 0, 4, false)).unwrap();
    core::hint::black_box(decode_varint(payload)).unwrap();
    loop {
        core::hint::spin_loop();
    }
}
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
