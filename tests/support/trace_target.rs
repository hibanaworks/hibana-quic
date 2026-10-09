//! Writer-only allocator-free thumb link smoke, not bootable firmware.
#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![allow(dead_code)]

#[path = "../../src/runtime/trace.rs"]
mod trace;
mod trace_cases;

// Rust's symbol export attribute is the only unsafe declaration here. There
// are no memory operations or allocator implementations in this test image.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    trace_cases::exercise();
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
