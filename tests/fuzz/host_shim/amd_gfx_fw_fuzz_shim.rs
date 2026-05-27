// Host fuzz support shim for duetos_amd_gfx_fw.
// NOTE: this is Rust, not C++ — never run clang-format on it.

#![no_std]
#![crate_type = "staticlib"]

use core::panic::PanicInfo;

extern "C" {
    fn abort() -> !;
}

#[panic_handler]
fn fuzz_panic(_info: &PanicInfo) -> ! {
    unsafe { abort() }
}

pub use duetos_amd_gfx_fw::*;
