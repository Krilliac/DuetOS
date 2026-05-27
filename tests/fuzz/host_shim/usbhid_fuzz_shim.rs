// Host fuzz support shim for the `usbhid` Rust crate. Mirrors
// the `usbclass_fuzz_shim.rs` pattern — see that file for the
// detailed rationale. A Rust-side panic in the HID report-
// descriptor walker (bad collection nesting, item-prefix size
// overflow, etc.) aborts the process so libFuzzer records a
// crash.
//
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

pub use usbhid::*;
