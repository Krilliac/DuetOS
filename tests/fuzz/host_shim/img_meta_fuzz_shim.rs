// Host fuzz support shim for the `duetos_img_meta` Rust crate.
// Same role as exec_meta_fuzz_shim.rs / exfat_fuzz_shim.rs: the
// crate is `#![no_std]` and ships no `#[panic_handler]` (the
// kernel provides one), so this tiny panic=abort staticlib
// wrapper supplies an aborting handler and re-exports the crate's
// C ABI so the `#[no_mangle] extern "C"` PNG/BMP/TGA/JPEG header
// validators survive into the archive the C++ image fuzzers link
// against. A Rust-side panic (a bounds/overflow the header walker
// failed to guard) aborts the process so libFuzzer records a
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

pub use duetos_img_meta::*;
