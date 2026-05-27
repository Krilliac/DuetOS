// Host fuzz support shim for the `duetos_vt` Rust crate.
// Same role as the other *_fuzz_shim.rs files: the crate is
// `#![no_std]` and ships no `#[panic_handler]` (the kernel
// provides one), so this tiny panic=abort staticlib wrapper
// supplies an aborting handler and re-exports the crate's C
// ABI so the `#[no_mangle] extern "C"` VT parser entry points
// survive into the archive the C++ fuzzer links against.
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

pub use duetos_vt::*;
