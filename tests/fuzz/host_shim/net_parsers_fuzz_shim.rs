// Host fuzz support shim for the `duetos_net_parsers` Rust crate.
// Same role as the other *_fuzz_shim.rs wrappers: the crate is
// `#![no_std]` with no `#[panic_handler]`, so this tiny
// panic=abort staticlib wrapper supplies an aborting handler and
// re-exports the crate's C ABI so the `#[no_mangle] extern "C"`
// packet-option/name parsers (DHCP option find, DNS name skip,
// …) survive into the archive the C++ net fuzzer links. A
// Rust-side panic (a bounds/overflow the parser failed to guard)
// aborts so libFuzzer records a crash.
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

pub use duetos_net_parsers::*;
