// Host fuzz support shim for the `duetos_exec_meta` Rust crate.
//
// The crate is `#![no_std]` and ships no `#[panic_handler]` — in
// the kernel build the kernel provides one. The host fuzzer has
// no kernel, so this tiny staticlib wrapper supplies an aborting
// panic handler and force-re-exports the crate's C ABI so the
// `#[no_mangle] extern "C"` validators survive into the archive
// the C++ fuzzer links against. A Rust-side panic (a `checked_*`
// overflow the validator failed to guard, an indexing bug) aborts
// the process so libFuzzer records it as a crash — exactly the
// signal we want from fuzzing the pre-mapping gate.

#![no_std]
#![crate_type = "staticlib"]

use core::panic::PanicInfo;

extern "C" {
    fn abort() -> !;
}

#[panic_handler]
fn fuzz_panic(_info: &PanicInfo) -> ! {
    // libc abort(); libFuzzer/ASan turn the SIGABRT into a
    // recorded crash with a reproducer.
    unsafe { abort() }
}

pub use duetos_exec_meta::*;
