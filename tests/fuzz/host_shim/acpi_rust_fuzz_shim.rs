// Host fuzz support shim for the `duetos_acpi_rust` crate.
// Same role as exfat_fuzz_shim.rs / ntfs_fuzz_shim.rs: the crate
// is `#![no_std]` and ships no `#[panic_handler]` (the kernel
// provides one), so this tiny panic=abort staticlib wrapper
// supplies an aborting handler and re-exports the crate's C ABI so
// the `#[no_mangle] extern "C"` ACPI table parsers survive into the
// archive the C++ fuzzer links against. A Rust-side panic (a
// bounds/overflow the RSDP / header / MADT / FADT / MCFG / HPET /
// SRAT walker failed to guard) aborts the process so libFuzzer
// records a crash.
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

pub use duetos_acpi::*;
