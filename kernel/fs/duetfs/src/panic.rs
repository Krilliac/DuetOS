// no_std + staticlib needs a `#[panic_handler]`. The crate is a leaf
// linked into the C++ kernel; on a real panic we call the kernel's
// `duetos_kernel_panic` symbol so the host's klog / probe / serial
// pipeline records the failure with full context. The kernel
// provides this symbol from kernel/core/panic.cpp; the FFI shape is
// frozen in include/duetfs.h alongside the rest of the contract.
//
// `panic = "abort"` in Cargo.toml means we never need an unwinder.
//
// In a `cargo build` outside the kernel link (i.e. when validating
// the crate compiles standalone), the host's panic symbol is
// missing and the link step fails — that's fine, the leaf target
// is meant to be linked into the kernel binary, not run alone. We
// keep this file out of the FFI surface header.

use core::panic::PanicInfo;

extern "C"
{
    fn duetos_rust_panic(msg: *const u8, msg_len: usize) -> !;
}

#[panic_handler]
fn on_panic(info: &PanicInfo) -> !
{
    // Don't bother formatting — `&str` payload is the typical shape
    // for `panic!("literal")`, and v0 has no allocator to format
    // arbitrary args. The kernel's panic prints the call site
    // (return address) anyway.
    let msg = info.message().as_str().unwrap_or("duetfs panic");
    unsafe { duetos_rust_panic(msg.as_ptr(), msg.len()) }
}
