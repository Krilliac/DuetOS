use core::panic::PanicInfo;

extern "C"
{
    fn duetos_rust_panic(msg: *const u8, msg_len: usize) -> !;
}

#[panic_handler]
fn on_panic(info: &PanicInfo) -> !
{
    let msg = info.message().as_str().unwrap_or("kernel rust panic");
    // SAFETY: The C++ kernel owns this non-returning panic bridge and accepts a
    // Rust string-slice `(ptr, len)` without requiring a NUL terminator.
    unsafe { duetos_rust_panic(msg.as_ptr(), msg.len()) }
}
