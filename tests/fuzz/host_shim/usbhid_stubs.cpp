// The duetos `usbhid` Rust staticlib pulls precompiled `core`
// objects that reference the unwind personality even though our
// shim is panic=abort. Nothing ever unwinds here (the panic
// handler calls abort()), so an empty personality satisfies the
// linker. Same pattern as host_shim/pe_stubs.cpp's
// `rust_eh_personality` stub for the exec_meta staticlib.
//
// usbclass doesn't need this because its lib.rs is simpler and
// doesn't pull in the same set of `core` objects — if a future
// usbclass refactor adds a function that lands `core::fmt` or
// `core::panicking` in the rlib, link this TU into fuzz_usbclass
// too.

extern "C" void rust_eh_personality() {}
