// rust_eh_personality stub for the duetos_vt staticlib. Same
// rationale as host_shim/usbhid_stubs.cpp — the staticlib pulls
// in `core` objects that reference the unwind personality even
// though we're panic=abort.

extern "C" void rust_eh_personality() {}
