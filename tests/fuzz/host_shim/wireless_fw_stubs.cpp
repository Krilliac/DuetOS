// Each Rust staticlib pulls in `core` objects that reference the
// unwind personality even though we're panic=abort. Empty stub
// satisfies the linker for fuzz_iwl_fw + fuzz_rtl_fw + fuzz_bcm_fw.

extern "C" void rust_eh_personality() {}
