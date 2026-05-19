// DuetOS — exFAT volume parser fuzz harness.
//
// ExfatProbe reads the boot sector + root directory off a block
// device; the byte-level parsing (boot sector, geometry, dirent
// sets, FAT chain) lives in the memory-safe `duetos_exfat` Rust
// crate, fuzzed here for free alongside the C++ wrapper's scratch
// I/O and Unicode filter. Same read-only-disk shim and
// attacker-controlled threat model as fuzz_gpt / fuzz_fat32.
//
// The registry caps at kMaxVolumes with no public reset, so most
// inputs (which fail the boot-sector parse and never register)
// keep coverage flowing; a run that registers kMaxVolumes valid
// volumes then early-returns is benign for parser-bug discovery.

#include "fs/exfat.h"

#include <cstddef>
#include <cstdint>

namespace duetos::fuzz
{
const duetos::u8* g_fuzz_block_img = nullptr;
duetos::u64 g_fuzz_block_len = 0;
} // namespace duetos::fuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 512 || size > (1u << 20))
        return 0;

    duetos::fuzz::g_fuzz_block_img = reinterpret_cast<const duetos::u8*>(data);
    duetos::fuzz::g_fuzz_block_len = static_cast<duetos::u64>(size);

    (void)duetos::fs::exfat::ExfatProbe(0);

    duetos::fuzz::g_fuzz_block_img = nullptr;
    duetos::fuzz::g_fuzz_block_len = 0;
    return 0;
}
