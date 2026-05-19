// DuetOS — NTFS volume parser fuzz harness.
//
// NtfsProbe reads the boot sector + walks the MFT off a block
// device; the byte-level parsing (boot sector, MFT record header,
// $FILE_NAME attribute walk, USA fixups) lives in the memory-safe
// `duetos_ntfs` Rust crate, fuzzed here alongside the C++
// wrapper's scratch I/O and Unicode filter. Same read-only-disk
// shim and attacker-controlled threat model as fuzz_gpt /
// fuzz_fat32 / fuzz_exfat.

#include "fs/ntfs.h"

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

    (void)duetos::fs::ntfs::NtfsProbe(0);

    duetos::fuzz::g_fuzz_block_img = nullptr;
    duetos::fuzz::g_fuzz_block_len = 0;
    return 0;
}
