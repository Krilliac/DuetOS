// DuetOS — ext4 volume parser fuzz harness.
//
// Ext4Probe reads the superblock + group descriptor + root inode
// + extent tree + root directory off a block device; the
// byte-level parsing lives in the memory-safe `duetos_ext4` Rust
// crate, fuzzed here alongside the C++ wrapper's block I/O and
// extent-walk arithmetic. Same read-only-disk shim and
// attacker-controlled threat model as the other FS harnesses
// (ext4 read-only is DuetOS's Linux-data-partition interop tier).

#include "fs/ext4.h"

#include <cstddef>
#include <cstdint>

namespace duetos::fuzz
{
const duetos::u8* g_fuzz_block_img = nullptr;
duetos::u64 g_fuzz_block_len = 0;
} // namespace duetos::fuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1536 || size > (1u << 20)) // need >= SB offset (1024) + 512
        return 0;

    duetos::fuzz::g_fuzz_block_img = reinterpret_cast<const duetos::u8*>(data);
    duetos::fuzz::g_fuzz_block_len = static_cast<duetos::u64>(size);

    (void)duetos::fs::ext4::Ext4Probe(0);

    duetos::fuzz::g_fuzz_block_img = nullptr;
    duetos::fuzz::g_fuzz_block_len = 0;
    return 0;
}
