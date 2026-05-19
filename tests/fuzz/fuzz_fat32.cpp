// DuetOS — FAT32 volume parser fuzz harness.
//
// Fat32Probe reads the boot sector (BPB), FSInfo, and walks the
// FAT + root-directory cluster chain off a block device. Those
// bytes come from whatever disk / USB stick is plugged in — the
// same attacker-controlled threat model as the GPT parser. This
// harness serves the libFuzzer input as a read-only disk
// (host_shim/drivers/storage/block.h) and drives the real probe,
// then resets the volume registry via Fat32Shutdown() so each
// input starts from a clean registry (the probe caps at
// kMaxVolumes otherwise and coverage stalls).

#include "fs/fat32.h"

#include <cstddef>
#include <cstdint>

namespace duetos::fuzz
{
const duetos::u8* g_fuzz_block_img = nullptr;
duetos::u64 g_fuzz_block_len = 0;
} // namespace duetos::fuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Need at least a boot sector; cap to keep the FAT / dir
    // cluster walk bounded.
    if (size < 512 || size > (1u << 20))
        return 0;

    duetos::fuzz::g_fuzz_block_img = reinterpret_cast<const duetos::u8*>(data);
    duetos::fuzz::g_fuzz_block_len = static_cast<duetos::u64>(size);

    duetos::u32 idx = 0;
    (void)duetos::fs::fat32::Fat32Probe(0, &idx);
    (void)duetos::fs::fat32::Fat32Shutdown();

    duetos::fuzz::g_fuzz_block_img = nullptr;
    duetos::fuzz::g_fuzz_block_len = 0;
    return 0;
}
