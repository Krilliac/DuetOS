// DuetOS — GPT partition-table parser fuzz harness.
//
// GptProbe reads the Protective MBR + primary GPT header + the
// 128×128 partition-entry array off a block device and validates
// two CRC32s before trusting any LBA. Those bytes come from
// whatever disk / USB stick is plugged in — fully attacker-
// controlled. This harness serves the libFuzzer input as a
// read-only disk (host_shim/drivers/storage/block.h) and drives
// the real parser, exercising the header walk, the CRC checks,
// and the partition-entry loop on hostile input.

#include "fs/gpt.h"

#include <cstddef>
#include <cstdint>

namespace duetos::fuzz
{
const duetos::u8* g_fuzz_block_img = nullptr;
duetos::u64 g_fuzz_block_len = 0;
} // namespace duetos::fuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Need at least a sector to look like a disk; cap to keep the
    // 128-entry array walk bounded. The shim reports
    // sector_count = size/512, so a few hundred KiB is plenty to
    // cover the entries array (LBA 2..33) plus slack.
    if (size < 512 || size > (1u << 20))
        return 0;

    duetos::fuzz::g_fuzz_block_img = reinterpret_cast<const duetos::u8*>(data);
    duetos::fuzz::g_fuzz_block_len = static_cast<duetos::u64>(size);

    duetos::u32 idx = 0;
    (void)duetos::fs::gpt::GptProbe(0, &idx);

    duetos::fuzz::g_fuzz_block_img = nullptr;
    duetos::fuzz::g_fuzz_block_len = 0;
    return 0;
}
