// DuetOS — AMD GFX9+ microcode-image parser fuzz harness.
//
// `AmdGfxFwParse` walks a 44-byte gfx_firmware_header_v1_0 +
// jump-table + microcode payload from an on-disk `*.bin`
// blob distributed by AMD's `linux-firmware` tree. Attacker
// controllable when the install media or the firmware
// staging path is hostile. Pure compute parser; no shimming
// beyond the host_shim/log/klog no-ops.

#include "drivers/gpu/amd_gfx_fw.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;
    duetos::drivers::gpu::amd::AmdGfxFwParsed parsed{};
    (void)duetos::drivers::gpu::amd::AmdGfxFwParse(reinterpret_cast<const duetos::u8*>(data),
                                                  static_cast<duetos::u32>(size), &parsed);
    return 0;
}
