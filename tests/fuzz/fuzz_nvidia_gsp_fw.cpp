// DuetOS — NVIDIA GSP firmware-image parser fuzz harness.
//
// `NvidiaGspFwParse` walks a 24-byte container header + a
// per-arch inner descriptor + an ELF64 RISC-V payload pulled
// straight from an on-disk `gsp_*.bin` blob. Container layout
// is from NVIDIA's open-gpu-kernel-modules — attacker
// controllable when the install media or the firmware staging
// path is hostile. The parser is pure compute (no allocation,
// no IRQ, no DMA), so no shimming beyond the existing
// host_shim/log/klog no-ops is needed.

#include "drivers/gpu/nvidia_gsp_fw.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;
    duetos::drivers::gpu::nvidia::NvidiaGspFwParsed parsed{};
    (void)duetos::drivers::gpu::nvidia::NvidiaGspFwParse(reinterpret_cast<const duetos::u8*>(data),
                                                        static_cast<duetos::u32>(size), &parsed);
    return 0;
}
