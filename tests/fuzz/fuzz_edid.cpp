// DuetOS — VESA E-EDID base-block parser fuzz harness.
//
// EdidParseBaseBlock walks a 128-byte buffer the kernel
// receives from a per-vendor GPU driver (DDC/I2C transport) —
// fully attacker-controlled when the monitor is hostile. The
// parser is "pure compute, allocation-free, no IRQ" per
// edid.h, so no shimming beyond the existing host_shim/log/klog
// no-ops is needed. ASan catches any OOB read past `length`;
// UBSan catches sign/overflow bugs in the DTD pixel-clock and
// refresh-rate math.

#include "drivers/gpu/edid.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Accept any length — the parser must handle short inputs
    // (return an error) without OOB-reading past the bound.
    if (size > 4096)
        return 0;

    (void)duetos::drivers::gpu::EdidParseBaseBlock(reinterpret_cast<const duetos::u8*>(data),
                                                   static_cast<duetos::u64>(size));
    return 0;
}
