// Pure, WHP-free helper: compute framebuffer guest-physical region.
// Split into its own TU so the host unit-test harness can link it
// without pulling in GuestMemory's VirtualAlloc / WHP dependencies.
#include "guest_memory.h"

namespace duetos::vmm
{

bool ComputeFbRegion(uint64_t ramBytes, uint32_t width, uint32_t height,
                     uint64_t& gpa, uint64_t& bytes)
{
    uint64_t rawBytes = uint64_t(width) * height * 4;
    // Round up to a page boundary.
    uint64_t rounded = (rawBytes + 0xFFFu) & ~uint64_t(0xFFF);
    if (rounded == 0 || rounded > ramBytes)
    {
        return false;
    }
    uint64_t base = (ramBytes - rounded) & ~uint64_t(0xFFF);
    if (base == 0)
    {
        return false;
    }
    gpa   = base;
    bytes = rounded;
    return true;
}

} // namespace duetos::vmm
