#include "page.h"

#include "../core/panic.h"

namespace duetos::mm
{

namespace
{

[[noreturn]] void PanicPage(const char* message, u64 value)
{
    core::PanicWithValue("mm/page", message, value);
}

} // namespace

void* PhysToVirt(PhysAddr phys)
{
    if (phys >= kDirectMapBytes)
    {
        PanicPage("PhysToVirt called outside direct map", phys);
    }
    return reinterpret_cast<void*>(static_cast<uptr>(phys) + kKernelVirtualBase);
}

PhysAddr VirtToPhys(const void* virt)
{
    const uptr v = reinterpret_cast<uptr>(virt);
    if (v < kKernelVirtualBase || v >= kKernelVirtualBase + kDirectMapBytes)
    {
        PanicPage("VirtToPhys called outside direct map", v);
    }
    return static_cast<PhysAddr>(v - kKernelVirtualBase);
}

} // namespace duetos::mm
