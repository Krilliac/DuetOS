#include "page.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"

namespace customos::mm
{

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

[[noreturn]] void PanicPage(const char* message, u64 value)
{
    SerialWrite("\n[panic] mm/page: ");
    SerialWrite(message);
    SerialWrite(" value=");
    SerialWriteHex(value);
    SerialWrite("\n");
    Halt();
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

} // namespace customos::mm
