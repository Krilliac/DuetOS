#include "percpu.h"

#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/serial.h"

namespace customos::cpu
{

namespace
{

constexpr u32 kIa32GsBaseMsr = 0xC0000101u;

// Static BSP struct. Every AP will have its own heap-allocated one.
constinit PerCpu g_bsp_percpu = {
    .cpu_id = 0,
    .lapic_id = 0,
    .current_task = nullptr,
    .current_as = nullptr, // kernel AS = boot PML4, until a process is activated
    .need_resched = false,
    ._pad = {},
};

// One-shot flag so CurrentCpuIdOrBsp can return a sane value before
// PerCpuInitBsp has run. Without it, reading GSBASE would return 0
// and CurrentCpu() would dereference a null pointer.
constinit bool g_bsp_installed = false;

inline void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFF);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

} // namespace

void PerCpuInitBsp()
{
    // Stamp the LAPIC ID from the LAPIC register — the MADT also
    // reports LAPIC IDs, but the register is the authoritative source
    // for the CPU we're actually executing on.
    g_bsp_percpu.lapic_id = static_cast<u32>(arch::LapicRead(arch::kLapicRegId) >> 24);

    WriteMsr(kIa32GsBaseMsr, reinterpret_cast<u64>(&g_bsp_percpu));
    g_bsp_installed = true;

    arch::SerialWrite("[cpu] BSP PerCpu installed: cpu_id=0 lapic_id=");
    arch::SerialWriteHex(g_bsp_percpu.lapic_id);
    arch::SerialWrite(" addr=");
    arch::SerialWriteHex(reinterpret_cast<u64>(&g_bsp_percpu));
    arch::SerialWrite("\n");
}

PerCpu* CurrentCpu()
{
    PerCpu* p;
    // "mov %%gs:0, %0" reads the first qword of the per-CPU region
    // treating it as an offset from GSBASE — but we want the BASE
    // itself. `rdgsbase` is the direct instruction; since we don't
    // gate on CPUID.EBX.FSGSBASE yet, use RDMSR instead.
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000101u));
    p = reinterpret_cast<PerCpu*>((static_cast<u64>(hi) << 32) | lo);
    return p;
}

u32 CurrentCpuIdOrBsp()
{
    if (!g_bsp_installed)
    {
        return 0;
    }
    return CurrentCpu()->cpu_id;
}

} // namespace customos::cpu
