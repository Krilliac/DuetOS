#include "arch/x86_64/lapic.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/serial.h"

#include "log/klog.h"
#include "core/panic.h"
#include "mm/paging.h"

// Defined in exceptions.S — the dedicated stub for the LAPIC spurious
// vector (0xFF). Lives outside isr_stub_table because a 256-entry table
// would be wasted on a single extra slot.
extern "C" void isr_spurious();

namespace duetos::arch
{

namespace
{

constexpr u32 kIa32ApicBaseMsr = 0x1B;
constexpr u64 kApicBaseEnable = 1ULL << 11;
constexpr u64 kApicBaseAddrMask = 0x000FFFFFFFFFF000ULL; // bits 12..51

constexpr u32 kSvrSoftwareEnable = 1U << 8;

constexpr u8 kSpuriousVector = 0xFF;

constinit volatile u32* g_lapic_mmio = nullptr;

// MSR helpers live in `arch/x86_64/cpu.h` now (same namespace);
// the local copies that used to sit here would shadow-collide
// with the canonical ones once both are visible at this scope.

// CPUID leaf 1, EDX bit 9 = APIC-on-chip.
bool CpuidApicPresent()
{
    u32 eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    return (edx & (1U << 9)) != 0;
}

[[noreturn]] void PanicLapic(const char* message)
{
    core::Panic("arch/lapic", message);
}

} // namespace

u32 LapicRead(u64 reg_offset)
{
    return g_lapic_mmio[reg_offset / sizeof(u32)];
}

bool LapicIsReady()
{
    return g_lapic_mmio != nullptr;
}

void LapicWrite(u64 reg_offset, u32 value)
{
    g_lapic_mmio[reg_offset / sizeof(u32)] = value;
}

void LapicEoi()
{
    LapicWrite(kLapicRegEoi, 0);
}

void LapicInit()
{
    KLOG_TRACE_SCOPE("arch/lapic", "LapicInit");
    if (!CpuidApicPresent())
    {
        PanicLapic("CPUID reports no on-chip APIC (impossible on x86_64?)");
    }

    // Read the LAPIC base from MSR. The default is 0xFEE00000 but firmware
    // can relocate it; trust the MSR.
    u64 apic_base_msr = ReadMsr(kIa32ApicBaseMsr);
    const duetos::mm::PhysAddr base_phys = apic_base_msr & kApicBaseAddrMask;

    // Set the global enable bit (writing the MSR back also locks-in any
    // hardware-default settings the firmware may have left clear).
    if ((apic_base_msr & kApicBaseEnable) == 0)
    {
        apic_base_msr |= kApicBaseEnable;
        WriteMsr(kIa32ApicBaseMsr, apic_base_msr);
    }

    // Map the 4 KiB register window with cache-disable. Cached MMIO would
    // turn EOIs into NOPs and timer-init writes into "delivered eventually
    // when the line gets evicted" — i.e. nothing would work.
    void* mmio = duetos::mm::MapMmio(base_phys, 0x1000);
    if (mmio == nullptr)
    {
        PanicLapic("MapMmio failed for LAPIC window");
    }
    g_lapic_mmio = static_cast<volatile u32*>(mmio);

    // Install the spurious vector handler, then enable the LAPIC by
    // setting the SVR's software-enable bit. Vector goes in the low 8
    // bits; the low 4 bits are hard-wired to 1 on most CPUs, hence the
    // conventional 0xFF.
    IdtSetGate(kSpuriousVector, reinterpret_cast<u64>(&isr_spurious));
    LapicWrite(kLapicRegTpr, 0); // accept all
    LapicWrite(kLapicRegSvr, kSvrSoftwareEnable | kSpuriousVector);

    core::LogWithValue(core::LogLevel::Info, "arch/lapic", "base_phys", base_phys);
    core::LogWithValue(core::LogLevel::Info, "arch/lapic", "mmio", reinterpret_cast<u64>(g_lapic_mmio));
    core::LogWithValue(core::LogLevel::Info, "arch/lapic", "id", LapicRead(kLapicRegId));
    core::LogWithValue(core::LogLevel::Info, "arch/lapic", "version", LapicRead(kLapicRegVersion));
}

} // namespace duetos::arch
