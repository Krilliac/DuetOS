#include "arch/x86_64/lapic.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/msr_safe.h"
#include "arch/x86_64/serial.h"
#include "cpu/percpu.h"

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
constexpr u64 kApicBaseExtd = 1ULL << 10;                // x2APIC mode (Intel SDM Vol 3 §10.12.2)
constexpr u64 kApicBaseAddrMask = 0x000FFFFFFFFFF000ULL; // bits 12..51

constexpr u32 kSvrSoftwareEnable = 1U << 8;

constexpr u8 kSpuriousVector = 0xFF;

// ICR offsets (xAPIC MMIO) and the single x2APIC ICR MSR.
constexpr u64 kLapicRegIcrLow = 0x300;
constexpr u64 kLapicRegIcrHigh = 0x310;
constexpr u32 kX2ApicIcrMsr = 0x830;
constexpr u32 kIcrDeliveryPending = 1U << 12; // xAPIC delivery-status bit

constinit volatile u32* g_lapic_mmio = nullptr;
// false = xAPIC (MMIO), true = x2APIC (MSR). Set once in LapicInit
// before any LapicRead/Write/SendIcr; read-only thereafter.
constinit bool g_x2apic = false;
// Usable flag, mode-independent (g_lapic_mmio is always null in
// x2APIC, so the old "mmio != null" readiness test would lie).
constinit bool g_lapic_ready = false;

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
    if (g_x2apic)
    {
        // x2APIC: register N lives at MSR 0x800 + (offset >> 4).
        // Holds for every register the kernel reads (ID, version,
        // timer count, ESR). ICR never comes here — see LapicSendIcr.
        return static_cast<u32>(ReadMsr(0x800u + static_cast<u32>(reg_offset >> 4)) & 0xFFFFFFFFu);
    }
    return g_lapic_mmio[reg_offset / sizeof(u32)];
}

bool LapicIsReady()
{
    return g_lapic_ready;
}

bool LapicIsX2apic()
{
    return g_x2apic;
}

void LapicWrite(u64 reg_offset, u32 value)
{
    if (g_x2apic)
    {
        WriteMsr(0x800u + static_cast<u32>(reg_offset >> 4), static_cast<u64>(value));
        return;
    }
    g_lapic_mmio[reg_offset / sizeof(u32)] = value;
}

void LapicEoi()
{
    LapicWrite(kLapicRegEoi, 0);
}

void LapicSendIcr(u32 dest, u32 icr_low)
{
    if (g_x2apic)
    {
        // One 64-bit write: high half = 32-bit destination, low
        // half = the command. No delivery-status bit in x2APIC —
        // the write is self-completing, so there is nothing to
        // poll.
        //
        // Routed through `WriteMsrSafe` (extable-protected
        // wrmsr) so a KVM/QEMU-side #GP on the ICR MSR doesn't
        // halt the BSP via recursive-fault (PanicBroadcastNmi
        // would otherwise re-trigger the same wrmsr from inside
        // the trap dispatcher — see Design-Decisions
        // "SMP AP IA32_APIC_BASE..." for the residual flake this
        // closes). On fault: IPI is silently lost, klog gets one
        // warn-once line per (msr, value) so a real regression
        // is still visible.
        const u64 value = (static_cast<u64>(dest) << 32) | static_cast<u64>(icr_low);
        if (!arch::WriteMsrSafe(kX2ApicIcrMsr, value))
        {
            arch::SerialWrite("[lapic] x2APIC ICR wrmsr #GP — IPI lost (icr=");
            arch::SerialWriteHex(icr_low);
            arch::SerialWrite(" dest=");
            arch::SerialWriteHex(dest);
            arch::SerialWrite(")\n");
        }
        return;
    }
    // xAPIC: program destination (bits 31:24), then the command,
    // then spin on the delivery-status bit. Bounded + klog-free so
    // the panic / NMI-broadcast callers stay re-entrancy-safe.
    g_lapic_mmio[kLapicRegIcrHigh / sizeof(u32)] = dest << 24;
    g_lapic_mmio[kLapicRegIcrLow / sizeof(u32)] = icr_low;
    for (u64 spin = 0; spin < 1'000'000; ++spin)
    {
        if ((g_lapic_mmio[kLapicRegIcrLow / sizeof(u32)] & kIcrDeliveryPending) == 0)
        {
            return;
        }
        asm volatile("pause" ::: "memory");
    }
}

u32 LapicCurrentId()
{
    const u32 raw = LapicRead(kLapicRegId);
    // xAPIC packs the 8-bit ID into bits 31:24; x2APIC's ID MSR
    // (0x802) is the full 32-bit value with no shift.
    return g_x2apic ? raw : (raw >> 24);
}

void LapicInit()
{
    KLOG_TRACE_SCOPE("arch/lapic", "LapicInit");
    if (!CpuidApicPresent())
    {
        PanicLapic("CPUID reports no on-chip APIC");
    }

    // Read the LAPIC base from MSR. The default is 0xFEE00000 but firmware
    // can relocate it; trust the MSR.
    u64 apic_base_msr = ReadMsr(kIa32ApicBaseMsr);
    const duetos::mm::PhysAddr base_phys = apic_base_msr & kApicBaseAddrMask;

    // x2APIC when the CPU advertises it (CPUID.1:ECX[21]). This is
    // the standard OS choice (Linux/Windows do the same): the MSR
    // interface is faster, needs no MMIO mapping, carries 32-bit
    // APIC IDs, and — critically — is the ONLY mode that works when
    // firmware already locked the CPU into x2APIC (EXTD set), which
    // many server BIOSes do by default. The old code panicked on
    // exactly that configuration; it is now a supported boot path.
    //
    // Entering x2APIC: set EN=1 and EXTD=1. xAPIC->x2APIC is a legal
    // one-step transition (SDM Vol 3 §10.12.1); x2APIC->x2APIC (the
    // firmware-already-enabled case) is idempotent. The reverse
    // transition (the old disable->xAPIC dance) is no longer needed.
    if (arch::CpuHas(arch::kCpuFeatX2Apic))
    {
        WriteMsr(kIa32ApicBaseMsr, apic_base_msr | kApicBaseEnable | kApicBaseExtd);
        g_x2apic = true;
        // No MMIO window in x2APIC mode (it is architecturally
        // undefined); g_lapic_mmio stays null and every access
        // routes through the MSR path in LapicRead/Write/SendIcr.
    }
    else
    {
        // Legacy xAPIC. If firmware somehow left EXTD set without
        // advertising x2APIC in CPUID (not seen in practice — EXTD
        // implies support) we cannot safely MMIO; that contradiction
        // is a genuine hard stop.
        if ((apic_base_msr & kApicBaseExtd) != 0)
        {
            core::PanicWithValue("arch/lapic", "EXTD set but CPUID lacks x2APIC — inconsistent APIC state",
                                 apic_base_msr);
        }
        if ((apic_base_msr & kApicBaseEnable) == 0)
        {
            apic_base_msr |= kApicBaseEnable;
            WriteMsr(kIa32ApicBaseMsr, apic_base_msr);
        }
        // Map the 4 KiB register window with cache-disable. Cached
        // MMIO would turn EOIs into NOPs and timer-init writes into
        // "delivered eventually when the line gets evicted".
        void* mmio = duetos::mm::MapMmio(base_phys, 0x1000);
        if (mmio == nullptr)
        {
            PanicLapic("MapMmio failed for LAPIC window");
        }
        g_lapic_mmio = static_cast<volatile u32*>(mmio);
    }

    // Install the spurious vector handler, then enable the LAPIC by
    // setting the SVR's software-enable bit. Vector goes in the low 8
    // bits; the low 4 bits are hard-wired to 1 on most CPUs, hence the
    // conventional 0xFF. SVR/TPR writes are now mode-aware.
    IdtSetGate(kSpuriousVector, reinterpret_cast<u64>(&isr_spurious));
    g_lapic_ready = true;        // LapicWrite/Read are now safe in either mode
    LapicWrite(kLapicRegTpr, 0); // accept all
    LapicWrite(kLapicRegSvr, kSvrSoftwareEnable | kSpuriousVector);

    core::LogWithValue(core::LogLevel::Info, "arch/lapic", "base_phys", base_phys);
    core::Log(core::LogLevel::Info, "arch/lapic", g_x2apic ? "mode x2apic (MSR)" : "mode xapic (MMIO)");
    core::LogWithValue(core::LogLevel::Info, "arch/lapic", "id", LapicCurrentId());
    core::LogWithValue(core::LogLevel::Info, "arch/lapic", "version", LapicRead(kLapicRegVersion));
}

void ApicModeSelfTest()
{
    const bool cpuid_x2 = arch::CpuHas(arch::kCpuFeatX2Apic);
    const bool mode_x2 = LapicIsX2apic();
    // We enable x2APIC whenever CPUID advertises it, so the two
    // must agree exactly. A divergence means LapicInit's mode
    // selection broke (or CpuInfo wasn't probed first).
    if (cpuid_x2 != mode_x2)
    {
        core::PanicWithValue("arch/lapic", "ApicModeSelfTest: x2APIC CPUID/mode mismatch",
                             (static_cast<u64>(cpuid_x2) << 1) | static_cast<u64>(mode_x2));
    }
    // The mode-normalised ID must match what PerCpu recorded for
    // the CPU we're running on (stamped via LapicCurrentId()).
    cpu::PerCpu* self = cpu::CurrentCpu();
    if (self != nullptr && LapicCurrentId() != self->lapic_id)
    {
        core::PanicWithValue("arch/lapic", "ApicModeSelfTest: LAPIC id round-trip mismatch", LapicCurrentId());
    }
    SerialWrite(mode_x2 ? "[apic-mode-selftest] PASS (x2apic)\n" : "[apic-mode-selftest] PASS (xapic)\n");
}

} // namespace duetos::arch
