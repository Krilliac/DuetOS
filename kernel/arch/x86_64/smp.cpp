#include "smp.h"

#include "cpu.h"
#include "lapic.h"
#include "serial.h"
#include "timer.h"

#include "../../acpi/acpi.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../cpu/percpu.h"
#include "../../mm/kheap.h"
#include "../../mm/page.h"
#include "../../sched/sched.h"

// Linker-emitted symbols for the trampoline image (see ap_trampoline.S).
// Declared at file scope (outside any namespace) so the linker matches
// the unmangled .S labels; qualified types because `u8` lives inside
// customos::.
extern "C" const customos::u8 ap_trampoline_start[];
extern "C" const customos::u8 ap_trampoline_end[];

namespace customos::arch
{

namespace
{

// Parameter-block offsets — MUST match the `.set OFF_*` values in
// ap_trampoline.S. Changing one without the other wedges the AP into
// reading zero / random parameters.
constexpr u64 kOffOnlineFlag = 0xFD4;
constexpr u64 kOffCpuId = 0xFD8;
constexpr u64 kOffEntry = 0xFE0;
constexpr u64 kOffStack = 0xFE8;
constexpr u64 kOffPml4 = 0xFF0;

constexpr customos::mm::PhysAddr kTrampolinePhys = 0x8000;
constexpr u32 kMaxAps = acpi::kMaxCpus - 1;

// Per-AP persistent state, indexed by cpu_id (1..N). BSP is slot 0
// and uses the static g_bsp_percpu in cpu/percpu.cpp; APs each get a
// heap-allocated PerCpu whose pointer is cached here so the AP's C++
// entry can find its own struct by cpu_id.
constinit cpu::PerCpu* g_ap_percpus[acpi::kMaxCpus] = {};
constinit u64 g_cpus_online = 1; // BSP always counted

// LAPIC ICR low-half fields.
constexpr u64 kLapicRegIcrLow = 0x300;
constexpr u64 kLapicRegIcrHigh = 0x310;

constexpr u32 kIcrDeliveryInit = 5U << 8;
constexpr u32 kIcrDeliveryStartup = 6U << 8;
constexpr u32 kIcrLevelAssert = 1U << 14;
constexpr u32 kIcrDeliveryPending = 1U << 12;

inline void WriteMsrGsBase(u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFF);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(0xC0000101u), "a"(lo), "d"(hi));
}

inline void* TrampVirt()
{
    return mm::PhysToVirt(kTrampolinePhys);
}

inline u64& TrampU64At(u64 offset)
{
    auto* base = static_cast<u8*>(TrampVirt());
    return *reinterpret_cast<u64*>(base + offset);
}

inline u32& TrampU32At(u64 offset)
{
    auto* base = static_cast<u8*>(TrampVirt());
    return *reinterpret_cast<u32*>(base + offset);
}

void WaitForIcrDelivery()
{
    for (u64 spin = 0; spin < 1'000'000; ++spin)
    {
        if ((LapicRead(kLapicRegIcrLow) & kIcrDeliveryPending) == 0)
        {
            return;
        }
        asm volatile("pause" ::: "memory");
    }
    core::Panic("arch/smp", "IPI delivery-status bit stuck");
}

// Busy-spin up to ~200 ms for the AP to flip its online flag.
bool WaitForApOnline()
{
    constexpr u64 kTimeoutTicks = 20; // * 10 ms = 200 ms
    const u64 start = TimerTicks();
    while (TimerTicks() - start < kTimeoutTicks)
    {
        if (TrampU32At(kOffOnlineFlag) != 0)
        {
            return true;
        }
        asm volatile("pause" ::: "memory");
    }
    return false;
}

} // namespace

void SmpSendIpi(u8 target_apic_id, u32 icr_low)
{
    LapicWrite(kLapicRegIcrHigh, static_cast<u32>(target_apic_id) << 24);
    LapicWrite(kLapicRegIcrLow, icr_low);
    WaitForIcrDelivery();
}

u64 SmpCpusOnline()
{
    return g_cpus_online;
}

// ---------------------------------------------------------------------------
// AP kernel entry — called from ap_trampoline.S once long mode is live.
// Signature: void ApEntryFromTrampoline(u32 cpu_id)
//
// The AP enters here on its own 16 KiB stack (top loaded by the
// trampoline from the parameter block). Interrupts are disabled, no
// scheduler on this CPU yet, no LAPIC timer.
//
// v0 scope:
//   1) install per-CPU struct via GSBASE
//   2) bring up the AP's LAPIC (enable MSR + SVR)
//   3) flip the trampoline's online_flag so BSP stops waiting
//   4) hlt forever (scheduler entry is a separate follow-up commit,
//      gated on the runqueue/sleepqueue spinlock work landing fully)
// ---------------------------------------------------------------------------
extern "C" [[noreturn]] void ApEntryFromTrampoline(u32 cpu_id)
{
    cpu::PerCpu* pcpu = g_ap_percpus[cpu_id];
    WriteMsrGsBase(reinterpret_cast<u64>(pcpu));

    // Enable the AP's LAPIC. IA32_APIC_BASE MSR bit 11 is the global
    // enable; the LAPIC MMIO window is already mapped in the shared
    // PML4 (BSP's MapMmio for 0xFEE00000), so LapicRead/Write just
    // works on every CPU.
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0x1Bu));
    const u64 apic_base = (static_cast<u64>(hi) << 32) | lo;
    if ((apic_base & (1ULL << 11)) == 0)
    {
        const u64 enabled = apic_base | (1ULL << 11);
        const u32 elo = static_cast<u32>(enabled & 0xFFFFFFFF);
        const u32 ehi = static_cast<u32>(enabled >> 32);
        asm volatile("wrmsr" : : "c"(0x1Bu), "a"(elo), "d"(ehi));
    }
    LapicWrite(kLapicRegTpr, 0);
    LapicWrite(kLapicRegSvr, (1U << 8) | 0xFF);

    // Signal BSP BEFORE logging — log path races with BSP's serial
    // writes and can delay arbitrarily on contention.
    TrampU32At(kOffOnlineFlag) = 1;

    core::LogWithValue(core::LogLevel::Info, "arch/smp", "AP online cpu_id", static_cast<u64>(cpu_id));

    // Halt forever with IRQs enabled — timer IRQs that land here are
    // harmless noise (no IDT entry for the AP's perspective? actually
    // IDT is shared; any timer IRQ on this core would enter the
    // dispatcher and try to Schedule on a CPU that isn't in the
    // scheduler yet). Keep IF=0 until AP scheduler-join lands.
    for (;;)
    {
        asm volatile("cli; hlt");
    }
}

u64 SmpStartAps()
{
    KASSERT(acpi::CpuCount() > 0, "arch/smp", "MADT reported zero CPUs");

    // Copy the trampoline image into physical 0x8000. Frame allocator
    // has the low 1 MiB permanently reserved, so nobody else owns this
    // memory.
    const u64 tramp_len = static_cast<u64>(ap_trampoline_end - ap_trampoline_start);
    if (tramp_len > 0x1000)
    {
        core::PanicWithValue("arch/smp", "trampoline image larger than 4 KiB", tramp_len);
    }
    auto* dst = static_cast<u8*>(TrampVirt());
    for (u64 i = 0; i < tramp_len; ++i)
    {
        dst[i] = ap_trampoline_start[i];
    }

    // Shared parameters: the PML4 phys + the C++ entry point VA.
    // BSP's CR3 points at the kernel's single PML4; APs share it so
    // every kernel VA maps the same bytes everywhere.
    TrampU64At(kOffPml4) = ReadCr3() & ~0xFFFULL;
    TrampU64At(kOffEntry) = reinterpret_cast<u64>(&ApEntryFromTrampoline);

    const u8 bsp_apic_id = static_cast<u8>(LapicRead(kLapicRegId) >> 24);
    u64 aps_started = 0;

    for (u64 i = 0; i < acpi::CpuCount(); ++i)
    {
        const acpi::LapicRecord& rec = acpi::Lapic(i);
        if (rec.apic_id == bsp_apic_id)
        {
            continue;
        }
        if (!rec.enabled)
        {
            core::LogWithValue(core::LogLevel::Warn, "arch/smp", "skipping disabled AP apic_id",
                               static_cast<u64>(rec.apic_id));
            continue;
        }
        if (aps_started >= kMaxAps)
        {
            core::Log(core::LogLevel::Warn, "arch/smp", "AP slot limit reached; skipping remainder");
            break;
        }

        const u32 cpu_id = static_cast<u32>(aps_started + 1);

        // Allocate per-AP PerCpu struct.
        auto* ap_pcpu = static_cast<cpu::PerCpu*>(mm::KMalloc(sizeof(cpu::PerCpu)));
        if (ap_pcpu == nullptr)
        {
            core::Panic("arch/smp", "KMalloc failed for AP PerCpu");
        }
        ap_pcpu->cpu_id = cpu_id;
        ap_pcpu->lapic_id = rec.apic_id;
        ap_pcpu->current_task = nullptr;
        ap_pcpu->need_resched = false;
        g_ap_percpus[cpu_id] = ap_pcpu;

        // Per-AP 16 KiB stack. The trampoline loads RSP with stack_top
        // (= stack_base + size) so we pass that.
        constexpr u64 kApStackBytes = 16 * 1024;
        auto* stack = static_cast<u8*>(mm::KMalloc(kApStackBytes));
        if (stack == nullptr)
        {
            core::Panic("arch/smp", "KMalloc failed for AP stack");
        }
        TrampU64At(kOffStack) = reinterpret_cast<u64>(stack + kApStackBytes);
        TrampU32At(kOffCpuId) = cpu_id;
        TrampU32At(kOffOnlineFlag) = 0;

        core::LogWithValue(core::LogLevel::Info, "arch/smp", "starting AP apic_id", static_cast<u64>(rec.apic_id));

        // INIT IPI (assert). Per Intel SDM Vol. 3A §8.4.4.
        SmpSendIpi(rec.apic_id, kIcrDeliveryInit | kIcrLevelAssert);

        // 10 ms wait — SchedSleepTicks(1) at 100 Hz. Interrupts must
        // be enabled for this (the wait path uses the timer-driven
        // sleep queue); SmpStartAps runs after TimerInit so that's fine.
        sched::SchedSleepTicks(1);

        // SIPI with vector = trampoline_phys >> 12 = 0x08.
        const u32 sipi = kIcrDeliveryStartup | (kTrampolinePhys >> 12);
        SmpSendIpi(rec.apic_id, sipi);

        if (!WaitForApOnline())
        {
            // Intel recommends a second SIPI if the first doesn't take.
            SmpSendIpi(rec.apic_id, sipi);
            if (!WaitForApOnline())
            {
                core::LogWithValue(core::LogLevel::Error, "arch/smp", "AP never signalled online, giving up",
                                   static_cast<u64>(rec.apic_id));
                continue;
            }
        }

        ++aps_started;
        ++g_cpus_online;
    }

    core::LogWithValue(core::LogLevel::Info, "arch/smp", "SMP bring-up complete, cpus_online", g_cpus_online);
    return aps_started;
}

} // namespace customos::arch
