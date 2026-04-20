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

namespace customos::arch
{

namespace
{

// LAPIC ICR (Interrupt Command Register) — two 32-bit halves. Used by
// the IPI-send helper. Writing the low half triggers delivery; the
// delivery-status bit (low-half bit 12) stays set until the LAPIC has
// accepted the IPI.
constexpr u64 kLapicRegIcrLow = 0x300;
constexpr u64 kLapicRegIcrHigh = 0x310;

constexpr u32 kIcrDeliveryInit = 5U << 8;
constexpr u32 kIcrDeliveryStartup = 6U << 8;
constexpr u32 kIcrLevelAssert = 1U << 14;
constexpr u32 kIcrDeliveryPending = 1U << 12;

// The SIPI vector byte carries the trampoline's physical page number
// (page aligned, below 1 MiB). 0x08 means the trampoline must live at
// physical 0x8000. This matches the de-facto convention used by most
// Unix-like kernels for the AP wake-up page.
constexpr u32 kSipiVector = 0x08;

constinit u64 g_cpus_online = 1; // BSP counted; APs add to this when they
                                 // reach the C++ entry (future slice).

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

} // namespace

/// Send a raw IPI via the LAPIC ICR. Public-ish (file scope anonymous
/// in v0 but callable from the future ap_bringup trampoline-sender).
/// Exposed now so future drivers can send their own IPIs (reschedule,
/// TLB shootdown) without reimplementing the ICR dance.
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

u64 SmpStartAps()
{
    // BSP side of AP bring-up — v0 is DISCOVERY ONLY.
    //
    // Discovery: enumerate MADT LAPIC records, identify which apic_ids
    // are eligible to be brought up (enabled + not-BSP), log each one.
    //
    // Actual bring-up (INIT-SIPI-SIPI + real→long mode trampoline + AP
    // C++ entry joining the scheduler) is deliberately deferred to a
    // dedicated session so the trampoline assembly gets proper
    // iterative testing. See:
    //   docs/knowledge/smp-ap-bringup-scope.md
    // for the staged plan.

    if (acpi::CpuCount() == 0)
    {
        core::Panic("arch/smp", "MADT reported zero CPUs");
    }

    const u8 bsp_apic_id = static_cast<u8>(LapicRead(kLapicRegId) >> 24);
    u64 ap_candidates = 0;

    for (u64 i = 0; i < acpi::CpuCount(); ++i)
    {
        const acpi::LapicRecord& rec = acpi::Lapic(i);
        if (rec.apic_id == bsp_apic_id)
        {
            core::LogWithValue(core::LogLevel::Info, "arch/smp", "BSP apic_id", static_cast<u64>(rec.apic_id));
            continue;
        }
        if (!rec.enabled)
        {
            core::LogWithValue(core::LogLevel::Warn, "arch/smp", "skipping disabled AP apic_id",
                               static_cast<u64>(rec.apic_id));
            continue;
        }
        ++ap_candidates;
        core::LogWithValue(core::LogLevel::Info, "arch/smp", "candidate AP apic_id", static_cast<u64>(rec.apic_id));
    }

    core::LogWithValue(core::LogLevel::Info, "arch/smp", "discovery complete; APs to bring up later", ap_candidates);
    return 0;
}

} // namespace customos::arch
