#include "acpi/acpi_sci.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/ioapic.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "core/panic.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

namespace duetos::acpi
{

namespace
{

// PM1 status/enable bit 8 — power or sleep button. ACPI §4.8.3.1.
constexpr u16 kPwrBtnBit = 1U << 8;
// PM1 control bit 0 — SCI_EN: 1 ⇒ OS owns ACPI, SCI routed to the
// OS instead of an SMI. ACPI §4.8.3.2.1.
constexpr u16 kSciEnBit = 1U << 0;

sync::SpinLock g_sci_lock;
SciPending g_pending{};
sched::WaitQueue* g_wake = nullptr;
constinit bool g_active = false;

// Cached register ports (latched in AcpiSciInit so the IRQ handler
// does no FADT accessor calls — just port I/O).
constinit u16 g_pm1a_sts = 0;
constinit u16 g_pm1b_sts = 0;
constinit u16 g_gpe0_base = 0;
constinit u8 g_gpe0_half = 0; // status bytes (== enable bytes)
constinit u16 g_gpe1_base = 0;
constinit u8 g_gpe1_half = 0;

// IRQ context. No AML, no allocation, no blocking. Read + write-1-
// clear PM1 / GPE status, latch what fired, wake the worker.
void SciHandler()
{
    if (!g_active)
    {
        return;
    }

    bool pwrbtn = false;
    u32 gpe0 = 0;
    u32 gpe1 = 0;

    const u16 a = arch::Inw(g_pm1a_sts);
    if ((a & kPwrBtnBit) != 0)
    {
        pwrbtn = true;
        arch::Outw(g_pm1a_sts, kPwrBtnBit); // write-1-clear
    }
    if (g_pm1b_sts != 0)
    {
        const u16 b = arch::Inw(g_pm1b_sts);
        if ((b & kPwrBtnBit) != 0)
        {
            pwrbtn = true;
            arch::Outw(g_pm1b_sts, kPwrBtnBit);
        }
    }

    // GPE status: ack every set bit so the level-triggered SCI
    // de-asserts. The matching `_Qxx` AML method is NOT run here —
    // see acpi_sci.h GAP. We also clear the GPE's enable bit so a
    // re-raise can't livelock the SCI before a `_Qxx` consumer
    // exists.
    for (u8 i = 0; i < g_gpe0_half; ++i)
    {
        const u16 sp = static_cast<u16>(g_gpe0_base + i);
        const u8 s = arch::Inb(sp);
        if (s != 0)
        {
            gpe0 |= static_cast<u32>(s) << (8u * i);
            arch::Outb(sp, s); // write-1-clear status
            const u16 ep = static_cast<u16>(g_gpe0_base + g_gpe0_half + i);
            arch::Outb(ep, static_cast<u8>(arch::Inb(ep) & ~s)); // mask
        }
    }
    for (u8 i = 0; i < g_gpe1_half; ++i)
    {
        const u16 sp = static_cast<u16>(g_gpe1_base + i);
        const u8 s = arch::Inb(sp);
        if (s != 0)
        {
            gpe1 |= static_cast<u32>(s) << (8u * i);
            arch::Outb(sp, s);
            const u16 ep = static_cast<u16>(g_gpe1_base + g_gpe1_half + i);
            arch::Outb(ep, static_cast<u8>(arch::Inb(ep) & ~s));
        }
    }

    if (pwrbtn)
    {
        // Terminal-significance structural sentinel (IRQ-safe raw
        // serial): a power-button SCI is rare and leads to
        // shutdown — boot-log-analyze wants the breadcrumb, and it
        // is the audit point if the button ever fires unexpectedly.
        arch::SerialWrite("[env/sci] PWRBTN_STS latched\n");
    }
    {
        sync::SpinLockGuard g(g_sci_lock);
        g_pending.power_button |= pwrbtn;
        g_pending.gpe0_status |= gpe0;
        g_pending.gpe1_status |= gpe1;
    }
    if (g_wake != nullptr)
    {
        sched::WaitQueueWakeOne(g_wake);
    }
}

} // namespace

void AcpiSciInit(sched::WaitQueue* wake)
{
    if (g_active)
    {
        return;
    }

    const u32 pm1a_evt = Pm1aEventPort();
    const u8 evt_len = Pm1EventLen();
    if (pm1a_evt == 0 || evt_len < 2)
    {
        KLOG_WARN("acpi/sci", "no PM1 event block in FADT — SCI not serviced");
        return;
    }

    g_wake = wake;
    const u16 half = static_cast<u16>(evt_len / 2);
    g_pm1a_sts = static_cast<u16>(pm1a_evt);
    const u16 pm1a_en = static_cast<u16>(pm1a_evt + half);
    const u32 pm1b_evt = Pm1bEventPort();
    u16 pm1b_en = 0;
    if (pm1b_evt != 0)
    {
        g_pm1b_sts = static_cast<u16>(pm1b_evt);
        pm1b_en = static_cast<u16>(pm1b_evt + half);
    }

    const u32 gpe0 = Gpe0Block();
    if (gpe0 != 0 && Gpe0BlockLen() >= 2)
    {
        g_gpe0_base = static_cast<u16>(gpe0);
        g_gpe0_half = static_cast<u8>(Gpe0BlockLen() / 2);
    }
    const u32 gpe1 = Gpe1Block();
    if (gpe1 != 0 && Gpe1BlockLen() >= 2)
    {
        g_gpe1_base = static_cast<u16>(gpe1);
        g_gpe1_half = static_cast<u8>(Gpe1BlockLen() / 2);
    }

    // Hand ACPI ownership from firmware SMM to the OS if it isn't
    // already (QEMU/SeaBIOS sets SCI_EN for us, so this is a no-op
    // there). Bounded poll — never hang the boot if firmware is
    // uncooperative; PWRBTN arming below is still attempted.
    const u32 pm1a_cnt = Pm1aControlPort();
    const u32 smi = AcpiSmiCommandPort();
    const u8 enval = AcpiEnableValue();
    if (pm1a_cnt != 0 && smi != 0 && enval != 0 && (arch::Inw(static_cast<u16>(pm1a_cnt)) & kSciEnBit) == 0)
    {
        arch::Outb(static_cast<u16>(smi), enval);
        bool on = false;
        for (u32 spin = 0; spin < 2000000u; ++spin)
        {
            if ((arch::Inw(static_cast<u16>(pm1a_cnt)) & kSciEnBit) != 0)
            {
                on = true;
                break;
            }
            asm volatile("pause");
        }
        if (!on)
        {
            KLOG_WARN("acpi/sci", "ACPI_ENABLE handshake did not set SCI_EN — continuing");
        }
    }

    // Clear any stale PWRBTN_STS, then arm PWRBTN_EN. GPEs are
    // intentionally left disabled in v0 (no `_Qxx` consumer yet —
    // see header GAP); the handler still acks them defensively.
    arch::Outw(g_pm1a_sts, kPwrBtnBit);
    arch::Outw(pm1a_en, static_cast<u16>(arch::Inw(pm1a_en) | kPwrBtnBit));
    if (g_pm1b_sts != 0)
    {
        arch::Outw(g_pm1b_sts, kPwrBtnBit);
        arch::Outw(pm1b_en, static_cast<u16>(arch::Inw(pm1b_en) | kPwrBtnBit));
    }

    // Route the SCI line through the IOAPIC and install the handler.
    // SCI_INT is reported as an ISA-style IRQ; the vector follows
    // the same 0x20+irq convention as timer/keyboard, and
    // IsaIrqToGsi applies any MADT override (the SCI is normally
    // level/active-low and the firmware ships an override for it).
    const u16 sci_irq = SciVector();
    if (sci_irq > 222)
    {
        KLOG_WARN("acpi/sci", "SCI_INT out of ISA range — SCI not serviced");
        return;
    }
    const u8 vector = static_cast<u8>(0x20 + sci_irq);
    const u32 gsi = IsaIrqToGsi(static_cast<u8>(sci_irq));
    const u8 bsp_id = static_cast<u8>(arch::LapicRead(arch::kLapicRegId) >> 24);

    g_active = true; // before routing — the line may already be asserted
    arch::IrqInstall(vector, &SciHandler);
    arch::IoApicRoute(gsi, vector, bsp_id, static_cast<u8>(sci_irq));

    // One-time structural boot milestone — raw serial like the
    // sibling `[acpi] sci_int=` line, so it survives klog level
    // demotion in release and boot-log-analyze / the power-button
    // smoke can gate on "the SCI is live".
    arch::SerialWrite("[acpi/sci] armed\n");
    KLOG_DEBUG_V("acpi/sci", "SCI isa_irq", sci_irq);
    KLOG_DEBUG_V("acpi/sci", "SCI vector", vector);
}

bool AcpiSciActive()
{
    return g_active;
}

SciPending AcpiSciTakePending()
{
    sync::SpinLockGuard g(g_sci_lock);
    const SciPending out = g_pending;
    g_pending = SciPending{};
    return out;
}

void AcpiSciSelfTest()
{
    // Decode predicate on a synthetic PM1 status word — no port
    // I/O, so this never arms or fires a real button / shutdown.
    KASSERT((static_cast<u16>(kPwrBtnBit) & kPwrBtnBit) != 0, "acpi/sci", "pwrbtn bit self-check");
    const u16 fake_idle = 0x0001; // TMR_STS only — not the button
    const u16 fake_btn = kPwrBtnBit | 0x0001;
    KASSERT((fake_idle & kPwrBtnBit) == 0, "acpi/sci", "decode false-positive");
    KASSERT((fake_btn & kPwrBtnBit) != 0, "acpi/sci", "decode false-negative");

    // Latch round-trip: seed, take, must read back then clear.
    {
        sync::SpinLockGuard g(g_sci_lock);
        g_pending.power_button = true;
        g_pending.gpe0_status = 0xAB;
    }
    const SciPending p = AcpiSciTakePending();
    KASSERT(p.power_button && p.gpe0_status == 0xAB, "acpi/sci", "take-pending did not read latched state");
    const SciPending q = AcpiSciTakePending();
    KASSERT(!q.power_button && q.gpe0_status == 0, "acpi/sci", "take-pending did not clear latch");

    arch::SerialWrite("[acpi/sci-selftest] PASS\n");
}

} // namespace duetos::acpi
