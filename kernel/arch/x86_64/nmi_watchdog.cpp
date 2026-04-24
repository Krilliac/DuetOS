#include "nmi_watchdog.h"

#include "lapic.h"
#include "serial.h"

#include "../../core/panic.h"

namespace customos::arch
{

namespace
{

// Approximate watchdog interval, measured in unhalted core
// cycles. The counter is preloaded so it overflows after this
// many cycles of real execution (halted cycles don't count, so
// idle time doesn't burn budget). At 1 GHz this is ~10 s; at
// 4 GHz it's ~2.5 s. The exact period doesn't have to be precise
// — what matters is that NmiWatchdogPet advances between
// consecutive overflows on a healthy kernel.
constexpr u64 kIntervalCycles = 10'000'000'000ULL;

// Number of consecutive watchdog NMIs with NO pet increment
// before we declare the kernel wedged. 3 gives a total
// detection window of 7.5–30 s across the speed range above,
// which comfortably absorbs any legitimate long CLI section
// while still catching a genuine hang before an operator would.
constexpr u32 kUnpettedThreshold = 3;

// Architectural PMU MSRs (Intel SDM Vol 4 — universal on any
// CPU that advertises arch perfmon v1 via CPUID.0Ah).
constexpr u32 kMsrIa32PmC0 = 0x0C1;
constexpr u32 kMsrIa32PerfEvtSel0 = 0x186;
constexpr u32 kMsrIa32PerfGlobalStatus = 0x38E;
constexpr u32 kMsrIa32PerfGlobalCtrl = 0x38F;
constexpr u32 kMsrIa32PerfGlobalOvfCtrl = 0x390;

// PERFEVTSEL0 layout.
constexpr u64 kEvtEventUnhaltedCycles = 0x3C;
constexpr u64 kEvtUmaskNone = 0x00;
constexpr u64 kEvtOs = 1ULL << 17;  // count in ring 0..2
constexpr u64 kEvtInt = 1ULL << 20; // APIC interrupt on overflow
constexpr u64 kEvtEn = 1ULL << 22;  // counter enable (local)

// LAPIC LVT Perfmon delivery-mode bits (bits 10:8).
constexpr u32 kLvtDeliveryNmi = 0b100U << 8;

// State. All writes happen either at init (once) or from the
// NMI handler itself (which blocks further NMI delivery on this
// CPU until iretq). Pet is a simple increment from the timer
// IRQ; a u64 load is atomic on x86_64 so the NMI side gets a
// consistent value.
constinit bool g_enabled = false;
constinit u64 g_counter_preload = 0;
constinit u64 g_pet_counter = 0;
constinit u64 g_pet_last_seen = 0;
constinit u32 g_consecutive_unpetted = 0;

void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = u32(value);
    const u32 hi = u32(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

u64 ReadMsr(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (u64(hi) << 32) | lo;
}

// Mask a preload value to the counter's bit width. Writing
// bits above the width would #GP on a strict PMU.
u64 MaskToWidth(u64 v, u32 width)
{
    if (width >= 64)
        return v;
    const u64 mask = (1ULL << width) - 1;
    return v & mask;
}

} // namespace

void NmiWatchdogInit()
{
    // CPUID leaf 0xA: architectural performance monitoring.
    // EAX[7:0]   = version
    // EAX[15:8]  = number of general-purpose counters per logical CPU
    // EAX[23:16] = bit width of general-purpose counters
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0xA));
    const u32 version = eax & 0xFF;
    const u32 n_counters = (eax >> 8) & 0xFF;
    const u32 width = (eax >> 16) & 0xFF;
    if (version < 1 || n_counters < 1 || width == 0 || width > 64)
    {
        SerialWrite("[nmi-watchdog] perfmon unavailable (version=");
        SerialWriteHex(u64(version));
        SerialWrite(" counters=");
        SerialWriteHex(u64(n_counters));
        SerialWrite(" width=");
        SerialWriteHex(u64(width));
        SerialWrite(") — disabled\n");
        return;
    }
    // Two's-complement preload so the counter overflows after
    // ~kIntervalCycles of real execution. Writing the masked
    // form keeps us within the counter's declared width.
    const u64 neg = u64(-i64(kIntervalCycles));
    g_counter_preload = MaskToWidth(neg, width);

    // Stop counter 0 before reprogramming (global enable bit 0).
    WriteMsr(kMsrIa32PerfGlobalCtrl, 0);

    // Event select: unhalted core cycles, count in ring 0–2,
    // raise APIC interrupt on overflow, local-enable the counter.
    const u64 sel = kEvtEventUnhaltedCycles | (kEvtUmaskNone << 8) | kEvtOs | kEvtInt | kEvtEn;
    WriteMsr(kMsrIa32PerfEvtSel0, sel);

    // Preload counter. Must be written AFTER PERFEVTSEL0 so the
    // enable/interrupt bits are armed by the time the counter
    // wraps.
    WriteMsr(kMsrIa32PmC0, g_counter_preload);

    // Clear any stale overflow bit for counter 0.
    WriteMsr(kMsrIa32PerfGlobalOvfCtrl, 1ULL << 0);

    // Route LVT Perf → NMI delivery. Mask bit (16) stays clear.
    // Vector bits (7:0) are ignored for NMI delivery but we
    // keep them zero for tidiness.
    LapicWrite(kLapicRegLvtPerf, kLvtDeliveryNmi);

    // Global-enable counter 0.
    WriteMsr(kMsrIa32PerfGlobalCtrl, 1ULL << 0);

    g_pet_last_seen = g_pet_counter;
    g_consecutive_unpetted = 0;
    g_enabled = true;

    SerialWrite("[nmi-watchdog] armed: perfmon v");
    SerialWriteHex(u64(version));
    SerialWrite(" width=");
    SerialWriteHex(u64(width));
    SerialWrite(" interval_cycles=");
    SerialWriteHex(kIntervalCycles);
    SerialWrite(" threshold=");
    SerialWriteHex(u64(kUnpettedThreshold));
    SerialWrite("\n");
}

void NmiWatchdogPet()
{
    ++g_pet_counter;
}

void NmiWatchdogDisable()
{
    if (!g_enabled)
        return;
    // Global-disable first so no further overflow-NMI fires.
    WriteMsr(kMsrIa32PerfGlobalCtrl, 0);
    // Mask the LVT Perf slot too in case some other path re-arms
    // the counter.
    LapicWrite(kLapicRegLvtPerf, 1U << 16);
    g_enabled = false;
}

bool NmiWatchdogHandleNmi()
{
    if (!g_enabled)
        return false;

    // Check overflow status bit 0 for counter 0. If not set,
    // this NMI came from somewhere else (panic-broadcast IPI,
    // external NMI pin, etc.) and is not ours to handle.
    const u64 status = ReadMsr(kMsrIa32PerfGlobalStatus);
    if ((status & (1ULL << 0)) == 0)
        return false;

    const u64 pet_now = g_pet_counter;
    if (pet_now != g_pet_last_seen)
    {
        // Pet advanced — timer IRQ is alive, kernel is making
        // progress. Reset the strike counter.
        g_pet_last_seen = pet_now;
        g_consecutive_unpetted = 0;
    }
    else
    {
        ++g_consecutive_unpetted;
        if (g_consecutive_unpetted >= kUnpettedThreshold)
        {
            // Kernel is wedged. Disable the watchdog FIRST so
            // the panic path can dump diagnostics without
            // re-entering through a subsequent NMI.
            NmiWatchdogDisable();
            SerialWrite("\n[nmi-watchdog] HANG DETECTED — pet counter stuck at ");
            SerialWriteHex(pet_now);
            SerialWrite(" across ");
            SerialWriteHex(u64(g_consecutive_unpetted));
            SerialWrite(" intervals\n");
            ::customos::core::Panic("nmi-watchdog", "kernel wedged (timer IRQ not firing)");
            // Panic is [[noreturn]]; unreachable below.
        }
    }

    // Clear overflow + re-preload + return to interrupted code.
    WriteMsr(kMsrIa32PerfGlobalOvfCtrl, 1ULL << 0);
    WriteMsr(kMsrIa32PmC0, g_counter_preload);
    return true;
}

} // namespace customos::arch
