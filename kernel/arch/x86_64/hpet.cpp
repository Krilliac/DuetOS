#include "arch/x86_64/hpet.h"

#include "acpi/acpi.h"
#include "log/klog.h"
#include "core/panic.h"
#include "mm/paging.h"

namespace duetos::arch
{

namespace
{

// Register offsets within the 1 KiB HPET MMIO block.
constexpr u64 kRegCap = 0x00;           // capabilities + ID (RO)
constexpr u64 kRegGeneralConfig = 0x10; // enable / legacy-replace
constexpr u64 kRegMainCounter = 0xF0;   // main counter (RW when halted)

// General-configuration bits.
constexpr u64 kConfigEnableCnf = 1ULL << 0;

// Capabilities register layout.
constexpr u64 kCapCounterSize64 = 1ULL << 13;
constexpr u64 kCapPeriodShift = 32;

// 1 KiB MMIO window — the HPET spec reserves this amount per block.
constexpr u64 kHpetWindowBytes = 0x400;

constinit volatile u8* g_mmio = nullptr;
constinit u32 g_period_fs = 0;

inline volatile u64& Reg(u64 offset)
{
    return *reinterpret_cast<volatile u64*>(g_mmio + offset);
}

} // namespace

void HpetInit()
{
    KLOG_TRACE_SCOPE("arch/hpet", "HpetInit");
    const u64 phys = acpi::HpetAddress();
    if (phys == 0)
    {
        core::Log(core::LogLevel::Warn, "arch/hpet", "no HPET table from ACPI; skipping init");
        return;
    }

    void* mmio = mm::MapMmio(phys, kHpetWindowBytes);
    if (mmio == nullptr)
    {
        // Debug: panic so the failure surfaces. Release: leave
        // g_mmio null and return — the timekeeper layer already
        // falls back to LAPIC timing when HPET is absent
        // (matches the "no ACPI table" path above). Explicitly
        // null g_mmio before bailing — without this, a previous
        // (re-)init attempt could leave a stale pointer the
        // fallback layer would then poke.
        g_mmio = nullptr;
        core::DebugPanicOrWarn("arch/hpet", "MapMmio failed for HPET block");
        return;
    }
    g_mmio = static_cast<volatile u8*>(mmio);

    const u64 cap = Reg(kRegCap);
    g_period_fs = static_cast<u32>(cap >> kCapPeriodShift);

    if ((cap & kCapCounterSize64) == 0)
    {
        // 32-bit HPETs are vanishingly rare on x86_64 but the spec
        // allows them. Debug: panic loudly so the unsupported-hw
        // bug report writes itself. Release: drop g_mmio and skip
        // — same fallback story as the MapMmio-failure case
        // above.
        core::DebugPanicOrWarn("arch/hpet", "32-bit HPET counter unsupported — file a bug");
        g_mmio = nullptr;
        return;
    }

    // Halt the counter before writing configuration or the counter
    // itself. Reset it to 0 so all deltas are relative to init.
    Reg(kRegGeneralConfig) = Reg(kRegGeneralConfig) & ~kConfigEnableCnf;
    Reg(kRegMainCounter) = 0;
    Reg(kRegGeneralConfig) = Reg(kRegGeneralConfig) | kConfigEnableCnf;

    core::LogWithValue(core::LogLevel::Info, "arch/hpet", "mmio virt", reinterpret_cast<u64>(g_mmio));
    core::LogWithValue(core::LogLevel::Info, "arch/hpet", "  period fs", static_cast<u64>(g_period_fs));
    core::LogWithValue(core::LogLevel::Info, "arch/hpet", "  timers", static_cast<u64>(acpi::HpetTimerCount()));
    core::Log(core::LogLevel::Info, "arch/hpet", "main counter enabled");
}

void HpetSelfTest()
{
    if (g_mmio == nullptr)
    {
        return; // no HPET — nothing to test, not an error
    }

    // Sanity: the counter must advance between two quick reads. Done
    // with a bounded spin cap rather than a sleep because the timer
    // isn't guaranteed to be armed yet (HpetSelfTest runs right
    // after HpetInit, well before the scheduler comes up). The
    // counter ticks at ~14 MHz on QEMU q35, so a few-million-
    // iteration pause should see plenty of increments.
    const u64 before = HpetReadCounter();
    for (u64 i = 0; i < 10'000'000; ++i)
    {
        asm volatile("pause" ::: "memory");
        if (HpetReadCounter() != before)
        {
            break;
        }
    }
    const u64 after = HpetReadCounter();
    if (after == before)
    {
        // Real-hardware soft-fail: some firmware (Intel C600 errata,
        // some AMD SB7xx, occasional Insyde laptops) report a present
        // HPET whose counter is dead-on-arrival because the chipset
        // gate is held low by an undocumented register. Panicking
        // here would brick boot on those boxes; the rest of the
        // kernel already treats `g_mmio==nullptr` as "no HPET, fall
        // back to LAPIC/TSC". Log a loud WARN and disable HPET
        // instead so the timekeeper layer transparently degrades.
        core::Log(core::LogLevel::Warn, "arch/hpet",
                  "self-test: counter did not advance — disabling HPET, falling back to LAPIC/TSC timing");
        g_mmio = nullptr;
        return;
    }
    if (after < before)
    {
        // Same soft-fail reasoning: a 64-bit monotonic counter that
        // went backwards is a firmware bug, but it's the firmware's
        // bug, not ours. Disable HPET and degrade gracefully —
        // panicking here would refuse to boot on a buggy laptop.
        core::LogWithValue(core::LogLevel::Warn, "arch/hpet", "self-test: counter went backwards — disabling HPET",
                           after);
        g_mmio = nullptr;
        return;
    }

    core::LogWithValue(core::LogLevel::Info, "arch/hpet", "self-test delta", after - before);
}

u64 HpetReadCounter()
{
    if (g_mmio == nullptr)
    {
        return 0;
    }
    return Reg(kRegMainCounter);
}

u32 HpetPeriodFemtoseconds()
{
    return g_period_fs;
}

} // namespace duetos::arch
