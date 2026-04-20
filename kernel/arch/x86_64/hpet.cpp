#include "hpet.h"

#include "../../acpi/acpi.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"

namespace customos::arch
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
    const u64 phys = acpi::HpetAddress();
    if (phys == 0)
    {
        core::Log(core::LogLevel::Warn, "arch/hpet", "no HPET table from ACPI; skipping init");
        return;
    }

    void* mmio = mm::MapMmio(phys, kHpetWindowBytes);
    if (mmio == nullptr)
    {
        core::Panic("arch/hpet", "MapMmio failed for HPET block");
    }
    g_mmio = static_cast<volatile u8*>(mmio);

    const u64 cap = Reg(kRegCap);
    g_period_fs = static_cast<u32>(cap >> kCapPeriodShift);

    if ((cap & kCapCounterSize64) == 0)
    {
        // 32-bit HPETs are vanishingly rare on x86_64 but the spec
        // allows them. Rather than write a 32-bit read+retry path
        // with no hardware to validate against, halt loudly and
        // leave the driver disabled if we ever see one.
        core::Panic("arch/hpet", "32-bit HPET counter unsupported — file a bug");
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

} // namespace customos::arch
