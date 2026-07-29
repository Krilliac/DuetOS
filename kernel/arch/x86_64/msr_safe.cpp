#include "arch/x86_64/msr_safe.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/extable.h"

/*
 * WriteMsrSafe / ReadMsrSafe extable wiring.
 *
 * The bodies live in msr_safe.S. Each wrapper exports three labels
 * delimiting its one faulting instruction and its fixup target:
 *
 *   wrmsr_safe_start / rdmsr_safe_start  — the faulting instruction
 *   wrmsr_safe_end   / rdmsr_safe_end    — one past it (success)
 *   wrmsr_safe_fault / rdmsr_safe_fault  — fixup the trap dispatcher
 *                                          jumps RIP to on a #GP /
 *                                          #PF inside [start, end).
 *
 * `RegisterMsrSafeExtable` is called from the early boot path after
 * `TrapsRegisterExtable`. The trap dispatcher in `traps.cpp` walks
 * the extable on every ring-0 #GP / #PF — if the faulting RIP falls
 * in [start, end) it redirects to `fault`.
 */

extern "C"
{
    extern const duetos::u8 wrmsr_safe_start[];
    extern const duetos::u8 wrmsr_safe_end[];
    extern const duetos::u8 wrmsr_safe_fault[];
    extern const duetos::u8 rdmsr_safe_start[];
    extern const duetos::u8 rdmsr_safe_end[];
    extern const duetos::u8 rdmsr_safe_fault[];
}

namespace duetos::arch
{

namespace
{

duetos::u64 Addr(const duetos::u8* label)
{
    return reinterpret_cast<duetos::u64>(label);
}

// An MSR selector no x86 part implements. Intel's model-specific
// space stops well short of it and AMD's runs 0xC000_0000..
// 0xC001_FFFF, so a `rdmsr` here is a #GP on every real CPU and
// every hypervisor that models MSRs faithfully.
constexpr duetos::u32 kNonexistentMsr = 0xDEADBEEFu;

// IA32_APIC_BASE. Architectural on every part with a local APIC,
// which the kernel unconditionally requires (CpuMinimumFeatureGate
// hard-stops without kCpuFeatApic), so a failed read here means the
// safe-read plumbing is broken rather than the hardware being odd.
constexpr duetos::u32 kMsrIa32ApicBase = 0x1B;

} // namespace

void RegisterMsrSafeExtable()
{
    if (!::duetos::debug::KernelExtableRegister(Addr(wrmsr_safe_start), Addr(wrmsr_safe_end), Addr(wrmsr_safe_fault),
                                               "arch/wrmsr_safe"))
    {
        SerialWrite("[arch/msr-safe] wrmsr extable registration failed\n");
    }
    if (!::duetos::debug::KernelExtableRegister(Addr(rdmsr_safe_start), Addr(rdmsr_safe_end), Addr(rdmsr_safe_fault),
                                               "arch/rdmsr_safe"))
    {
        SerialWrite("[arch/msr-safe] rdmsr extable registration failed\n");
    }
}

void MsrSafeSelfTest()
{
    using core::PanicWithValue;

    // --- bookkeeping: both rows resolve to their own fixups -------
    // Deterministic on every platform (pure table lookup), so this
    // half is a hard gate. A miss here means either the boot order
    // regressed (probe running before registration) or the label
    // triple in msr_safe.S drifted.
    const u64 wr_hit = ::duetos::debug::KernelExtableFindFixup(Addr(wrmsr_safe_start));
    if (wr_hit != Addr(wrmsr_safe_fault))
        PanicWithValue("arch/msr-safe", "wrmsr extable row missing or mis-targeted", wr_hit);

    const u64 rd_hit = ::duetos::debug::KernelExtableFindFixup(Addr(rdmsr_safe_start));
    if (rd_hit != Addr(rdmsr_safe_fault))
        PanicWithValue("arch/msr-safe", "rdmsr extable row missing or mis-targeted", rd_hit);

    // The protected range must cover exactly the faulting
    // instruction — an empty or inverted range would register fine
    // and then never match at trap time.
    if (Addr(rdmsr_safe_end) <= Addr(rdmsr_safe_start))
        PanicWithValue("arch/msr-safe", "rdmsr protected range is empty", Addr(rdmsr_safe_end));

    if (!CpuHas(kCpuFeatMsr))
    {
        SerialWrite("[msr-safe-selftest] PASS (extable rows only — CPU reports no MSR support)\n");
        return;
    }

    // --- functional: an MSR that must be there --------------------
    u64 apic_base = 0;
    if (!ReadMsrSafe(kMsrIa32ApicBase, &apic_base))
        PanicWithValue("arch/msr-safe", "IA32_APIC_BASE read faulted", 0);
    if (apic_base == 0)
        PanicWithValue("arch/msr-safe", "IA32_APIC_BASE read back zero", apic_base);

    // --- functional: an MSR that must not be -----------------------
    // What this proves is that the probe RETURNS. Whether it returns
    // false depends on the platform: real hardware and KVM raise #GP
    // (so the extable fixup runs and we get false), while QEMU's TCG
    // interpreter answers 0 for unknown MSRs and we get true. Both
    // are legal; asserting `false` here would fail on TCG for a
    // reason that has nothing to do with this code. Not reaching the
    // next line at all is the failure mode this test exists to catch.
    u64 bogus = 0xA5A5A5A5A5A5A5A5ULL;
    const bool bogus_ok = ReadMsrSafe(kNonexistentMsr, &bogus);
    if (!bogus_ok && bogus != 0xA5A5A5A5A5A5A5A5ULL)
        PanicWithValue("arch/msr-safe", "failed read clobbered the destination", bogus);

    SerialLineGuard guard;
    SerialWrite("[msr-safe-selftest] PASS (extable rows + APIC_BASE=");
    SerialWriteHex(apic_base);
    SerialWrite(bogus_ok ? " + bogus MSR answered (no MSR faults modelled)" : " + bogus MSR #GP recovered");
    SerialWrite(")\n");
}

} // namespace duetos::arch
