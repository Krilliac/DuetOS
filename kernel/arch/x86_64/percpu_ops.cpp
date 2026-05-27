#include "arch/x86_64/percpu_ops.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "log/klog.h"

namespace duetos::arch
{

namespace
{

// Iteration count for the self-test. Sized small enough that the
// bring-up cost is invisible (a thousand single-instruction GS
// increments is ~microseconds on any sane x86_64), big enough that
// a bit-flip / off-by-one would show up.
constexpr u64 kSelfTestIters = 1000u;

} // namespace

void ThisCpuOpsSelfTest()
{
    KLOG_TRACE_SCOPE("arch/percpu_ops", "ThisCpuOpsSelfTest");

    // The self-test must run AFTER PerCpuInitBsp — without GSBASE
    // pointing at a kernel-canonical PerCpu, every `%gs:offset`
    // access dereferences user space (or zero) and triple-faults.
    // The caller (boot_bringup) sequences the call correctly; this
    // guard exists so a future reordering surfaces a clean panic
    // instead of an opaque triple fault.
    KASSERT(cpu::BspInstalled(), "arch/percpu_ops", "self-test ran before BSP install");

    constexpr u64 kOff = DUETOS_THIS_CPU_OFFSET(cpu::PerCpu, this_cpu_selftest_counter);

    // Disable interrupts across the test window. Even though every
    // helper is a single retired instruction, the test reads back
    // through `cpu::CurrentCpu()` to cross-check, and the IRQ-off
    // window matches the contract callers commit to anyway: "no
    // migration between offset compute and GS-relative access".
    Cli();

    // Start from a known baseline so the test doesn't depend on
    // whatever the BSP's slot held before — initial init leaves it
    // zero, but explicit is safer.
    ThisCpuWrite64(kOff, 0);
    if (ThisCpuRead64<u64>(kOff) != 0u)
    {
        Sti();
        core::Panic("arch/percpu_ops", "ThisCpuWrite64/Read64 round-trip != 0");
    }

    // Tight loop of `incq %gs:offset` instructions.
    for (u64 i = 0; i < kSelfTestIters; ++i)
    {
        ThisCpuInc64(kOff);
    }

    const u64 after_inc = ThisCpuRead64<u64>(kOff);
    if (after_inc != kSelfTestIters)
    {
        Sti();
        core::PanicWithValue("arch/percpu_ops", "ThisCpuInc64 read-back mismatch", after_inc);
    }

    // Validate the ADD path with a non-unit delta. 7 is coprime
    // with the previous counter so an off-by-one accidentally
    // landing on the right value is impossible.
    ThisCpuAdd64(kOff, 7);
    const u64 after_add = ThisCpuRead64<u64>(kOff);
    if (after_add != kSelfTestIters + 7u)
    {
        Sti();
        core::PanicWithValue("arch/percpu_ops", "ThisCpuAdd64 read-back mismatch", after_add);
    }

    // Cross-check: the same slot read via the normal pointer-deref
    // path must agree with the GS-relative reads. This catches the
    // case where the macros silently encode the wrong offset (e.g.
    // a PerCpu reshuffle missed an annotation).
    const u64 via_pointer = cpu::CurrentCpu()->this_cpu_selftest_counter;
    if (via_pointer != after_add)
    {
        Sti();
        core::PanicWithValue("arch/percpu_ops", "ThisCpu* vs CurrentCpu()->field divergence", via_pointer);
    }

    // Reset to zero so the slot doesn't carry stray state out of
    // the test window (defence-in-depth — no current reader, but
    // a future debug self-test that runs again would otherwise
    // start from a non-zero baseline).
    ThisCpuWrite64(kOff, 0);

    Sti();

    // One explicit PASS sentinel so a grepper can confirm the test
    // ran on this boot (the default KLOG_INFO would be quiet under
    // a release log-floor; the sentinel goes through SerialWrite
    // for the same reason the other structural sentinels do).
    SerialWrite("[this-cpu-ops] self-test OK\n");
}

} // namespace duetos::arch
