#include "reboot.h"

#include "../acpi/acpi.h"
#include "../arch/x86_64/cpu.h"
#include "klog.h"

namespace customos::core
{

namespace
{

// Mid-scale delay between reset attempts. Any reset that works at
// all works in single-digit microseconds; this just gives the
// chipset time to latch the reset before we fall through to the
// next approach.
void SpinShortDelay()
{
    for (u64 i = 0; i < 1'000'000; ++i)
    {
        asm volatile("" ::: "memory");
    }
}

} // namespace

[[noreturn]] void KernelReboot()
{
    Log(LogLevel::Warn, "core/reboot", "reboot requested — trying ACPI FADT reset");

    // 1. ACPI FADT RESET_REG. The firmware-defined path, honoured
    //    by every modern chipset that ships an ACPI table with the
    //    RESET_REG_SUP flag set. If AcpiReset returns false, no
    //    usable reset register is advertised; if it returns true,
    //    control has already been reset and we don't actually
    //    reach the next line.
    if (acpi::AcpiReset())
    {
        // Write issued — chipset should already be rebooting. If
        // we somehow still run, drop into the legacy fall-backs.
        SpinShortDelay();
    }

    // 2. PC-AT chipset reset port 0xCF9. Value 0x02 asserts the
    //    sys-reset line; 0x04 cycles; 0x06 combines both. QEMU
    //    q35 honours 0x06; real chipsets vary, so try both
    //    stepping-stones.
    Log(LogLevel::Warn, "core/reboot", "trying port 0xCF9 (chipset reset)");
    arch::Outb(0xCF9, 0x02);
    SpinShortDelay();
    arch::Outb(0xCF9, 0x06);
    SpinShortDelay();

    // 3. 8042 keyboard-controller reset line. Command 0xFE on
    //    port 0x64 pulses the CPU reset line on every PC-AT-
    //    compatible board — the pre-ACPI canonical path. Wait for
    //    the input buffer to drain so the command isn't dropped.
    Log(LogLevel::Warn, "core/reboot", "trying 8042 reset command");
    for (u64 i = 0; i < 100'000; ++i)
    {
        if ((arch::Inb(0x64) & (1U << 1)) == 0)
        {
            break;
        }
    }
    arch::Outb(0x64, 0xFE);
    SpinShortDelay();

    // 4. Triple fault via null IDT. Loading an empty IDT and then
    //    triggering ANY exception enters #DF; the double-fault
    //    handler is also missing (the IDT is zeroed), so the CPU
    //    shuts down and the chipset resets. This is the "nothing
    //    else worked" path — guaranteed to stop execution.
    Log(LogLevel::Error, "core/reboot", "all reset paths failed; triple-faulting");
    struct [[gnu::packed]] IdtPtr
    {
        u16 limit;
        u64 base;
    };
    const IdtPtr null_idtr{0, 0};
    asm volatile("lidt %0; int3" : : "m"(null_idtr));

    // Should never reach here. If we do, halt forever — the caller
    // asked to reboot and we can't; stopping the CPU is the least
    // surprising outcome.
    arch::Halt();
}

} // namespace customos::core
