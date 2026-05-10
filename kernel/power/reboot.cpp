#include "power/reboot.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "diag/fix_journal.h"
#include "log/klog.h"

namespace duetos::core
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

[[noreturn]] void KernelHalt()
{
    Log(LogLevel::Warn, "core/halt", "shutdown requested — trying ACPI S5");

    // 1. ACPI S5 via the AML _S5_ extractor + PM1A/PM1B write.
    //    AcpiShutdown returns false on missing `\_S5`, missing PM1
    //    block, or any AML-shape deviation; on success the chipset
    //    has already been told to soft-off and we shouldn't reach
    //    the next line. If we DO reach it, fall through to the
    //    QEMU-known shutdown ports.
    if (acpi::AcpiShutdown())
    {
        SpinShortDelay();
    }

    // 2. QEMU-specific shutdown ports. Some platforms wire the
    //    PM1A control register at 0x604 (q35), 0xB004 (piix), or
    //    0x4004; others surface a debug-exit at 0x501. Writing
    //    SLP_TYP=5 + SLP_EN=1 = 0x2000 to the PM1A register tells
    //    the chipset model to soft-off. Reaches the chipset on
    //    QEMU even when the FADT didn't carry a usable PM1A
    //    address (some old machine types ship pm1a_cnt_blk=0).
    Log(LogLevel::Warn, "core/halt", "trying QEMU shutdown ports (0x604 / 0xB004 / 0x4004)");
    arch::Outw(0x604, 0x2000);
    SpinShortDelay();
    arch::Outw(0xB004, 0x2000);
    SpinShortDelay();
    arch::Outw(0x4004, 0x3400);
    SpinShortDelay();

    // 3. Last resort — mask interrupts and park the CPU. The
    //    chipset stays powered; the operator (or VM `quit`) cuts
    //    power. Documented fallback for hardware that needs
    //    `_PTS` / `_GTS` method execution we don't run yet.
    Log(LogLevel::Warn, "core/halt", "all shutdown paths failed — CPU halted");
    asm volatile("cli");
    for (;;)
    {
        arch::Halt();
    }
}

} // namespace duetos::core
