#include "types.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/traps.h"

/*
 * Kernel entry in C++. Called by kernel/arch/x86_64/boot.S once the CPU is
 * in 64-bit long mode with a valid stack and a minimal identity-mapped
 * page hierarchy.
 *
 * Current scope: bring up the canonical GDT + IDT, exercise the trap path
 * with a self-test int3, halt deterministically. Physical frame allocator,
 * higher-half move, and IRQ controller bring-up are all future commits —
 * each large enough to stand on its own rather than being smeared in here.
 */

extern "C" void kernel_main(customos::u32 multiboot_magic,
                            customos::uptr multiboot_info)
{
    using namespace customos::arch;

    SerialInit();
    SerialWrite("[boot] CustomOS kernel reached long mode.\n");

    constexpr customos::u32 kMultiboot2BootMagic = 0x36D76289;
    if (multiboot_magic == kMultiboot2BootMagic)
    {
        SerialWrite("[boot] Multiboot2 handoff verified.\n");
    }
    else
    {
        SerialWrite("[boot] WARNING: unexpected boot magic.\n");
    }

    (void)multiboot_info;   // Consumed by the memory-map parser in a later commit.

    SerialWrite("[boot] Installing kernel GDT.\n");
    GdtInit();

    SerialWrite("[boot] Installing IDT (vectors 0..31).\n");
    IdtInit();

    SerialWrite("[boot] Trap path online — raising int3 to self-test.\n");
    RaiseSelfTestBreakpoint();
    // RaiseSelfTestBreakpoint never returns (the dispatcher halts).
}
