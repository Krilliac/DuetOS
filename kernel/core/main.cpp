#include "types.h"
#include "../arch/x86_64/serial.h"

/*
 * Kernel entry in C++. Called by kernel/arch/x86_64/boot.S once the CPU
 * is in 64-bit long mode with a valid stack and a minimal identity-mapped
 * page hierarchy.
 *
 * Scope of this function today: produce visible output on COM1, then halt
 * deterministically. Paging, IDT, GDT reload, SMP bring-up, and scheduler
 * init all land in follow-up commits — each large enough to stand on its
 * own without being smeared into this entry point.
 */

namespace
{

[[noreturn]] void HaltForever()
{
    for (;;)
    {
        asm volatile("cli; hlt");
    }
}

} // namespace

extern "C" void kernel_main(customos::u32 multiboot_magic,
                            customos::uptr multiboot_info)
{
    customos::arch::SerialInit();
    customos::arch::SerialWrite("[boot] CustomOS kernel reached long mode.\n");

    // Verify we were loaded by a Multiboot2-compliant loader. The magic
    // value is defined by the spec and passed in eax at handoff; boot.S
    // forwards it here. If it's wrong we still halt, but we announce the
    // mismatch so early hardware bring-up doesn't silently boot on an
    // unexpected protocol.
    constexpr customos::u32 kMultiboot2BootMagic = 0x36D76289;
    if (multiboot_magic == kMultiboot2BootMagic)
    {
        customos::arch::SerialWrite("[boot] Multiboot2 handoff verified.\n");
    }
    else
    {
        customos::arch::SerialWrite("[boot] WARNING: unexpected boot magic.\n");
    }

    (void)multiboot_info;   // Consumed by the memory-map parser in a later commit.

    customos::arch::SerialWrite("[boot] Halting CPU.\n");
    HaltForever();
}
