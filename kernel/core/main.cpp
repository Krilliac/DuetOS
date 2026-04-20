#include "types.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/serial.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"

/*
 * Kernel entry in C++. Called by kernel/arch/x86_64/boot.S once the CPU is
 * in 64-bit long mode with a valid stack and the first 1 GiB of physical
 * memory identity-mapped.
 *
 * Current scope: bring up descriptors, parse the Multiboot2 memory map,
 * hand the frame allocator a working bitmap, run its self-test, carve a
 * fixed-size pool out for the kernel heap and self-test that, then halt.
 * IRQ controller bring-up, page-table API, and SMP are separate follow-up
 * commits.
 */

extern "C" void kernel_main(customos::u32 multiboot_magic,
                            customos::uptr multiboot_info)
{
    using namespace customos::arch;
    using namespace customos::mm;

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

    SerialWrite("[boot] Installing kernel GDT.\n");
    GdtInit();

    SerialWrite("[boot] Installing IDT (vectors 0..31).\n");
    IdtInit();

    SerialWrite("[boot] Parsing Multiboot2 memory map.\n");
    FrameAllocatorInit(multiboot_info);

    SerialWrite("  total frames : "); SerialWriteHex(TotalFrames());     SerialWrite("\n");
    SerialWrite("  free frames  : "); SerialWriteHex(FreeFramesCount()); SerialWrite("\n");

    FrameAllocatorSelfTest();

    SerialWrite("[boot] Bringing up kernel heap.\n");
    KernelHeapInit();
    KernelHeapSelfTest();

    SerialWrite("[boot] All subsystems online. Halting CPU.\n");
    Halt();
}
