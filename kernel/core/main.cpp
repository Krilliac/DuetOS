#include "types.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/pic.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../mm/paging.h"
#include "../sched/sched.h"

/*
 * Kernel entry in C++. Called by kernel/arch/x86_64/boot.S once the CPU is
 * in 64-bit long mode with a valid stack and the first 1 GiB of physical
 * memory identity-mapped.
 *
 * Current scope: bring up descriptors, parse the Multiboot2 memory map,
 * hand the frame allocator a working bitmap, run its self-test, carve a
 * fixed-size pool out for the kernel heap and self-test it, adopt the
 * boot PML4 + run the paging self-test, mask the legacy 8259, bring up
 * the LAPIC, calibrate + arm the LAPIC timer at 100 Hz, then drop into
 * the idle loop with interrupts enabled. SMP, scheduler, and userland
 * are separate follow-up commits.
 */

extern "C" void kernel_main(customos::u32 multiboot_magic, customos::uptr multiboot_info)
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

    SerialWrite("  total frames : ");
    SerialWriteHex(TotalFrames());
    SerialWrite("\n");
    SerialWrite("  free frames  : ");
    SerialWriteHex(FreeFramesCount());
    SerialWrite("\n");

    FrameAllocatorSelfTest();

    SerialWrite("[boot] Bringing up kernel heap.\n");
    KernelHeapInit();
    KernelHeapSelfTest();

    SerialWrite("[boot] Bringing up paging.\n");
    PagingInit();
    PagingSelfTest();

    SerialWrite("[boot] Disabling 8259 PIC.\n");
    PicDisable();

    SerialWrite("[boot] Bringing up LAPIC.\n");
    LapicInit();

    SerialWrite("[boot] Bringing up periodic timer.\n");
    TimerInit();

    SerialWrite("[boot] Bringing up scheduler.\n");
    customos::sched::SchedInit();

    // Scheduler self-test: three kernel threads that each print their
    // name + iteration counter a handful of times, then exit. The boot
    // task (this one) then drops into IdleLoop; once all three workers
    // have called SchedExit the boot task is the only runnable task and
    // stays on the CPU indefinitely.
    auto worker = [](void* arg)
    {
        const char* name = static_cast<const char*>(arg);
        for (customos::u64 i = 0; i < 5; ++i)
        {
            SerialWrite("[sched] ");
            SerialWrite(name);
            SerialWrite(" i=");
            SerialWriteHex(i);
            SerialWrite(" ticks=");
            SerialWriteHex(TimerTicks());
            SerialWrite("\n");

            // Burn ~10 ms of CPU so the timer has a chance to preempt us
            // between iterations. Pure busy-loop; once sleep() lands,
            // switch to that.
            for (customos::u64 j = 0; j < 5'000'000; ++j)
            {
                asm volatile("" ::: "memory");
            }
        }
    };

    customos::sched::SchedCreate(worker, const_cast<char*>("A"), "worker-A");
    customos::sched::SchedCreate(worker, const_cast<char*>("B"), "worker-B");
    customos::sched::SchedCreate(worker, const_cast<char*>("C"), "worker-C");

    SerialWrite("[boot] All subsystems online. Entering idle loop.\n");
    IdleLoop();
}
