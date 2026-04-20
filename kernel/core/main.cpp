#include "types.h"
#include "../acpi/acpi.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/ioapic.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/pic.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/timer.h"
#include "../cpu/percpu.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/pci/pci.h"
#include "../mm/frame_allocator.h"
#include "../sync/spinlock.h"
#include "heartbeat.h"
#include "klog.h"
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
 * the LAPIC, calibrate + arm the LAPIC timer at 100 Hz, start the
 * scheduler with three workers contending on a shared mutex (exercising
 * the new wait-queue blocking path), then drop into the idle loop with
 * interrupts enabled. SMP and userland are separate follow-up commits.
 */

extern "C" void kernel_main(customos::u32 multiboot_magic, customos::uptr multiboot_info)
{
    using namespace customos::arch;
    using namespace customos::mm;

    SerialInit();
    SerialWrite("[boot] CustomOS kernel reached long mode.\n");

    // klog online as early as Serial. Self-test prints one line at
    // each severity so visual inspection of the early boot log
    // confirms the tag format + u64-value form are working.
    customos::core::KLogSelfTest();

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

    SerialWrite("[boot] Parsing ACPI tables.\n");
    customos::acpi::AcpiInit(multiboot_info);

    SerialWrite("[boot] Disabling 8259 PIC.\n");
    PicDisable();

    SerialWrite("[boot] Bringing up LAPIC.\n");
    LapicInit();

    SerialWrite("[boot] Bringing up IOAPIC.\n");
    IoApicInit();

    SerialWrite("[boot] Installing BSP per-CPU struct.\n");
    customos::cpu::PerCpuInitBsp();

    customos::sync::SpinLockSelfTest();

    SerialWrite("[boot] Bringing up periodic timer.\n");
    TimerInit();

    SerialWrite("[boot] Bringing up scheduler.\n");
    customos::sched::SchedInit();
    customos::sched::SchedStartReaper();

    SerialWrite("[boot] Bringing up PS/2 keyboard.\n");
    customos::drivers::input::Ps2KeyboardInit();

    SerialWrite("[boot] Enumerating PCI bus.\n");
    customos::drivers::pci::PciEnumerate();

    // Keyboard reader thread: blocks on Ps2KeyboardRead, prints each
    // scan code. First real end-to-end test of the IRQ path: ACPI →
    // IOAPIC → IDT → dispatcher → IrqHandler → WaitQueueWakeOne →
    // Schedule → reader wakes in Ps2KeyboardRead → prints. If any link
    // in that chain is broken, keypresses in QEMU are silently dropped.
    auto kbd_reader = [](void*)
    {
        for (;;)
        {
            const customos::u8 sc = customos::drivers::input::Ps2KeyboardRead();
            SerialWrite("[kbd] scan=");
            SerialWriteHex(sc);
            SerialWrite("\n");
        }
    };
    customos::sched::SchedCreate(kbd_reader, nullptr, "kbd-reader");

    // Scheduler self-test: three kernel threads that each bump a shared
    // counter five times under a mutex. If the mutex serialises them
    // correctly, the counter reaches exactly 15 and the prints interleave
    // without any skipped values. A race would skip values (two workers
    // reading the same `before` and writing `before + 1`). This also
    // exercises WaitQueueBlock / WaitQueueWakeOne whenever two workers
    // collide on MutexLock, so the wait-queue machinery is on the boot
    // path by default.
    static customos::sched::Mutex s_demo_mutex{};
    static customos::u64 s_shared_counter = 0;

    auto worker = [](void* arg)
    {
        const char* name = static_cast<const char*>(arg);
        for (customos::u64 i = 0; i < 5; ++i)
        {
            customos::sched::MutexLock(&s_demo_mutex);

            const customos::u64 before = s_shared_counter;
            // Burn a couple of ms of CPU inside the critical section so
            // that other workers are almost guaranteed to hit the slow
            // path on MutexLock and park on the wait queue. Without this
            // the race is too tight for the self-test to be meaningful.
            for (customos::u64 j = 0; j < 2'000'000; ++j)
            {
                asm volatile("" ::: "memory");
            }
            s_shared_counter = before + 1;

            SerialWrite("[sched] ");
            SerialWrite(name);
            SerialWrite(" i=");
            SerialWriteHex(i);
            SerialWrite(" counter=");
            SerialWriteHex(s_shared_counter);
            SerialWrite("\n");

            customos::sched::MutexUnlock(&s_demo_mutex);
            customos::sched::SchedSleepTicks(1); // yield + 10 ms pause
        }
    };

    customos::sched::SchedCreate(worker, const_cast<char*>("A"), "worker-A");
    customos::sched::SchedCreate(worker, const_cast<char*>("B"), "worker-B");
    customos::sched::SchedCreate(worker, const_cast<char*>("C"), "worker-C");

    // Bring up APs AFTER worker spawn — SmpStartAps calls
    // SchedSleepTicks(1) between INIT and SIPI, and the BSP needs
    // SOMETHING runnable (any Ready task) for the scheduler to pick
    // while it sleeps. Workers are still running through their 15
    // iterations (~150 ms at 10 ms/sleep) at this point, plus the
    // kheartbeat thread below — plenty to keep the runqueue non-
    // empty. Proper fix is an idle task per CPU; deferred.
    SerialWrite("[boot] Bringing up APs.\n");
    SmpStartAps();

    customos::core::StartHeartbeatThread();

    SerialWrite("[boot] All subsystems online. Entering idle loop.\n");
    IdleLoop();
}
