#include "types.h"
#include "../acpi/acpi.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/ioapic.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/pic.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/timer.h"
#include "../cpu/percpu.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/input/ps2mouse.h"
#include "../drivers/pci/pci.h"
#include "../drivers/storage/ahci.h"
#include "../drivers/video/cursor.h"
#include "../drivers/video/framebuffer.h"
#include "../drivers/video/widget.h"
#include "../fs/ramfs.h"
#include "../fs/vfs.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../sync/spinlock.h"
#include "heartbeat.h"
#include "klog.h"
#include "panic.h"
#include "ring3_smoke.h"
#include "syscall.h"
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

#ifdef CUSTOMOS_CANARY_DEMO
// Deliberately overrun a stack buffer so the function's epilogue
// stack-canary check fails on return. Volatile + asm sink prevent
// the optimiser from eliding the out-of-bounds stores. MUST return
// normally — the stack-protector epilogue runs on `ret`, and we
// want the __stack_chk_fail tail-call to happen.
//
// No __attribute__((no_stack_protector)) here — the WHOLE POINT is
// that this function DOES have a canary the compiler can check.
[[gnu::noinline]] static void CanarySmashDemo()
{
    volatile customos::u8 buf[8] = {};
    for (int i = 0; i < 64; ++i)
    {
        buf[i] = static_cast<customos::u8>(i);
    }
    asm volatile("" : : "r"(&buf[0]) : "memory");
}
#endif

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

    SerialWrite("[boot] Installing TSS + IST stacks (#DF / #MC / #NMI).\n");
    TssInit();
    IdtSetIst(2, kIstNmi);           // #NMI
    IdtSetIst(8, kIstDoubleFault);   // #DF
    IdtSetIst(18, kIstMachineCheck); // #MC

    SerialWrite("[boot] Installing syscall gate (int 0x80, DPL=3).\n");
    customos::core::SyscallInit();

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
    // Kernel-image W^X / DEP — split the 2 MiB PS direct map covering
    // the kernel image into 4 KiB pages, then apply per-section flags:
    //   .text  → R + X   (writes to .text now #PF)
    //   .rodata → R      (writes or execution from .rodata now #PF)
    //   .data/.bss → R + W (execution from .data/.bss now #PF)
    //
    // MUST run AFTER PagingInit adopted the boot PML4 + enabled
    // EFER.NXE, and BEFORE anything else needs .rodata strings. No
    // subsystem below this point should be writing to .text; if any
    // of them does, the fault will fire here at boot rather than
    // corrupt code silently later.
    ProtectKernelImage();

    SerialWrite("[boot] Bringing up framebuffer (if present).\n");
    customos::drivers::video::FramebufferInit(multiboot_info);
    customos::drivers::video::FramebufferSelfTest();

    // Paint a "desktop" background, register boot-time widgets,
    // draw them, then render the cursor on top. Order matters —
    // cursor always last so its saved backing pixels include the
    // widgets underneath.
    constexpr customos::u32 kDesktopTeal = 0x00204868;
    customos::drivers::video::FramebufferClear(kDesktopTeal);

    // Demo window chrome. Classic three-colour scheme: dark
    // border, navy title bar, light-grey client area, with a
    // red close-button square at the top-right corner. Proves
    // the window-drawing primitive end-to-end.
    customos::drivers::video::WindowChrome demo_window{};
    demo_window.x = 220;
    demo_window.y = 120;
    demo_window.w = 420;
    demo_window.h = 260;
    demo_window.colour_border = 0x00101828;
    demo_window.colour_title = 0x00284878;
    demo_window.colour_client = 0x00D8D8D8;
    demo_window.colour_close_btn = 0x00E04020;
    demo_window.title_height = 22;
    customos::drivers::video::WindowDraw(demo_window);

    // Demo clickable button, now sitting inside the window's
    // client area. Click lights it up red; release returns it
    // to grey — the smallest proof the mouse-event pipeline
    // reaches widgets end-to-end.
    customos::drivers::video::ButtonWidget demo_button{};
    demo_button.id = 1;
    demo_button.x = 256;
    demo_button.y = 168;
    demo_button.w = 160;
    demo_button.h = 48;
    demo_button.colour_normal = 0x00C0C0C0;  // neutral grey
    demo_button.colour_pressed = 0x00E04020; // warm red on press
    demo_button.colour_border = 0x00101828;  // dark outline
    customos::drivers::video::WidgetRegisterButton(demo_button);
    customos::drivers::video::WidgetDrawAll();

    customos::drivers::video::CursorInit(kDesktopTeal);

    SerialWrite("[boot] Seeding ramfs + VFS self-test.\n");
    customos::fs::RamfsInit();
    {
        using namespace customos::fs;
        const RamfsNode* trusted = RamfsTrustedRoot();
        const RamfsNode* sandbox = RamfsSandboxRoot();

        // Positive lookups against the trusted tree. Trailing slash,
        // leading slash, empty-component runs — all tolerated.
        if (VfsLookup(trusted, "/etc/version", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: /etc/version missing from trusted root");
        if (VfsLookup(trusted, "/bin/hello", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: /bin/hello missing from trusted root");
        if (VfsLookup(trusted, "//etc//version", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: double-slash tolerance broken");

        // The sandbox root has exactly one file; its lookup must
        // succeed, and the trusted-only paths must fail.
        if (VfsLookup(sandbox, "/welcome.txt", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: /welcome.txt missing from sandbox root");
        if (VfsLookup(sandbox, "/etc/version", 64) != nullptr)
            customos::core::Panic("fs/vfs", "self-test: JAIL BROKEN — sandbox saw trusted /etc/version");
        if (VfsLookup(sandbox, "/bin/hello", 64) != nullptr)
            customos::core::Panic("fs/vfs", "self-test: JAIL BROKEN — sandbox saw trusted /bin/hello");

        // ".." is rejected outright.
        if (VfsLookup(trusted, "/etc/..", 64) != nullptr)
            customos::core::Panic("fs/vfs", "self-test: .. accepted (would break jails)");

        SerialWrite("[fs/vfs] self-test OK\n");
    }

    // Address-space isolation self-test — direct assertion that a
    // user page mapped in one AS is invisible in a sibling AS, and
    // that AddressSpaceActivate flips CR3 correctly. Indirectly
    // covered by ring3_smoke running two tasks at the same VA, but
    // this runs BEFORE scheduler/ring3 bring-up so a regression
    // surfaces at the earliest possible point.
    customos::mm::AddressSpaceSelfTest();

    SerialWrite("[boot] Parsing ACPI tables.\n");
    customos::acpi::AcpiInit(multiboot_info);

    SerialWrite("[boot] Disabling 8259 PIC.\n");
    PicDisable();

    SerialWrite("[boot] Bringing up LAPIC.\n");
    LapicInit();

    SerialWrite("[boot] Bringing up IOAPIC.\n");
    IoApicInit();

    SerialWrite("[boot] Bringing up HPET (if present).\n");
    HpetInit();
    HpetSelfTest();

    SerialWrite("[boot] Installing BSP per-CPU struct.\n");
    customos::cpu::PerCpuInitBsp();

    customos::sync::SpinLockSelfTest();

    SerialWrite("[boot] Bringing up periodic timer.\n");
    TimerInit();

    SerialWrite("[boot] Bringing up scheduler.\n");
    customos::sched::SchedInit();
    // Idle task FIRST so the runqueue is never empty — even if the
    // reaper or any subsequent worker blocks before the boot task
    // spawns anything else, Schedule() always has a fallback to
    // pick. Supersedes the "ensure SmpStartAps has a runnable peer"
    // workaround that used to depend on worker creation order.
    customos::sched::SchedStartIdle("idle-bsp");
    customos::sched::SchedStartReaper();

    SerialWrite("[boot] Bringing up PS/2 keyboard.\n");
    customos::drivers::input::Ps2KeyboardInit();

    SerialWrite("[boot] Bringing up PS/2 mouse.\n");
    customos::drivers::input::Ps2MouseInit();

    SerialWrite("[boot] Enumerating PCI bus.\n");
    customos::drivers::pci::PciEnumerate();

    SerialWrite("[boot] Discovering AHCI controller.\n");
    customos::drivers::storage::AhciInit();

    // Keyboard reader thread: blocks on Ps2KeyboardReadChar, prints
    // one line per resolved key press. End-to-end path exercised:
    // ACPI → IOAPIC → IDT → dispatcher → IrqHandler → WaitQueueWakeOne
    // → Schedule → reader wakes → translator consumes modifier +
    // release bytes → returns ASCII → prints. If any link in that
    // chain is broken, keypresses in QEMU are silently dropped.
    auto kbd_reader = [](void*)
    {
        for (;;)
        {
            const char ch = customos::drivers::input::Ps2KeyboardReadChar();
            const char buf[2] = {ch, '\0'};
            SerialWrite("[kbd] char='");
            SerialWrite(buf);
            SerialWrite("'\n");
        }
    };
    customos::sched::SchedCreate(kbd_reader, nullptr, "kbd-reader");

    // Mouse reader thread: blocks on Ps2MouseReadPacket, prints one
    // line per decoded packet. Same end-to-end closure the keyboard
    // reader gives, for IRQ 12. On machines without a PS/2 aux line
    // (most laptops), Ps2MouseInit returned without routing the
    // IRQ — the reader just parks forever on an unfed queue.
    auto mouse_reader = [](void*)
    {
        for (;;)
        {
            const auto p = customos::drivers::input::Ps2MouseReadPacket();
            // Drive the on-screen cursor. When the framebuffer isn't
            // available, CursorMove is a silent no-op — the log line
            // below still prints so IRQ-12 health is visible.
            customos::drivers::video::CursorMove(p.dx, p.dy);

            // Route the latest cursor-state sample through the
            // widget table. A click on the demo button switches
            // its fill colour; release switches it back.
            customos::u32 cx = 0, cy = 0;
            customos::drivers::video::CursorPosition(&cx, &cy);
            const customos::u32 hit = customos::drivers::video::WidgetRouteMouse(cx, cy, p.buttons);
            if (hit != customos::drivers::video::kWidgetInvalid)
            {
                SerialWrite("[ui] widget event id=");
                SerialWriteHex(hit);
                SerialWrite("\n");
            }

            SerialWrite("[mouse] dx=");
            SerialWriteHex(static_cast<customos::u64>(p.dx));
            SerialWrite(" dy=");
            SerialWriteHex(static_cast<customos::u64>(p.dy));
            SerialWrite(" btn=");
            SerialWriteHex(p.buttons);
            SerialWrite("\n");
        }
    };
    customos::sched::SchedCreate(mouse_reader, nullptr, "mouse-reader");

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

    // First ring-3 slice: spawn a dedicated scheduler thread that maps a
    // user code + stack page, drops to ring 3, and runs an interruptible
    // pause/jmp loop forever. Kernel workers above keep running and
    // periodically preempt it; the proof-of-life is that this whole
    // boot sequence continues to make forward progress after the
    // iretq into user mode.
    customos::core::StartRing3SmokeTask();

    // Bring up APs. SmpStartAps calls SchedSleepTicks(1) between
    // INIT and SIPI; the dedicated idle task installed at the top
    // of SchedInit guarantees the runqueue is non-empty, so the
    // BSP always has something to switch to while it sleeps —
    // independent of worker-creation order.
    SerialWrite("[boot] Bringing up APs.\n");
    SmpStartAps();

    customos::core::StartHeartbeatThread();

    SerialWrite("[boot] All subsystems online. Entering idle loop.\n");

#ifdef CUSTOMOS_CANARY_DEMO
    // Compile-time-gated deliberate stack smash. Calls a helper that
    // overruns a local array past its stack canary; on function
    // return, the compiler-inserted epilogue reads the stashed
    // canary, finds it clobbered, and tail-calls __stack_chk_fail,
    // which panics with "stack canary corrupted — overflow detected".
    //
    // MUST be a function that actually returns — kernel_main itself
    // doesn't (it ends in IdleLoop), so the epilogue-check would
    // never run if we inlined the smash here.
    CanarySmashDemo();
#endif

#ifdef CUSTOMOS_PANIC_DEMO
    // Compile-time-gated deliberate panic used by tools/test-panic.sh
    // to verify the panic path stays healthy end-to-end. Never
    // enabled in a normal build — the default preset does not pass
    // -DCUSTOMOS_PANIC_DEMO.
    customos::core::Panic("test/panic-demo", "CUSTOMOS_PANIC_DEMO enabled; halting on purpose");
#endif

#ifdef CUSTOMOS_TRAP_DEMO
    // Compile-time-gated deliberate CPU exception used by
    // tools/test-trap.sh to verify the trap dispatcher's crash-dump
    // path produces an extractable record (BEGIN/END markers,
    // symbolized RIP, backtrace). `ud2` is the canonical "never
    // resume" undefined-opcode encoding and raises #UD with no
    // error code.
    asm volatile("ud2");
#endif

    // Terminate the boot task instead of idle-looping on the boot
    // stack. Rationale: kboot runs on the low-VA boot stack
    // (.bss.boot). Any Schedule() triggered from kboot's context
    // (e.g. a timer IRQ that raises need_resched) flips CR3 to
    // whatever task we're switching INTO. Per-process ASes zero
    // PML4[0..255], so the boot stack's low VA isn't reachable
    // after the flip — the next stack access would #PF on IST
    // stacks (also low-VA) and cascade into a #DF cluster.
    //
    // SchedExit marks kboot Dead, drops it from the runqueue,
    // and loops in Schedule() picking other tasks. The dedicated
    // idle task (SchedStartIdle) ensures the runqueue is never
    // empty. From this point on, kboot is never re-scheduled and
    // the boot stack is never touched again — it just sits at
    // low VA unreferenced until reboot.
    //
    // Note: kboot has stack_base=nullptr (it never had a
    // scheduler-allocated stack), so the reaper's KFree(stack_base)
    // is a no-op for it. The boot stack's .bss.boot storage isn't
    // heap-managed; the linker placed it and it persists.
    customos::sched::SchedExit();
}
