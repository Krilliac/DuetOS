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
#include "../drivers/video/console.h"
#include "../drivers/video/cursor.h"
#include "../drivers/video/framebuffer.h"
#include "../drivers/video/menu.h"
#include "../drivers/video/taskbar.h"
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

    // GUI composition. Order for every paint pass:
    //   1. Desktop fill
    //   2. Desktop banner text
    //   3. Windows in z-order (back-to-front)
    //   4. Widgets (buttons on top of windows for v0)
    //   5. Cursor on top (CursorShow re-samples backing)
    //
    // Wrapped in a file-scope helper so both the initial boot
    // paint AND the window-drag path (mouse reader thread) can
    // repaint the whole surface with one call.
    constexpr customos::u32 kDesktopTeal = 0x00204868;

    // Register two demo windows so z-order + raise-to-front are
    // visibly exercised. Window B starts in front because it
    // was registered second. Click-drag on either title bar
    // moves that window and brings it to the top.
    customos::drivers::video::WindowChrome win_a_chrome{};
    win_a_chrome.x = 60;
    win_a_chrome.y = 60;
    win_a_chrome.w = 380;
    win_a_chrome.h = 220;
    win_a_chrome.colour_border = 0x00101828;
    win_a_chrome.colour_title = 0x00205080;
    win_a_chrome.colour_client = 0x00D8D8D8;
    win_a_chrome.colour_close_btn = 0x00E04020;
    win_a_chrome.title_height = 22;
    const customos::drivers::video::WindowHandle win_a_handle =
        customos::drivers::video::WindowRegister(win_a_chrome, "CUSTOMOS GUI v0");

    customos::drivers::video::WindowChrome win_b_chrome{};
    win_b_chrome.x = 500;
    win_b_chrome.y = 100;
    win_b_chrome.w = 380;
    win_b_chrome.h = 200;
    win_b_chrome.colour_border = 0x00101828;
    win_b_chrome.colour_title = 0x00306838;
    win_b_chrome.colour_client = 0x00E0E0D8;
    win_b_chrome.colour_close_btn = 0x00E04020;
    win_b_chrome.title_height = 22;
    customos::drivers::video::WindowRegister(win_b_chrome, "NOTES   DRAG ME");

    // Framebuffer text console. 80x40 chars of boot log at the
    // bottom of the desktop, under the windows in z-order. Dragging
    // a window over it occludes; moving away restores.
    // Taskbar across the bottom of the framebuffer. Placed at
    // runtime so a different resolution still anchors correctly.
    {
        const auto fb_info = customos::drivers::video::FramebufferGet();
        constexpr customos::u32 tb_h = 28;
        const customos::u32 tb_y = (fb_info.height > tb_h) ? fb_info.height - tb_h : 0;
        customos::drivers::video::TaskbarInit(tb_y, tb_h, 0x00202838, 0x00FFFFFF, 0x00406090);
    }

    // Start menu items. action_id is a caller-owned enumeration
    // the mouse reader switches on — zero is reserved for
    // "no item hit," so first id starts at 1.
    static const customos::drivers::video::MenuItem start_items[] = {
        {"ABOUT CUSTOMOS", 1},
        {"CYCLE WINDOWS", 2},
        {"LIST WINDOWS", 3},
        {"PING CONSOLE", 4},
    };
    customos::drivers::video::MenuInit(start_items, 4);

    customos::drivers::video::ConsoleInit(16, 400, 0x0080F088, 0x00181028);

    // Tee kernel log lines to the on-screen console so the desktop
    // shows subsystem activity live — not just the boot seed block.
    // Forwards chunks through ConsoleWrite; no DesktopCompose is
    // triggered here (ui-ticker recomposes at 1 Hz, and user input
    // forces a recompose on demand). IRQ-time klogs race the kbd
    // reader on the char buffer but the damage is bounded to one
    // garbled line at worst; the authoritative log ring is serial.
    customos::core::SetLogTee([](const char* s) { customos::drivers::video::ConsoleWrite(s); });
    customos::drivers::video::ConsoleWriteln("CUSTOMOS BOOT LOG");
    customos::drivers::video::ConsoleWriteln("=================");
    customos::drivers::video::ConsoleWriteln("");
    customos::drivers::video::ConsoleWriteln("LONG-MODE KERNEL        OK");
    customos::drivers::video::ConsoleWriteln("GDT IDT TSS IST         OK");
    customos::drivers::video::ConsoleWriteln("PAGING W^X SMEP SMAP    OK");
    customos::drivers::video::ConsoleWriteln("FRAME ALLOCATOR / HEAP  OK");
    customos::drivers::video::ConsoleWriteln("ACPI MADT FADT MCFG     OK");
    customos::drivers::video::ConsoleWriteln("LAPIC IOAPIC HPET       OK");
    customos::drivers::video::ConsoleWriteln("SCHEDULER + BLOCKING    OK");
    customos::drivers::video::ConsoleWriteln("PS/2 KEYBOARD           OK");
    customos::drivers::video::ConsoleWriteln("PS/2 MOUSE              OK");
    customos::drivers::video::ConsoleWriteln("PCI ENUMERATION         OK");
    customos::drivers::video::ConsoleWriteln("FRAMEBUFFER + FONT      OK");
    customos::drivers::video::ConsoleWriteln("WINDOW MANAGER v0       OK");
    customos::drivers::video::ConsoleWriteln("");
    customos::drivers::video::ConsoleWriteln("READY.  TRY DRAGGING A WINDOW BY ITS TITLE BAR.");

    // Demo clickable button, owned by window A. x/y are offsets
    // INTO window A — dragging window A carries the button
    // along, and the button only responds to clicks when window
    // A is on top of any other window at the click point.
    customos::drivers::video::ButtonWidget demo_button{};
    demo_button.id = 1;
    demo_button.owner = win_a_handle;
    demo_button.x = 40;   // offset into window A
    demo_button.y = 90;
    demo_button.w = 160;
    demo_button.h = 48;
    demo_button.colour_normal = 0x00C0C0C0;
    demo_button.colour_pressed = 0x00E04020;
    demo_button.colour_border = 0x00101828;
    demo_button.colour_label = 0x00101828;
    demo_button.label = "CLICK ME";
    customos::drivers::video::WidgetRegisterButton(demo_button);

    // First paint. Uses the same path subsequent drags take,
    // so any layout bug shows up at boot rather than on first
    // mouse interaction.
    customos::drivers::video::DesktopCompose(kDesktopTeal, "WELCOME TO CUSTOMOS   BOOT OK");

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

    // Keyboard reader thread: consumes KeyEvents and writes the
    // printable ones into the framebuffer console. Backspace and
    // Enter get line-editing semantics; modifier-only edges
    // update internal state silently. The console is also
    // mirrored to COM1 so a headless run still produces the
    // classic serial boot log.
    //
    // v0 race note: this thread and the mouse reader both call
    // DesktopCompose without a lock. FB writes are per-pixel
    // atomic on x86_64 and the worst-case collision is a
    // transient visual artifact, not corrupt state. A proper
    // compositor mutex lands with the first crash, or on SMP
    // scheduler join — whichever comes first.
    auto kbd_reader = [](void*)
    {
        using namespace customos::drivers::input;
        constexpr customos::u32 kDesktopTealLocal = 0x00204868;
        for (;;)
        {
            const KeyEvent ev = Ps2KeyboardReadEvent();
            if (ev.is_release || ev.code == kKeyNone)
            {
                continue;
            }
            const bool alt = (ev.modifiers & kKeyModAlt) != 0;
            bool dirty = false;

            // Window-manager shortcuts take priority over any
            // text-input path. Alt+Tab cycles active window;
            // Alt+F4 closes it.
            if (alt && ev.code == kKeyTab)
            {
                customos::drivers::video::CompositorLock();
                customos::drivers::video::WindowCycleActive();
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal,
                                                         "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
                customos::drivers::video::CompositorUnlock();
                SerialWrite("[ui] alt-tab\n");
                continue;
            }
            if (alt && ev.code == kKeyF4)
            {
                customos::drivers::video::CompositorLock();
                const auto active = customos::drivers::video::WindowActive();
                if (active != customos::drivers::video::kWindowInvalid)
                {
                    customos::drivers::video::WindowClose(active);
                    SerialWrite("[ui] alt-f4 close window=");
                    SerialWriteHex(active);
                    SerialWrite("\n");
                }
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal,
                                                         "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
                customos::drivers::video::CompositorUnlock();
                continue;
            }

            if (ev.code == kKeyBackspace)
            {
                // v0: backspace removes the last character from the
                // display but NOT from the scrollback — the Console
                // has no edit-point concept. A future shell line-
                // edit layer sits on top of this.
                customos::drivers::video::ConsoleWriteChar(' ');
                dirty = true;
            }
            else if (ev.code == kKeyEnter)
            {
                customos::drivers::video::ConsoleWriteChar('\n');
                dirty = true;
            }
            else if (ev.code >= 0x20 && ev.code <= 0x7E)
            {
                const char ch = static_cast<char>(ev.code);
                customos::drivers::video::ConsoleWriteChar(ch);
                const char buf[2] = {ch, '\0'};
                SerialWrite(buf);
                dirty = true;
            }
            if (dirty)
            {
                customos::drivers::video::CompositorLock();
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal,
                                                         "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
                customos::drivers::video::CompositorUnlock();
            }
        }
    };
    customos::sched::SchedCreate(kbd_reader, nullptr, "kbd-reader");

    // UI ticker: once per second, re-composite so the taskbar's
    // uptime counter advances even when the user hasn't touched
    // keyboard or mouse. Uses the compositor mutex so it serialises
    // cleanly with input threads. No separate "dirty" flag — full
    // recompose at 1 Hz costs ~one frame's worth of MMIO writes and
    // keeps the code branch-free.
    auto ui_ticker = [](void*)
    {
        constexpr customos::u32 kDesktopTealLocal = 0x00204868;
        for (;;)
        {
            customos::sched::SchedSleepTicks(100);
            customos::drivers::video::CompositorLock();
            customos::drivers::video::CursorHide();
            customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
            customos::drivers::video::CursorShow();
            customos::drivers::video::CompositorUnlock();
        }
    };
    customos::sched::SchedCreate(ui_ticker, nullptr, "ui-ticker");

    // Mouse reader thread: blocks on Ps2MouseReadPacket, prints one
    // line per decoded packet. Same end-to-end closure the keyboard
    // reader gives, for IRQ 12. On machines without a PS/2 aux line
    // (most laptops), Ps2MouseInit returned without routing the
    // IRQ — the reader just parks forever on an unfed queue.
    auto mouse_reader = [](void*)
    {
        // Drag state is local to this thread. No other task
        // observes windows moving, so keeping the state on the
        // stack (via static-lambda-local) avoids a fragile global.
        struct DragState
        {
            bool active;
            customos::drivers::video::WindowHandle window;
            customos::u32 grab_offset_x;
            customos::u32 grab_offset_y;
        };
        static DragState drag{false, customos::drivers::video::kWindowInvalid, 0, 0};
        static bool prev_left = false;
        constexpr customos::u32 kDesktopTealLocal = 0x00204868;

        for (;;)
        {
            const auto p = customos::drivers::input::Ps2MouseReadPacket();

            // Every UI mutation inside this packet lives under
            // the compositor mutex — the kbd reader can be mid-
            // ConsoleWrite / DesktopCompose at the same time.
            customos::drivers::video::CompositorLock();
            customos::drivers::video::CursorMove(p.dx, p.dy);

            customos::u32 cx = 0, cy = 0;
            customos::drivers::video::CursorPosition(&cx, &cy);

            const bool left_down = (p.buttons & customos::drivers::input::kMouseButtonLeft) != 0;
            const bool press_edge = left_down && !prev_left;
            const bool release_edge = !left_down && prev_left;
            prev_left = left_down;

            // Priority for press edges (highest first):
            //   0a. Menu open + click on item → fire action, close.
            //   0b. Menu open + click outside → close.
            //   1.  Click on START → open/close menu.
            //   2.  Taskbar tab → raise tab's window.
            //   3.  Close-box on topmost window → close it.
            //   4.  Title bar → raise + begin drag.
            //   5.  Any other part of a window → raise only.
            bool menu_handled = false;
            if (press_edge && customos::drivers::video::MenuIsOpen())
            {
                const customos::u32 action = customos::drivers::video::MenuItemAt(cx, cy);
                if (action != 0)
                {
                    // Dispatch action. Pure demo actions — wire
                    // into real functionality as each feature
                    // becomes available.
                    switch (action)
                    {
                    case 1: // ABOUT CUSTOMOS
                        customos::drivers::video::ConsoleWriteln("");
                        customos::drivers::video::ConsoleWriteln(
                            "-> CUSTOMOS v0 — WINDOWED DESKTOP SHELL");
                        customos::drivers::video::ConsoleWriteln(
                            "   KEYBOARD + MOUSE + FRAMEBUFFER ALL LIVE");
                        break;
                    case 2: // CYCLE WINDOWS
                        customos::drivers::video::WindowCycleActive();
                        customos::drivers::video::ConsoleWriteln("-> CYCLED ACTIVE WINDOW");
                        break;
                    case 3: // LIST WINDOWS
                        customos::drivers::video::ConsoleWriteln("-> REGISTERED WINDOWS:");
                        for (customos::u32 h = 0;
                             h < customos::drivers::video::WindowRegistryCount(); ++h)
                        {
                            if (customos::drivers::video::WindowIsAlive(h))
                            {
                                const char* title = customos::drivers::video::WindowTitle(h);
                                customos::drivers::video::ConsoleWrite("   ");
                                customos::drivers::video::ConsoleWriteln(
                                    (title != nullptr) ? title : "(UNNAMED)");
                            }
                        }
                        break;
                    case 4: // PING CONSOLE
                        customos::drivers::video::ConsoleWriteln("-> PONG");
                        break;
                    }
                    SerialWrite("[ui] menu fire action=");
                    SerialWriteHex(action);
                    SerialWrite("\n");
                }
                customos::drivers::video::MenuClose();
                menu_handled = true;
            }

            // START button press opens (or closes) the menu.
            if (press_edge && !menu_handled && !drag.active)
            {
                customos::u32 sx = 0, sy = 0, sw = 0, sh = 0;
                customos::drivers::video::TaskbarStartBounds(&sx, &sy, &sw, &sh);
                if (cx >= sx && cx < sx + sw && cy >= sy && cy < sy + sh)
                {
                    if (customos::drivers::video::MenuIsOpen())
                    {
                        customos::drivers::video::MenuClose();
                    }
                    else
                    {
                        const customos::u32 mh = customos::drivers::video::MenuPanelHeight();
                        const customos::u32 my = (sy > mh) ? sy - mh : 0;
                        customos::drivers::video::MenuOpen(sx, my);
                        SerialWrite("[ui] menu open\n");
                    }
                    menu_handled = true;
                }
            }

            if (press_edge && !menu_handled && !drag.active &&
                customos::drivers::video::TaskbarContains(cx, cy))
            {
                const customos::u32 tab_hit = customos::drivers::video::TaskbarTabAt(cx, cy);
                if (tab_hit != customos::drivers::video::kWindowInvalid)
                {
                    customos::drivers::video::WindowRaise(tab_hit);
                    SerialWrite("[ui] taskbar raise window=");
                    SerialWriteHex(tab_hit);
                    SerialWrite("\n");
                    customos::drivers::video::CursorHide();
                    customos::drivers::video::DesktopCompose(kDesktopTealLocal,
                                                             "WELCOME TO CUSTOMOS   BOOT OK");
                    customos::drivers::video::CursorShow();
                    menu_handled = true; // taskbar ate the click
                }
            }

            if (press_edge && menu_handled)
            {
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal,
                                                         "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
            }
            else if (press_edge && !drag.active)
            {
                const auto hit = customos::drivers::video::WindowTopmostAt(cx, cy);
                if (hit != customos::drivers::video::kWindowInvalid)
                {
                    if (customos::drivers::video::WindowPointInCloseBox(hit, cx, cy))
                    {
                        customos::drivers::video::WindowClose(hit);
                        SerialWrite("[ui] close window=");
                        SerialWriteHex(hit);
                        SerialWrite("\n");
                    }
                    else
                    {
                        customos::u32 wx = 0, wy = 0;
                        customos::drivers::video::WindowGetBounds(hit, &wx, &wy, nullptr, nullptr);
                        customos::drivers::video::WindowRaise(hit);
                        const bool in_title = customos::drivers::video::WindowPointInTitle(hit, cx, cy);
                        if (in_title)
                        {
                            drag.active = true;
                            drag.window = hit;
                            drag.grab_offset_x = cx - wx;
                            drag.grab_offset_y = cy - wy;
                            SerialWrite("[ui] drag begin window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                        else
                        {
                            SerialWrite("[ui] raise window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                    }
                    customos::drivers::video::CursorHide();
                    customos::drivers::video::DesktopCompose(kDesktopTealLocal,
                                                             "WELCOME TO CUSTOMOS   BOOT OK");
                    customos::drivers::video::CursorShow();
                }
            }
            if (release_edge && drag.active)
            {
                SerialWrite("[ui] drag end window=");
                SerialWriteHex(drag.window);
                SerialWrite("\n");
                drag.active = false;
            }

            if (drag.active)
            {
                // Position the window so the grabbed pixel stays
                // under the cursor. Any sub-pixel clamp lives
                // inside WindowMoveTo.
                const customos::u32 nx = (cx > drag.grab_offset_x) ? cx - drag.grab_offset_x : 0;
                const customos::u32 ny = (cy > drag.grab_offset_y) ? cy - drag.grab_offset_y : 0;
                customos::drivers::video::WindowMoveTo(drag.window, nx, ny);
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
            }
            else
            {
                // Non-drag path: route clicks + motion through the
                // widget table as before. Only reachable when the
                // cursor is NOT pinning a window move; this keeps
                // the button widget inert during drag, matching
                // Windows' "modal drag" semantics.
                const customos::u32 hit =
                    customos::drivers::video::WidgetRouteMouse(cx, cy, p.buttons);
                if (hit != customos::drivers::video::kWidgetInvalid)
                {
                    SerialWrite("[ui] widget event id=");
                    SerialWriteHex(hit);
                    SerialWrite("\n");
                }
            }

            customos::drivers::video::CompositorUnlock();

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
